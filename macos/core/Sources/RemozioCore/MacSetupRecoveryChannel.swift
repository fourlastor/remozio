import Darwin
import Foundation
import Security

enum MacSetupRecoveryLane: Equatable, Sendable { case status, recovery }

enum MacSetupRecoveryCall: Sendable {
    case status(Data)
    case hello
    case start(Data, authorization: Data)
    case progress(Data)
}

protocol MacSetupRecoveryChannelDriver: Sendable {
    func activate(onClose: @escaping @Sendable () -> Void)
    func peer() throws -> XPCPeerCredentials
    func send(_ call: MacSetupRecoveryCall, reply: @escaping @Sendable (SetupClientReply) -> Void)
    func close()
}

private final class NativeMacSetupRecoveryChannelDriver: MacSetupRecoveryChannelDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy

    init(lane: MacSetupRecoveryLane, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName, options: .privileged)
        switch lane {
        case .status: connection.remoteObjectInterface = NSXPCInterface(with: RetainedSetupStatusXPCProtocol.self)
        case .recovery: connection.remoteObjectInterface = NSXPCInterface(with: RetainedSetupRecoveryXPCProtocol.self)
        }
        policy.configure(connection)
    }

    func activate(onClose: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = onClose
        connection.invalidationHandler = onClose
        connection.activate()
    }

    func peer() throws -> XPCPeerCredentials { try policy.verifyCredentials(connection) }

    func send(_ call: MacSetupRecoveryCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in reply(.failed) }
        if case .status(let request) = call {
            guard let status = proxy as? any RetainedSetupStatusXPCProtocol else { reply(.failed); return }
            status.retainedInvocationStatus(request) { reply(.progress($0)) }
            return
        }
        guard let recovery = proxy as? any RetainedSetupRecoveryXPCProtocol else { reply(.failed); return }
        switch call {
        case .status: preconditionFailure("Status uses its own connection")
        case .hello: recovery.recoveryHello { reply(.version($0)) }
        case .start(let request, let authorization):
            recovery.startRecovery(request, authorization: authorization) { reply(.progress($0)) }
        case .progress(let request): recovery.recoveryProgress(request) { reply(.progress($0)) }
        }
    }

    func close() { connection.invalidate() }
}

/// A status connection has one read. A recovery connection owns at most one submitted request.
actor MacSetupRecoveryChannel {
    typealias Wire = SetupOrphanRecoveryWire
    typealias ScheduleTimeout = @Sendable (@escaping @Sendable () async -> Void) -> Task<Void, Never>?
    private enum State { case new, opening, open, closed }

    private let lane: MacSetupRecoveryLane
    private let statusV3: Bool
    private let driver: any MacSetupRecoveryChannelDriver
    private let scheduleTimeout: ScheduleTimeout
    private let verifyAccount: @Sendable () throws -> Void
    private let lifetime = SetupClientLifetime()
    private var state = State.new
    private var peer: XPCPeerCredentials?
    private var reserved = false
    private var submission: Wire.Request?
    private var pending: (id: UUID, continuation: CheckedContinuation<SetupClientReply, any Error>)?
    private var timer: Task<Void, Never>?

    /// Only the installed Setup factory supplies the verified release.
    init(lane: MacSetupRecoveryLane, verifiedRelease: SignedReleaseEvidence) throws {
        try Self.requireFormats(lane: lane, release: verifiedRelease)
        guard let component = verifiedRelease.manifest.components.first(where: { $0.role == .setupController }),
              let team = component.teamID, let hash = verifiedRelease.codeDirectoryHashes[.setupController] else {
            throw AdministrativeSetupChannelError.invalidConfiguration
        }
        let uid = getuid(), pid = getpid()
        guard uid > 0, uid < UInt32.max, uid == geteuid() else { throw AdministrativeSetupChannelError.wrongAccount }
        let policy = try XPCPeerPolicy(teamID: team, componentIdentifier: component.identifier,
            approvedCodeDirectoryHashes: [hash], expectedUserID: 0)
        self.init(lane: lane, driver: NativeMacSetupRecoveryChannelDriver(lane: lane, policy: policy),
            statusV3: SetupRetainedStatusV3Wire.supports(verifiedRelease),
            verifyAccount: {
                guard getpid() == pid, getuid() == uid, geteuid() == uid else {
                    throw AdministrativeSetupChannelError.wrongAccount
                }
            })
    }

    static func requireFormats(lane: MacSetupRecoveryLane, release: SignedReleaseEvidence) throws {
        if lane == .recovery { try Wire.requireFormats(release) }
    }

    init(lane: MacSetupRecoveryLane, driver: any MacSetupRecoveryChannelDriver, statusV3: Bool = false,
         scheduleTimeout: @escaping ScheduleTimeout = { expire in
             Task {
                 do { try await Task.sleep(for: .seconds(5)) } catch { return }
                 await expire()
             }
         }, verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.lane = lane
        self.statusV3 = statusV3
        self.driver = driver
        self.scheduleTimeout = scheduleTimeout
        self.verifyAccount = verifyAccount
    }

    deinit { timer?.cancel(); driver.close() }

    func readStatus() async throws -> SetupRetainedStatusWire.Observation {
        guard lane == .status, state == .new else { throw AdministrativeSetupChannelError.closed }
        state = .opening
        defer { close() }
        let request = try SetupRetainedStatusWire.Request(requestID: AccountPreparationIntent.randomID())
        let versioned = SetupRetainedStatusV3Wire.Request(legacy: request)
        let bytes = try statusV3 ? versioned.bytes : request.bytes
        guard case .progress(let data) = try await invoke(.status(bytes), opening: true), let data else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        if statusV3 { return try SetupRetainedStatusV3Wire.decodeReply(data, matching: versioned) }
        return try SetupRetainedStatusWire.decodeReply(data, matching: request)
    }

    func open() async throws {
        guard lane == .recovery, state == .new else { throw AdministrativeSetupChannelError.closed }
        state = .opening
        do {
            guard case .version(let version) = try await invoke(.hello, opening: true), version == Wire.ipcVersion else {
                throw AdministrativeSetupChannelError.unsupportedVersion
            }
            state = .open
        } catch { close(); throw error }
    }

    /// The synchronous reader exports an already authorized form. It must not prompt.
    func start(_ request: Wire.Request, readAuthorization: @Sendable () throws -> Data) async throws -> Wire.Code {
        guard lane == .recovery, state == .open else { throw AdministrativeSetupChannelError.closed }
        guard !reserved, pending == nil else { throw AdministrativeSetupChannelError.busy }
        guard request.identity != nil else { throw AdministrativeSetupChannelError.invalidMessage }
        reserved = true
        do {
            let bytes = try request.bytes
            try requirePeer()
            guard lifetime.ifOpen({}) else { throw AdministrativeSetupChannelError.closed }
            let form = try readAuthorization()
            guard form.count == MemoryLayout<AuthorizationExternalForm>.size else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            let reply = try await invoke(.start(bytes, authorization: form), submitting: request)
            guard case .progress(let data) = reply, let data else { throw AdministrativeSetupChannelError.invalidMessage }
            let value = try Wire.Reply.decode(data)
            guard value.requestID == request.requestID, value.code == .requestRecorded || value.code == .refusedUnavailable else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            return value.code
        } catch AdministrativeSetupChannelError.timedOut {
            // The send may have reached this endpoint. A later read uses this connection and request ID only.
            throw AdministrativeSetupChannelError.timedOut
        } catch { close(); throw error }
    }

    var didDispatchStart: Bool { submission != nil }

    func readProgress() async throws -> Wire.Code {
        guard lane == .recovery, state == .open, let submission else { throw AdministrativeSetupChannelError.closed }
        do {
            let request = try Wire.Progress(requestID: submission.requestID)
            guard case .progress(let data) = try await invoke(.progress(request.bytes)), let data else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            let value = try Wire.Reply.decode(data)
            guard value.requestID == submission.requestID, value.code != .requestRecorded,
                  value.code != .released || submission.action == .releaseWindowFree,
                  value.code != .restored || submission.action != .releaseWindowFree else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            return value.code
        } catch AdministrativeSetupChannelError.busy { throw AdministrativeSetupChannelError.busy }
        catch { close(); throw error }
    }

    func close() { finish(.closed) }

    private func requirePeer() throws {
        try verifyAccount()
        try Task.checkCancellation()
        let current = try driver.peer()
        guard current.userID == 0, let peer, current == peer else { throw XPCPeerPolicyError.wrongPeer }
    }

    private func invoke(_ call: MacSetupRecoveryCall, opening: Bool = false,
                        submitting: Wire.Request? = nil) async throws -> SetupClientReply {
        try verifyAccount()
        try Task.checkCancellation()
        guard pending == nil else { throw AdministrativeSetupChannelError.busy }
        let id = UUID(), lifetime = self.lifetime, driver = self.driver
        let reply: SetupClientReply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = scheduleTimeout { [weak self] in
                    await self?.expire(id, preserveConnection: submitting != nil)
                }
                guard lifetime.ifOpen({
                    do {
                        if opening {
                            driver.activate { [weak self] in lifetime.close(); Task { await self?.close() } }
                        } else {
                            try requirePeer()
                        }
                        submission = submitting ?? submission
                        driver.send(call) { [weak self] value in Task { await self?.complete(id, with: value) } }
                    } catch { finish(.closed) }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in
            lifetime.close()
            driver.close()
            Task { await self?.close() }
        }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { throw AdministrativeSetupChannelError.closed }
        return reply
    }

    private func complete(_ id: UUID, with reply: SetupClientReply) {
        guard pending?.id == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = reply { close(); return }
        do {
            try verifyAccount()
            let current = try driver.peer()
            guard current.userID == 0, peer == nil || peer == current else { throw XPCPeerPolicyError.wrongPeer }
            peer = current
            resolve(.success(reply))
        } catch { close() }
    }

    private func expire(_ id: UUID, preserveConnection: Bool) {
        guard pending?.id == id else { return }
        if preserveConnection { resolve(.failure(AdministrativeSetupChannelError.timedOut)) }
        else { finish(.timedOut) }
    }

    private func finish(_ error: AdministrativeSetupChannelError) {
        guard state != .closed else { return }
        state = .closed
        lifetime.close()
        driver.close()
        resolve(.failure(error))
    }

    private func resolve(_ result: Result<SetupClientReply, any Error>) {
        let continuation = pending?.continuation
        pending = nil
        timer?.cancel()
        timer = nil
        continuation?.resume(with: result)
    }
}
