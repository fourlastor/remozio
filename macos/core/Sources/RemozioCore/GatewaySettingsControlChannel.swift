import Darwin
import Foundation
import Security

/// A fixed account address. Neither the phone nor the app supplies a service name.
enum GatewaySettingsControlAddress {
    static func serviceName(accountID: Data) throws -> String {
        try RuntimePreparationPaths(accountID: accountID).gatewaySettingsControlService
    }
}

/// Check signed declarations and exact retained identities before a client can use the native interface.
enum GatewaySettingsControlReleaseValidation {
    static let formatName = "authority.gateway-settings-control"
    static func validate(_ release: SignedReleaseEvidence, authority: AuthorityCodeEntry, setup: AuthorityCodeEntry) throws {
        guard authority.role == .authority, setup.role == .setupController, authority.active, setup.active,
              authority.teamID == setup.teamID else { throw GatewayPreparationError.changedScope }
        for entry in [authority, setup] {
            guard let component = release.manifest.components.first(where: { $0.role == entry.role }),
                  component.identifier == entry.identifier, component.teamID == entry.teamID,
                  component.generation == entry.installedGeneration,
                  component.codeDirectoryHash == entry.codeDirectoryHash,
                  release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash,
                  let format = component.formats.first(where: { $0.name == formatName }),
                  format.readers.contains(GatewaySettingsControlInterface.version),
                  format.writers.contains(GatewaySettingsControlInterface.version) else { throw GatewayPreparationError.changedScope }
        }
    }
}
enum GatewaySettingsControlChannelError: Error, Equatable { case closed, busy, timedOut, unsupportedVersion, invalidReply, changedScope }
enum GatewaySettingsControlCall: Sendable { case hello, control(Data) }
enum GatewaySettingsControlReply: Sendable { case greeting(UInt64, Data?), response(Data?), failed }
protocol GatewaySettingsControlDriver: AnyObject, Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: GatewaySettingsControlCall, reply: @escaping @Sendable (GatewaySettingsControlReply) -> Void)
    func close()
}

final class NativeGatewaySettingsControlDriver: GatewaySettingsControlDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let verifyPeer: () throws -> Void
    convenience init(serviceName: String, policy: XPCPeerPolicy) {
        let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        policy.configure(connection)
        self.init(connection: connection, verifyPeer: { _ = try policy.verifyCredentials(connection) })
    }
    // An owned anonymous connection can test transport shape, but cannot prove production peer admission.
    init(connection: NSXPCConnection, verifyPeer: @escaping () throws -> Void) {
        self.connection = connection; self.verifyPeer = verifyPeer
        connection.remoteObjectInterface = NSXPCInterface(with: GatewaySettingsControlXPCProtocol.self)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: GatewaySettingsControlCall, reply: @escaping @Sendable (GatewaySettingsControlReply) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any GatewaySettingsControlXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [weak self] version, bytes in self?.checked(.greeting(version, bytes), reply: reply) ?? reply(.failed) }
        case .control(let payload): proxy.control(payload) { [weak self] in self?.checked(.response($0), reply: reply) ?? reply(.failed) }
        }
    }
    private func checked(_ value: GatewaySettingsControlReply, reply: @Sendable (GatewaySettingsControlReply) -> Void) {
        do { try verifyPeer(); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class GatewaySettingsControlClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    @discardableResult
    func close() -> Bool { lock.withLock { guard !closed else { return false }; closed = true; return true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return !closed } }
}

/// One control operation with no automatic retry. The owner must resolve an uncertain result through a fresh observation.
actor GatewaySettingsControlChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any GatewaySettingsControlDriver
    private let accountID: Data
    private let expectedRootEpoch: UUID?
    private let verifyAccount: @Sendable () throws -> Void
    private let verifyCurrent: @Sendable () throws -> Void
    private let challenge: @Sendable () throws -> Data
    private let timeout: UInt64
    private let lifetime = GatewaySettingsControlClientLifetime()
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<GatewaySettingsControlReply, any Error>)?
    private var timer: Task<Void, Never>?

    init(accountID: Data, authorityCode: AuthorityCodeEntry, setupCode: AuthorityCodeEntry, release: SignedReleaseEvidence,
         expectedRootEpoch: UUID?, timeoutMilliseconds: UInt64 = 5000,
         verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard accountID.count == 16, (1...60_000).contains(timeoutMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        try GatewaySettingsControlReleaseValidation.validate(release, authority: authorityCode, setup: setupCode)
        let policy = try XPCPeerPolicy(teamID: authorityCode.teamID, componentIdentifier: authorityCode.identifier,
            approvedCodeDirectoryHashes: [authorityCode.codeDirectoryHash], expectedUserID: 0)
        let local = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
        }
        try verify(); try verifyCurrent()
        driver = NativeGatewaySettingsControlDriver(serviceName: try GatewaySettingsControlAddress.serviceName(accountID: accountID), policy: policy)
        self.accountID = accountID; self.expectedRootEpoch = expectedRootEpoch; timeout = timeoutMilliseconds
        self.verifyAccount = verify; self.verifyCurrent = verifyCurrent; challenge = Self.randomChallenge
    }
    init(driver: any GatewaySettingsControlDriver, accountID: Data, expectedRootEpoch: UUID?, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, verifyCurrent: @escaping @Sendable () throws -> Void = {},
         challenge: @escaping @Sendable () throws -> Data) throws {
        guard accountID.count == 16, (1...60_000).contains(timeoutMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        self.driver = driver; self.accountID = accountID; self.expectedRootEpoch = expectedRootEpoch; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.verifyCurrent = verifyCurrent; self.challenge = challenge
    }
    deinit { timer?.cancel(); if lifetime.close() { driver.close() } }

    func execute(_ change: AuthorityPhonePushSettingsChange, action: GatewaySettingsControlAction) async throws -> GatewaySettingsControlResponse {
        guard state == .new else { throw state == .closed ? GatewaySettingsControlChannelError.closed : .busy }
        do {
            guard action != .accept || expectedRootEpoch != nil else { throw GatewaySettingsControlChannelError.changedScope }
            try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
            state = .opening
            let lifetime = lifetime, driver = driver
            driver.start { [weak self, weak driver] in
                if lifetime.close() { driver?.close() }
                Task { await self?.close() }
            }
            guard case .greeting(let version, let bytes) = try await perform(.hello), let bytes else { throw GatewaySettingsControlChannelError.invalidReply }
            guard GatewaySettingsControlInterface.supportedVersions.contains(version) else { throw GatewaySettingsControlChannelError.unsupportedVersion }
            let binding = try GatewaySettingsControlBinding.decode(bytes)
            guard binding.accountID == accountID, expectedRootEpoch == nil || expectedRootEpoch == binding.rootEpoch else {
                throw GatewaySettingsControlChannelError.changedScope
            }
            try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
            state = .open
            let request = try GatewaySettingsControlRequest(binding: binding, change: change, action: action, challenge: challenge())
            guard case .response(let reply) = try await perform(.control(request.encoded)), let reply else { throw GatewaySettingsControlChannelError.invalidReply }
            let result = try GatewaySettingsControlResponse.decode(reply, expected: request)
            try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
            guard state == .open, lifetime.ifOpen({}) else { throw GatewaySettingsControlChannelError.closed }
            close(); return result
        } catch { close(); throw error }
    }
    func close() {
        guard state != .closed else { return }
        state = .closed; timer?.cancel(); timer = nil
        if lifetime.close() { driver.close() }
        let old = pending; pending = nil; old?.continuation.resume(throwing: GatewaySettingsControlChannelError.closed)
    }
    private func perform(_ call: GatewaySettingsControlCall) async throws -> GatewaySettingsControlReply {
        try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw GatewaySettingsControlChannelError.closed }
        case .control: guard state == .open else { throw GatewaySettingsControlChannelError.closed }
        }
        guard lifetime.ifOpen({}) else { close(); throw GatewaySettingsControlChannelError.closed }
        guard pending == nil else { throw GatewaySettingsControlChannelError.busy }
        let id = UUID(), lifetime = lifetime, driver = driver
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                guard lifetime.ifOpen({
                    driver.invoke(call) { [weak self, weak driver] value in
                        if case .failed = value, lifetime.close() { driver?.close() }
                        Task { await self?.complete(id, value) }
                    }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in
            if lifetime.close() { driver.close() }
            Task { await self?.close() }
        }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw GatewaySettingsControlChannelError.closed }
        return result
    }
    private func complete(_ id: UUID, _ value: GatewaySettingsControlReply) {
        guard let pending, pending.id == id, state != .closed else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = value { pending.continuation.resume(throwing: GatewaySettingsControlChannelError.closed); close() }
        else { pending.continuation.resume(returning: value) }
    }
    private func expire(_ id: UUID) {
        guard let old = pending, old.id == id else { return }
        pending = nil; close(); old.continuation.resume(throwing: GatewaySettingsControlChannelError.timedOut)
    }
    private static func randomChallenge() throws -> Data {
        var bytes = Data(count: 32)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw GatewayPreparationError.invalidRecord
        }
        return bytes
    }
}
