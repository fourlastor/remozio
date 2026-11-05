import Darwin
import Foundation
import Security

/// A read that reached the daemon and ended without usable progress.
/// The daemon refuses reads while maintenance holds it for another connection, so this never shows that no upgrade ran.
public enum AuditUpgradeSetupChannelError: Error, Equatable { case progressUnavailable }

enum AuditUpgradeSetupCall: Sendable { case hello, progress, perform(SetupAuditUpgradeProgress, Data) }
protocol AuditUpgradeSetupDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func verifyPeer() throws
    func invoke(_ call: AuditUpgradeSetupCall, reply: @escaping @Sendable (SetupClientReply) -> Void)
    func close()
}
private final class NativeAuditUpgradeSetupDriver: AuditUpgradeSetupDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy; connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AuditUpgradeSetupXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func verifyPeer() throws { _ = try policy.verifyCredentials(connection) }
    func invoke(_ call: AuditUpgradeSetupCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
        if case .hello = call {} else { do { try verifyPeer() } catch { reply(.failed); return } }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AuditUpgradeSetupXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.auditUpgradeHello { [self] in checked(.version($0), reply: reply) }
        case .progress: proxy.auditUpgradeProgress { [self] in checked(.progress($0), reply: reply) }
        case .perform(let expected, let form):
            do { proxy.performAuditUpgrade(try expected.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        }
    }
    private func checked(_ value: SetupClientReply, reply: @Sendable (SetupClientReply) -> Void) {
        do { try verifyPeer(); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class AuditUpgradeSetupLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    private var dropped = false
    func close() { lock.withLock { closed = true } }
    /// Records a transport loss only when no local close came first.
    func drop() { lock.withLock { if !closed { dropped = true }; closed = true } }
    var wasDropped: Bool { lock.withLock { dropped } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return true } }
}

/// Authenticated maintenance connection. A mutating connection closes after one result; a lost result requires a fresh read.
public actor AuditUpgradeSetupChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any AuditUpgradeSetupDriver
    private let ownerUID: uid_t
    private let timeout: UInt64
    private let operationTimeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let lifetime = AuditUpgradeSetupLifetime()
    private var scope: SetupAuditUpgradeProgress?
    private var state = State.new
    private var pending: (UUID, CheckedContinuation<SetupClientReply, any Error>)?
    private var timer: Task<Void, Never>?
    private var refused = false

    /// The peer policy must come from verified installed release metadata.
    public init(serviceName: String, rootPolicy: XPCPeerPolicy, ownerUID: uid_t, expected: SetupAuditUpgradeProgress? = nil,
                timeoutMilliseconds: UInt64 = 5000, operationTimeoutMilliseconds: UInt64 = 60_000) throws {
        guard MacServiceNamespace.accepts(serviceName), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              rootPolicy.expectedUserID == 0, ownerUID > 0, ownerUID < UInt32.max,
              expected == nil || expected?.runtime.ownerUID == ownerUID,
              (1...60_000).contains(timeoutMilliseconds), (1...300_000).contains(operationTimeoutMilliseconds) else {
            throw AdministrativeSetupChannelError.invalidConfiguration
        }
        guard getuid() == ownerUID, geteuid() == ownerUID else { throw AdministrativeSetupChannelError.wrongAccount }
        driver = NativeAuditUpgradeSetupDriver(serviceName: serviceName, policy: rootPolicy)
        self.ownerUID = ownerUID; scope = expected; timeout = timeoutMilliseconds; operationTimeout = operationTimeoutMilliseconds
        let processID = getpid()
        verifyAccount = { guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw AdministrativeSetupChannelError.wrongAccount } }
    }
    // Logical fixtures exercise peer checks and continuation ownership, not native signing or rights.
    init(driver: any AuditUpgradeSetupDriver, ownerUID: uid_t = getuid(), expected: SetupAuditUpgradeProgress? = nil,
         timeoutMilliseconds: UInt64 = 5000, operationTimeoutMilliseconds: UInt64 = 60_000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.driver = driver; self.ownerUID = ownerUID; scope = expected
        timeout = timeoutMilliseconds; operationTimeout = operationTimeoutMilliseconds; self.verifyAccount = verifyAccount
    }
    deinit { timer?.cancel(); driver.close() }
    /// A refused, dropped or expired handshake throws `AuditUpgradeSetupChannelError.progressUnavailable`.
    public func start() async throws {
        guard state == .new else { throw AdministrativeSetupChannelError.closed }; state = .opening
        do {
            guard case .version(let version) = try await invoke(.hello) else { throw AdministrativeSetupChannelError.unsupportedVersion }
            // The endpoint answers zero when it refuses the handshake, for example while maintenance holds the daemon.
            guard version != 0 else { throw AuditUpgradeSetupChannelError.progressUnavailable }
            guard version == SetupAuditUpgradeLocalContract.version else { throw AdministrativeSetupChannelError.unsupportedVersion }
            try driver.verifyPeer(); state = .open
        } catch { close(); throw readFailure(error) }
    }
    /// Read and pin the complete account scope. A later scope change requires a new connection and review.
    /// A refused, dropped or expired read throws `AuditUpgradeSetupChannelError.progressUnavailable`. The upgrade state is then unknown.
    public func progress() async throws -> SetupAuditUpgradeProgress? {
        guard state == .open else { close(); throw AdministrativeSetupChannelError.closed }
        do {
            guard case .progress(let reply) = try await invoke(.progress) else { throw AdministrativeSetupChannelError.invalidMessage }
            // The endpoint answers nil when it refuses the read, for example while maintenance holds the daemon.
            guard let bytes = reply else { throw AuditUpgradeSetupChannelError.progressUnavailable }
            guard bytes.count <= SetupAuditUpgradeProgress.maximumBytes else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard scope == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupAuditUpgradeProgress.decode(bytes)
            let stages: Set<SetupAuditUpgradeProgress.Stage> = [.ready, .graphPrepared, .filesChanging, .filesVerified, .metadataCommitted, .alreadyCurrent]
            guard value.runtime.ownerUID == ownerUID, stages.contains(value.stage), value.registrationObserved.isEmpty else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            if let scope { try value.validateScope(of: scope) } else { scope = value }
            return value
        } catch AdministrativeSetupChannelError.busy { throw AdministrativeSetupChannelError.busy }
        catch { close(); throw readFailure(error) }
    }
    /// Read a preauthorized form only after verifying Root. This closure must not request interactive rights.
    /// Any error after the reader returns leaves the outcome unknown. Open a fresh channel and read progress; never repeat the call.
    public func perform(_ expected: SetupAuditUpgradeProgress,
                        readAuthorization: @Sendable () throws -> Data) async throws -> SetupAuditUpgradeProgress {
        guard state == .open else { throw AdministrativeSetupChannelError.closed }
        guard pending == nil else { throw AdministrativeSetupChannelError.busy }
        do {
            guard let scope, expected.runtime.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            try expected.validateScope(of: scope)
            try verifyAccount(); try Task.checkCancellation(); try driver.verifyPeer()
            guard lifetime.ifOpen({}) else { throw AdministrativeSetupChannelError.closed }
            let form = try readAuthorization()
            try Task.checkCancellation(); try driver.verifyPeer()
            guard lifetime.ifOpen({}), form.count == MemoryLayout<AuthorizationExternalForm>.size else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            guard case .progress(let bytes) = try await invoke(.perform(expected, form)), let bytes,
                  bytes.count <= SetupAuditUpgradeProgress.maximumBytes else { throw AdministrativeSetupChannelError.invalidMessage }
            let value = try SetupAuditUpgradeProgress.decode(bytes)
            try value.validateScope(of: expected)
            let stages: Set<SetupAuditUpgradeProgress.Stage> = [.waitingForActivity, .waitingForMachine, .waitingForQuiescence, .registrationObserved, .alreadyCurrent]
            guard stages.contains(value.stage) else { throw AdministrativeSetupChannelError.invalidMessage }
            close(); return value
        } catch AdministrativeSetupChannelError.busy { throw AdministrativeSetupChannelError.busy }
        catch { close(); throw error }
    }
    public func perform(_ expected: SetupAuditUpgradeProgress, authorization: Data) async throws -> SetupAuditUpgradeProgress {
        try await perform(expected, readAuthorization: { authorization })
    }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() { finish(.closed) }
    /// Local errors keep their meaning. A remote refusal, a dropped transport or an expired read becomes unavailable progress.
    private func readFailure(_ error: any Error) -> any Error {
        guard !Task.isCancelled, let value = error as? AdministrativeSetupChannelError else { return error }
        switch value {
        case .timedOut: return AuditUpgradeSetupChannelError.progressUnavailable
        case .closed where refused || lifetime.wasDropped: return AuditUpgradeSetupChannelError.progressUnavailable
        default: return error
        }
    }
    private func invoke(_ call: AuditUpgradeSetupCall) async throws -> SetupClientReply {
        do { try verifyAccount() } catch { close(); throw error }
        try Task.checkCancellation()
        let handshake: Bool, deadline: UInt64
        switch call {
        case .hello: handshake = true; deadline = timeout; guard state == .opening else { throw AdministrativeSetupChannelError.closed }
        case .progress: handshake = false; deadline = timeout; guard state == .open else { throw AdministrativeSetupChannelError.closed }
        case .perform: handshake = false; deadline = operationTimeout; guard state == .open else { throw AdministrativeSetupChannelError.closed }
        }
        guard pending == nil else { throw AdministrativeSetupChannelError.busy }
        if !handshake { try driver.verifyPeer() }
        let id = UUID(), driver = driver, lifetime = lifetime
        let result: SetupClientReply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self] in
                    do { try await Task.sleep(for: .milliseconds(deadline)) } catch { return }
                    await self?.expire(id)
                }
                if handshake { driver.start { [weak self] in lifetime.drop(); Task { await self?.close() } } }
                guard lifetime.ifOpen({ driver.invoke(call) { [weak self] reply in Task { await self?.complete(id, reply: reply) } } }) else { close(); return }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw AdministrativeSetupChannelError.closed }; return result
    }
    private func complete(_ id: UUID, reply: SetupClientReply) {
        guard let old = pending, old.0 == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = reply { refused = true; close(); return }
        do { try verifyAccount(); try driver.verifyPeer() } catch { close(); return }
        pending = nil; timer?.cancel(); timer = nil; old.1.resume(returning: reply)
    }
    private func expire(_ id: UUID) { if pending?.0 == id { finish(.timedOut) } }
    private func finish(_ error: AdministrativeSetupChannelError) {
        guard state != .closed else { return }; state = .closed; lifetime.close(); timer?.cancel(); timer = nil
        let old = pending; pending = nil; driver.close(); old?.1.resume(throwing: error)
    }
}
