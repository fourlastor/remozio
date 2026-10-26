import Darwin
import Foundation
import Security

enum PortableSetupImportCall: Sendable { case hello, recoveryHello, progress, recovery, perform(SetupPortableImportOperation, Data) }
protocol PortableSetupImportDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: PortableSetupImportCall, reply: @escaping @Sendable (SetupClientReply) -> Void)
    func close()
}
private final class NativePortableSetupImportDriver: PortableSetupImportDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy; connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: PortableSetupImportCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
        switch call {
        case .hello, .recoveryHello: break
        default: do { _ = try policy.verifyCredentials(connection) } catch { reply(.failed); return }
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any PortableSetupImportXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .recoveryHello: proxy.portableImportRecoveryHello { [self] in checked(.version($0), reply: reply) }
        case .recovery: proxy.portableImportRecovery { [self] in checked(.progress($0), reply: reply) }
        case .hello: proxy.portableImportHello { [self] in checked(.version($0), reply: reply) }
        case .progress: proxy.portableImportProgress { [self] in checked(.progress($0), reply: reply) }
        case .perform(let request, let authorization):
            do { proxy.performPortableImport(try request.bytes, authorization: authorization) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        }
    }
    private func checked(_ value: SetupClientReply, reply: @Sendable (SetupClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class PortableSetupImportLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return true } }
}

/// Authenticate the Root handshake before exporting administrator rights. A lost reply requires progress reconciliation.
public actor PortableSetupImportChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any PortableSetupImportDriver
    private let ownerUID: uid_t
    private let recoveryEnabled: Bool
    private let timeout: UInt64
    private let operationTimeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let lifetime = PortableSetupImportLifetime()
    private var state = State.new
    private var pending: (UUID, CheckedContinuation<SetupClientReply, any Error>)?
    private var timer: Task<Void, Never>?
    public init(serviceName: String, rootPolicy: XPCPeerPolicy, ownerUID: uid_t, recoveryEnabled: Bool = false,
                timeoutMilliseconds: UInt64 = 5000, operationTimeoutMilliseconds: UInt64 = 600_000) throws {
        guard serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              rootPolicy.expectedUserID == 0, ownerUID > 0, ownerUID < UInt32.max,
              (1...60_000).contains(timeoutMilliseconds), (1...900_000).contains(operationTimeoutMilliseconds) else {
            throw AdministrativeSetupChannelError.invalidConfiguration
        }
        guard getuid() == ownerUID, geteuid() == ownerUID else { throw AdministrativeSetupChannelError.wrongAccount }
        self.ownerUID = ownerUID; self.recoveryEnabled = recoveryEnabled; timeout = timeoutMilliseconds; operationTimeout = operationTimeoutMilliseconds
        driver = NativePortableSetupImportDriver(serviceName: serviceName, policy: rootPolicy)
        let processID = getpid()
        verifyAccount = { guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw AdministrativeSetupChannelError.wrongAccount } }
    }
    // Logical fixtures do not prove native XPC signing, authorization or service registration.
    init(driver: any PortableSetupImportDriver, ownerUID: uid_t = getuid(), recoveryEnabled: Bool = false, timeoutMilliseconds: UInt64 = 5000,
         operationTimeoutMilliseconds: UInt64 = 600_000, verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.driver = driver; self.ownerUID = ownerUID; self.recoveryEnabled = recoveryEnabled; timeout = timeoutMilliseconds; operationTimeout = operationTimeoutMilliseconds
        self.verifyAccount = verifyAccount
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws {
        guard state == .new else { throw AdministrativeSetupChannelError.closed }; state = .opening
        do {
            let expected = recoveryEnabled ? AdministrativeSetupInterface.portableImportRecoveryVersion : AdministrativeSetupInterface.portableImportVersion
            guard case .version(let version) = try await invoke(recoveryEnabled ? .recoveryHello : .hello), version == expected else {
                throw AdministrativeSetupChannelError.unsupportedVersion
            }
            state = .open
        } catch { close(); throw error }
    }
    public func progress() async throws -> SetupPortableImportProgress? {
        do {
            guard case .progress(let bytes) = try await invoke(.progress), let bytes,
                  bytes.count <= SetupPortableImportProgress.maximumByteCount else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty { return nil }
            let progress = try SetupPortableImportProgress.decode(bytes)
            guard progress.runtime.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }; return progress
        } catch AdministrativeSetupChannelError.busy { throw AdministrativeSetupChannelError.busy }
        catch { close(); throw error }
    }
    /// Historical metadata only. This read does not request rights, contact the provider or retry a write.
    public func recovery() async throws -> SetupPortableImportRecovery? {
        guard recoveryEnabled else { throw AdministrativeSetupChannelError.unsupportedVersion }
        do {
            guard case .progress(let bytes) = try await invoke(.recovery), let bytes,
                  bytes.count <= SetupPortableImportRecovery.maximumByteCount else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty { return nil }
            let value = try SetupPortableImportRecovery.decode(bytes)
            guard value.progress.runtime.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            return value
        } catch AdministrativeSetupChannelError.busy { throw AdministrativeSetupChannelError.busy }
        catch { close(); throw error }
    }
    public func perform(_ request: SetupPortableImportOperation, authorization: Data) async throws -> SetupPortableImportOperationResult {
        guard !request.requiresRecoveryHandshake || recoveryEnabled else { throw AdministrativeSetupChannelError.unsupportedVersion }
        guard request.expected.runtime.ownerUID == ownerUID, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        do {
            guard case .progress(let bytes) = try await invoke(.perform(request, authorization)), let bytes,
                  bytes.count <= SetupPortableImportOperationResult.maximumBytes else { throw AdministrativeSetupChannelError.invalidMessage }
            return try .decode(bytes, request: request)
        } catch AdministrativeSetupChannelError.busy { throw AdministrativeSetupChannelError.busy }
        catch { close(); throw error }
    }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() { finish(.closed) }
    private func invoke(_ call: PortableSetupImportCall) async throws -> SetupClientReply {
        do { try verifyAccount() } catch { close(); throw error }
        try Task.checkCancellation()
        let handshake: Bool, deadline: UInt64
        switch call {
        case .hello, .recoveryHello: handshake = true; deadline = timeout; guard state == .opening else { throw AdministrativeSetupChannelError.closed }
        case .progress, .recovery: handshake = false; deadline = timeout; guard state == .open else { throw AdministrativeSetupChannelError.closed }
        case .perform: handshake = false; deadline = operationTimeout; guard state == .open else { throw AdministrativeSetupChannelError.closed }
        }
        guard pending == nil else { throw AdministrativeSetupChannelError.busy }
        let id = UUID(), driver = driver, lifetime = lifetime
        let result: SetupClientReply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self] in
                    do { try await Task.sleep(for: .milliseconds(deadline)) } catch { return }
                    await self?.expire(id)
                }
                if handshake { driver.start { [weak self] in lifetime.close(); Task { await self?.close() } } }
                guard lifetime.ifOpen({ driver.invoke(call) { [weak self] reply in Task { await self?.complete(id, reply: reply) } } }) else { close(); return }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw AdministrativeSetupChannelError.closed }; return result
    }
    private func complete(_ id: UUID, reply: SetupClientReply) {
        guard let old = pending, old.0 == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = reply { close(); return }
        pending = nil; timer?.cancel(); timer = nil; old.1.resume(returning: reply)
    }
    private func expire(_ id: UUID) { if pending?.0 == id { finish(.timedOut) } }
    private func finish(_ error: AdministrativeSetupChannelError) {
        guard state != .closed else { return }; state = .closed; lifetime.close(); timer?.cancel(); timer = nil
        let old = pending; pending = nil; driver.close(); old?.1.resume(throwing: error)
    }
}
