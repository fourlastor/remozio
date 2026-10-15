import Darwin
import Foundation
import Security

public enum AdministrativeSetupChannelError: Error, Equatable {
    case invalidConfiguration, wrongAccount, closed, busy, unsupportedVersion, invalidMessage, timedOut
}
enum SetupClientCall: Sendable {
    case hello, progress(Data), resume(SetupAccountProgress, Data)
    case serviceAccountsHello, serviceAccountsProgress, prepareServiceAccounts(SetupServiceAccountProgress, Data)
    case enrollmentHello, enrollmentProgress, beginEnrollment(Data, Data), resumeEnrollment(SetupAccountEnrollmentProgress, Data)
    var handshake: Bool { switch self { case .hello, .enrollmentHello, .serviceAccountsHello: true; default: false } }
}
enum SetupClientReply: Sendable { case version(UInt64), progress(Data?), failed }
protocol SetupClientDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void)
    func close()
}
private final class NativeSetupClientDriver: SetupClientDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AdministrativeSetupXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: SetupClientCall, reply: @escaping @Sendable (SetupClientReply) -> Void) {
        // Hello discovers the peer. Every later send rechecks its kernel Root identity first.
        if !call.handshake {
            do { _ = try policy.verifyCredentials(connection) } catch { reply(.failed); return }
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AdministrativeSetupXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .serviceAccountsHello: proxy.serviceAccountsHello { [self] in checked(.version($0), reply: reply) }
        case .serviceAccountsProgress: proxy.serviceAccountsProgress { [self] in checked(.progress($0), reply: reply) }
        case .prepareServiceAccounts(let expected, let form):
            do { proxy.prepareServiceAccounts(try expected.bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) } }
            catch { reply(.failed) }
        case .enrollmentHello: proxy.enrollmentHello { [self] in checked(.version($0), reply: reply) }
        case .enrollmentProgress: proxy.accountEnrollmentProgress { [self] in checked(.progress($0), reply: reply) }
        case .beginEnrollment(let bytes, let form):
            proxy.beginAccountEnrollment(bytes, authorization: form) { [self] in checked(.progress($0), reply: reply) }
        case .resumeEnrollment(let expected, let form):
            proxy.resumeAccountEnrollment(expected.setupID, expectedRevision: expected.revision, authorization: form) { [self] in checked(.progress($0), reply: reply) }
        case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
        case .progress(let account): proxy.accountStorageProgress(account) { [self] in checked(.progress($0), reply: reply) }
        case .resume(let progress, let authorization):
            proxy.resumeAccountStorage(progress.accountID, setupID: progress.setupID, expectedRevision: progress.revision,
                authorization: authorization) { [self] in checked(.progress($0), reply: reply) }
        }
    }
    private func checked(_ value: SetupClientReply, reply: @Sendable (SetupClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class SetupClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return true } }
}

/// App-to-Root setup connection. Inputs must come from verified, protected installation metadata.
/// Authenticate with start before exporting native administrator rights. A lost reply must be reconciled by reading progress.
public actor AdministrativeSetupChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any SetupClientDriver
    private let accountID: Data?
    private let ownerUID: uid_t
    private let serviceAccounts: Bool
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let onClose: @Sendable () -> Void
    private let lifetime = SetupClientLifetime()
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<SetupClientReply, any Error>)?
    private var timer: Task<Void, Never>?

    public init(serviceName: String, rootPolicy: XPCPeerPolicy, accountID: Data? = nil, ownerUID: uid_t, serviceAccounts: Bool = false,
                timeoutMilliseconds: UInt64 = 5000, onClose: @escaping @Sendable () -> Void = {}) throws {
        guard serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }),
              (!serviceAccounts || accountID == nil), rootPolicy.expectedUserID == 0, accountID == nil || accountID?.count == 16, ownerUID > 0, ownerUID < UInt32.max,
              (1...60_000).contains(timeoutMilliseconds) else { throw AdministrativeSetupChannelError.invalidConfiguration }
        guard getuid() == ownerUID, geteuid() == ownerUID else { throw AdministrativeSetupChannelError.wrongAccount }
        let processID = getpid()
        driver = NativeSetupClientDriver(serviceName: serviceName, policy: rootPolicy)
        self.accountID = accountID; self.ownerUID = ownerUID; self.serviceAccounts = serviceAccounts; timeout = timeoutMilliseconds; self.onClose = onClose
        verifyAccount = {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else {
                throw AdministrativeSetupChannelError.wrongAccount
            }
        }
    }
    // Logical lifecycle controls do not prove native signing, service registration or administrator consent.
    init(driver: any SetupClientDriver, accountID: Data? = nil, ownerUID: uid_t = getuid(), serviceAccounts: Bool = false, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, onClose: @escaping @Sendable () -> Void = {}) {
        self.driver = driver; self.accountID = accountID; self.ownerUID = ownerUID; self.serviceAccounts = serviceAccounts; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.onClose = onClose
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws {
        guard state == .new else { throw AdministrativeSetupChannelError.closed }
        state = .opening
        do {
            let expected = serviceAccounts ? AdministrativeSetupInterface.serviceAccountsVersion :
                (accountID == nil ? AdministrativeSetupInterface.enrollmentVersion : AdministrativeSetupInterface.storageVersion)
            let call: SetupClientCall = serviceAccounts ? .serviceAccountsHello : (accountID == nil ? .enrollmentHello : .hello)
            guard case .version(let version) = try await perform(call), version == expected else {
                throw AdministrativeSetupChannelError.unsupportedVersion
            }
            state = .open
        } catch { close(); throw error }
    }
    /// Empty progress means this account has no retained setup intent. It is not a runtime health result.
    public func progress() async throws -> SetupAccountProgress? {
        guard let accountID else { throw AdministrativeSetupChannelError.wrongAccount }
        return try decode(await perform(.progress(accountID)), expected: nil)
    }
    /// Supply only a freshly exported local administrator form after start succeeds. This method never prompts or retries.
    public func resume(_ expected: SetupAccountProgress, authorization: Data) async throws -> SetupAccountProgress {
        guard expected.accountID == accountID, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        guard let result = try decode(await perform(.resume(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func enrollmentProgress() async throws -> SetupAccountEnrollmentProgress? {
        guard accountID == nil else { throw AdministrativeSetupChannelError.wrongAccount }
        return try decodeEnrollment(await perform(.enrollmentProgress), expected: nil)
    }
    public func beginEnrollment(_ choices: AccountEnrollmentRequest, authorization: Data) async throws -> SetupAccountEnrollmentProgress {
        guard accountID == nil, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        guard let result = try decodeEnrollment(await perform(.beginEnrollment(choices.bytes, authorization)), expected: nil),
              result.allowedTargetUIDs == choices.allowedTargetUIDs else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func resumeEnrollment(_ expected: SetupAccountEnrollmentProgress, authorization: Data) async throws -> SetupAccountEnrollmentProgress {
        guard accountID == nil, expected.ownerUID == ownerUID, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw AdministrativeSetupChannelError.invalidMessage
        }
        guard let result = try decodeEnrollment(await perform(.resumeEnrollment(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    public func serviceAccountsProgress() async throws -> SetupServiceAccountProgress? {
        guard serviceAccounts, accountID == nil else { throw AdministrativeSetupChannelError.unsupportedVersion }
        return try decodeServices(await perform(.serviceAccountsProgress), expected: nil)
    }
    public func prepareServiceAccounts(_ expected: SetupServiceAccountProgress, authorization: Data) async throws -> SetupServiceAccountProgress {
        guard serviceAccounts, accountID == nil, expected.ownerUID == ownerUID,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AdministrativeSetupChannelError.invalidMessage }
        guard let result = try decodeServices(await perform(.prepareServiceAccounts(expected, authorization)), expected: expected) else {
            close(); throw AdministrativeSetupChannelError.invalidMessage
        }
        return result
    }
    private func decodeServices(_ reply: SetupClientReply, expected: SetupServiceAccountProgress?) throws -> SetupServiceAccountProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 384 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupServiceAccountProgress.decode(bytes)
            guard value.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected { try value.validateCompletion(of: expected) }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    private func decodeEnrollment(_ reply: SetupClientReply, expected: SetupAccountEnrollmentProgress?) throws -> SetupAccountEnrollmentProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 1024 else { throw AdministrativeSetupChannelError.invalidMessage }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let result = try SetupAccountEnrollmentProgress.decode(bytes)
            guard result.ownerUID == ownerUID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected {
                guard result.macID == expected.macID, result.accountID == expected.accountID, result.setupID == expected.setupID,
                      result.allowedTargetUIDs == expected.allowedTargetUIDs, result.keyPrepared, result.storagePrepared,
                      (expected.storagePrepared ? result == expected : result.revision != expected.revision) else {
                    throw AdministrativeSetupChannelError.invalidMessage
                }
            }
            return result
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() { finish(.closed) }
    private func decode(_ reply: SetupClientReply, expected: SetupAccountProgress?) throws -> SetupAccountProgress? {
        do {
            guard case .progress(let bytes) = reply, let bytes, bytes.count <= 256 else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            if bytes.isEmpty {
                guard expected == nil else { throw AdministrativeSetupChannelError.invalidMessage }; return nil
            }
            let value = try SetupAccountProgress.decode(bytes)
            guard value.accountID == accountID else { throw AdministrativeSetupChannelError.invalidMessage }
            if let expected {
                guard value.setupID == expected.setupID, value.complete, value.checkpointCaptured,
                      (expected.complete ? value == expected : value.revision != expected.revision) else { throw AdministrativeSetupChannelError.invalidMessage }
            }
            return value
        } catch { finish(.invalidMessage); throw AdministrativeSetupChannelError.invalidMessage }
    }
    private func perform(_ call: SetupClientCall) async throws -> SetupClientReply {
        do { try verifyAccount() } catch { close(); throw error }
        try Task.checkCancellation()
        switch call {
        case .hello, .enrollmentHello, .serviceAccountsHello: guard state == .opening else { throw AdministrativeSetupChannelError.closed }
        case .progress, .resume, .enrollmentProgress, .beginEnrollment, .resumeEnrollment, .serviceAccountsProgress, .prepareServiceAccounts: guard state == .open else { throw AdministrativeSetupChannelError.closed }
        }
        guard pending == nil else { throw AdministrativeSetupChannelError.busy }
        let lifetime = lifetime, driver = driver, id = UUID()
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                if call.handshake {
                    driver.start { [weak self] in lifetime.close(); Task { await self?.close() } }
                }
                guard lifetime.ifOpen({ driver.invoke(call) { [weak self] value in Task { await self?.complete(id, value: value) } } }) else {
                    close(); return
                }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw AdministrativeSetupChannelError.closed }
        return value
    }
    private func complete(_ id: UUID, value: SetupClientReply) {
        guard let previous = pending, previous.id == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = value { finish(.closed); return }
        pending = nil; timer?.cancel(); timer = nil; previous.continuation.resume(returning: value)
    }
    private func expire(_ id: UUID) { if pending?.id == id { finish(.timedOut) } }
    private func finish(_ error: AdministrativeSetupChannelError) {
        guard state != .closed else { return }
        state = .closed; lifetime.close(); timer?.cancel(); timer = nil
        let previous = pending; pending = nil; driver.close(); onClose(); previous?.continuation.resume(throwing: error)
    }
}
