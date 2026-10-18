import Darwin
import Foundation
import Security

/// A separate setup address. Neither the normal gateway endpoint nor a phone-selected name is accepted.
enum GatewayJournalSetupAddress {
    static func serviceName(accountID: Data, intentID: Data) throws -> String {
        guard intentID.count == 16 else { throw GatewayPreparationError.invalidRecord }
        let paths = try RuntimePreparationPaths(accountID: accountID)
        return paths.namespace + ".gateway-journal-setup." + intentID.map { String(format: "%02x", $0) }.joined()
    }
}

enum GatewayJournalSetupChannelError: Error, Equatable { case closed, busy, timedOut, unsupportedVersion, invalidReply }
enum GatewayJournalSetupCall: Sendable { case hello, prepare(Data, Data) }
enum GatewayJournalSetupReply: Sendable { case version(UInt64), report(Data?), failed }
protocol GatewayJournalSetupDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: GatewayJournalSetupCall, reply: @escaping @Sendable (GatewayJournalSetupReply) -> Void)
    func close()
}

private final class NativeGatewayJournalSetupDriver: GatewayJournalSetupDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: GatewayJournalSetupXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: GatewayJournalSetupCall, reply: @escaping @Sendable (GatewayJournalSetupReply) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any GatewayJournalSetupXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
        case .prepare(let digest, let challenge): proxy.prepare(digest, challenge: challenge) { [self] in checked(.report($0), reply: reply) }
        }
    }
    private func checked(_ result: GatewayJournalSetupReply, reply: @Sendable (GatewayJournalSetupReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(result) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class GatewaySetupClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    @discardableResult
    func close() -> Bool { lock.withLock { guard !closed else { return false }; closed = true; return true } }
    func ifOpen(_ body: () -> Void) -> Bool {
        lock.withLock { guard !closed else { return false }; body(); return !closed }
    }
}

/// A single pending setup exchange. The Root owner must retain its release scope and recheck pending state before committing completion.
/// A valid report establishes neither normal gateway health nor push activation.
actor GatewayJournalSetupChannel {
    private enum State { case new, opening, open, closed }
    private let intentID: Data
    private let scopeDigest: Data
    private let driver: any GatewayJournalSetupDriver
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let verifyPending: @Sendable () throws -> Void
    private let challenge: @Sendable () throws -> Data
    private let lifetime = GatewaySetupClientLifetime()
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<GatewayJournalSetupReply, any Error>)?
    private var timer: Task<Void, Never>?

    init(intent: GatewayJournalSetupIntent, gatewayCode: AuthorityCodeEntry, timeoutMilliseconds: UInt64 = 5000,
         verifyPending: @escaping @Sendable () throws -> Void) throws {
        guard gatewayCode.role == .notificationGateway, gatewayCode.active, (1...60000).contains(timeoutMilliseconds),
              let claim = intent.material.runtime.services.claims.first(where: { $0.role == .gateway }),
              claim.number == intent.configuration.serviceUID else { throw GatewayPreparationError.invalidRecord }
        let policy = try XPCPeerPolicy(teamID: gatewayCode.teamID, componentIdentifier: gatewayCode.identifier,
            approvedCodeDirectoryHashes: [gatewayCode.codeDirectoryHash], expectedUserID: claim.number)
        driver = NativeGatewayJournalSetupDriver(serviceName: try GatewayJournalSetupAddress.serviceName(accountID: intent.accountID, intentID: intent.id), policy: policy)
        intentID = intent.id; scopeDigest = try intent.digest; timeout = timeoutMilliseconds; self.verifyPending = verifyPending
        let accountID = intent.accountID, ownerUID = intent.configuration.ownerUID
        verifyAccount = {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            let directory = try NativeServiceAccountDirectory(accountID: accountID, ownerUID: ownerUID)
            try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: ownerUID)
        }
        challenge = Self.randomChallenge
    }
    // Driver fixtures exercise sequencing and reply binding, not native peer admission or launchd routing.
    init(driver: any GatewayJournalSetupDriver, intentID: Data, scopeDigest: Data, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, verifyPending: @escaping @Sendable () throws -> Void = {},
         challenge: @escaping @Sendable () throws -> Data) throws {
        guard intentID.count == 16, scopeDigest.count == 32, (1...60000).contains(timeoutMilliseconds) else {
            throw GatewayPreparationError.invalidRecord
        }
        self.driver = driver; self.intentID = intentID; self.scopeDigest = scopeDigest; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.verifyPending = verifyPending; self.challenge = challenge
    }
    deinit { lifetime.close(); timer?.cancel(); driver.close() }

    func prepare() async throws -> GatewayJournalSetupReport {
        guard state == .new else { throw state == .closed ? GatewayJournalSetupChannelError.closed : .busy }
        do {
            try verifyAccount(); try verifyPending(); try Task.checkCancellation()
            state = .opening
            let lifetime = lifetime, driver = driver
            driver.start { [weak self] in
                if lifetime.close() { driver.close() }
                Task { await self?.close() }
            }
            guard case .version(let version) = try await perform(.hello), state == .opening else { throw GatewayJournalSetupChannelError.closed }
            guard GatewayJournalSetupInterface.supportedVersions.contains(version) else { throw GatewayJournalSetupChannelError.unsupportedVersion }
            state = .open
            let nonce = try challenge()
            guard nonce.count == 32 else { throw GatewayPreparationError.invalidRecord }
            guard case .report(let bytes) = try await perform(.prepare(scopeDigest, nonce)), let bytes else { throw GatewayJournalSetupChannelError.invalidReply }
            let report = try GatewayJournalSetupResponse.decode(bytes, challenge: nonce, intentID: intentID, scopeDigest: scopeDigest)
            try verifyAccount(); try verifyPending(); try Task.checkCancellation()
            guard state == .open, lifetime.ifOpen({}) else { throw GatewayJournalSetupChannelError.closed }
            close(); return report
        } catch { close(); throw error }
    }
    func close() {
        guard state != .closed else { return }
        state = .closed; lifetime.close(); timer?.cancel(); timer = nil; driver.close()
        let previous = pending; pending = nil; previous?.continuation.resume(throwing: GatewayJournalSetupChannelError.closed)
    }
    private func perform(_ call: GatewayJournalSetupCall) async throws -> GatewayJournalSetupReply {
        try verifyAccount(); try verifyPending(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw GatewayJournalSetupChannelError.closed }
        case .prepare: guard state == .open else { throw GatewayJournalSetupChannelError.closed }
        }
        guard lifetime.ifOpen({}) else { close(); throw GatewayJournalSetupChannelError.closed }
        guard pending == nil else { throw GatewayJournalSetupChannelError.busy }
        let id = UUID(), lifetime = lifetime, driver = driver
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                guard lifetime.ifOpen({
                    driver.invoke(call) { [weak self] result in
                        if case .failed = result, lifetime.close() { driver.close() }
                        Task { await self?.complete(id, result: result) }
                    }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw GatewayJournalSetupChannelError.closed }
        return result
    }
    private func complete(_ id: UUID, result: GatewayJournalSetupReply) {
        guard let pending, pending.id == id, state != .closed else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = result { pending.continuation.resume(throwing: GatewayJournalSetupChannelError.closed); close() }
        else { pending.continuation.resume(returning: result) }
    }
    private func expire(_ id: UUID) {
        guard let pending, pending.id == id else { return }
        self.pending = nil; pending.continuation.resume(throwing: GatewayJournalSetupChannelError.timedOut); close()
    }
    private static func randomChallenge() throws -> Data {
        var bytes = Data(count: 32)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw GatewayPreparationError.invalidRecord
        }
        return bytes
    }
}
