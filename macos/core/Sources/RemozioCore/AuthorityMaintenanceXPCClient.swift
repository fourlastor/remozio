import Darwin
import Foundation
import Security

enum AuthorityMaintenanceClientError: Error, Equatable { case invalidState, cancelled, needsOwnerRecovery }
enum AuthorityMaintenanceClientReply: Sendable { case hello(UInt64), bytes(Data?) }
protocol AuthorityMaintenanceClientDriver: Sendable {
    func start(_ invalidated: @escaping @Sendable () -> Void)
    func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void)
    func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void)
    func close()
}
private final class NativeMaintenanceClient: AuthorityMaintenanceClientDriver, @unchecked Sendable {
    private let connection: NSXPCConnection, policy: XPCPeerPolicy
    init(accountID: Data, policy: XPCPeerPolicy) throws {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: try AuthorityMaintenanceChannelScope.serviceName(accountID: accountID), options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); policy.configure(connection)
    }
    func start(_ invalidated: @escaping @Sendable () -> Void) {
        connection.invalidationHandler = invalidated; connection.interruptionHandler = invalidated; connection.activate()
    }
    func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        proxy(reply)?.hello { [self] in checked(.hello($0), reply) }
    }
    func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); proxy(reply)?.exchange(bytes) { [self] in checked(.bytes($0), reply) } }
        catch { reply(.bytes(nil)) }
    }
    private func proxy(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) -> (any AuthorityMaintenanceXPCProtocol)? {
        guard let p = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.bytes(nil)) }) as? any AuthorityMaintenanceXPCProtocol else {
            reply(.bytes(nil)); return nil
        }; return p
    }
    private func checked(_ value: AuthorityMaintenanceClientReply, _ reply: @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.bytes(nil)) }
    }
    func close() { connection.invalidate() }
    deinit { close() }
}
private final class MaintenanceClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock(); private var active = true, expected: UUID?
    private var delivered: AuthorityMaintenanceClientReply?
    func close() { lock.withLock { active = false; expected = nil; delivered = nil } }
    func invalidate() { lock.withLock { active = false } }
    func begin(_ id: UUID) -> Bool { lock.withLock { guard active else { return false }; expected = id; delivered = nil; return true } }
    func record(_ id: UUID, _ value: AuthorityMaintenanceClientReply, until deadline: ContinuousClock.Instant) -> Bool {
        lock.withLock { guard active, expected == id, delivered == nil, ContinuousClock.now < deadline else { return false }; delivered = value; return true }
    }
    func reply(_ id: UUID) -> AuthorityMaintenanceClientReply? { lock.withLock { expected == id ? delivered : nil } }
    func ifActive(_ body: () -> Void = {}) -> Bool { lock.withLock { guard active else { return false }; body(); return true } }
}

/// One Setup connection. Lost replies require recovery; only stagesPending permits bounded arm retries.
actor AuthorityMaintenanceXPCClient {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private enum State { case new, open, armed, closed }
    private let driver: any AuthorityMaintenanceClientDriver, context: Request
    private let verify: @Sendable () throws -> Void, timeout: Duration, interval: Duration
    private let lifetime = MaintenanceClientLifetime()
    private var state = State.new, busy = false, binding: AuthorityMaintenanceBinding?
    private var pending: (UUID, CheckedContinuation<AuthorityMaintenanceClientReply, Error>)?, timer: Task<Void, Never>?
    init(context: AuthorityMaintenanceChannelRequest, authority: AuthorityCodeEntry, setup: AuthorityCodeEntry,
         release: SignedReleaseEvidence) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try AuthorityMaintenanceChannelScope.validate(release, authority: authority, setup: setup)
        let policy = try XPCPeerPolicy(teamID: authority.teamID, componentIdentifier: authority.identifier,
            approvedCodeDirectoryHashes: [authority.codeDirectoryHash], expectedUserID: 0)
        let selfPolicy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        let pid = getpid()
        let verify: @Sendable () throws -> Void = {
            guard getpid() == pid, getuid() == 0, geteuid() == 0,
                  try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw RuntimePreparationError.changedScope
            }
            try DynamicCodeValidation.validateSelf(requirement: selfPolicy.requirement + " and info[\"RemozioSecurityGeneration\"] = \"\(setup.installedGeneration)\"")
        }
        try verify(); guard context.action == .open else { throw RuntimePreparationError.invalidRecord }
        self.context = context; self.verify = verify; timeout = .seconds(5); interval = .milliseconds(50)
        driver = try NativeMaintenanceClient(accountID: context.accountID, policy: policy)
    }
    private init(context: Request, driver: any AuthorityMaintenanceClientDriver, timeout: Duration, interval: Duration,
                 verify: @escaping @Sendable () throws -> Void) { self.context = context; self.driver = driver; self.timeout = timeout; self.interval = interval; self.verify = verify }
    static func openOwned(context: AuthorityMaintenanceChannelRequest, driver: any AuthorityMaintenanceClientDriver,
        timeoutMilliseconds: UInt64 = 5000, intervalMilliseconds: UInt64 = 50,
        verify: @escaping @Sendable () throws -> Void = {}) throws -> AuthorityMaintenanceXPCClient {
        guard getuid() > 0, getuid() == geteuid(), context.action == .open,
              (1...60_000).contains(timeoutMilliseconds), (1...1000).contains(intervalMilliseconds) else { throw JournalLeaseError.unsafeMetadata }
        let pid = getpid(), uid = getuid()
        return .init(context: context, driver: driver, timeout: .milliseconds(timeoutMilliseconds), interval: .milliseconds(intervalMilliseconds), verify: {
            guard getpid() == pid, getuid() == uid, geteuid() == uid else { throw JournalLeaseError.invalidated }; try verify()
        })
    }
    deinit { lifetime.close(); timer?.cancel(); driver.close() }
    func start(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .new else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        guard case .hello(1) = try await invoke(nil, until: deadline) else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        let response = try await send(.open, until: deadline); binding = response.binding; if state != .closed { state = .open }; return response
    }
    func observe(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .open else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        return try await send(.observe, until: deadline)
    }
    func arm(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .open else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        while ContinuousClock.now < deadline {
            let response = try await send(.arm, until: deadline)
            if response.outcome == .applied { if state != .closed { state = .armed }; return response }
            do { try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: interval))) }
            catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        }
        _ = try await send(.cancel, until: .now.advanced(by: timeout)); finish(.cancelled); throw AuthorityMaintenanceClientError.cancelled
    }
    func release(_ target: AuthorityMaintenanceBinding? = nil, reopen: Bool = false,
                 until deadline: ContinuousClock.Instant) async throws {
        guard state == .open || state == .armed else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        guard target == nil || target?.incarnation == binding?.incarnation else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        _ = try await send(reopen ? .reopen : .cancel, target: target, until: deadline); finish(.cancelled)
    }
    func close() { finish() }
    private func enter() throws {
        guard !busy else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }; busy = true
    }
    private func send(_ action: Request.Action, target: AuthorityMaintenanceBinding? = nil,
                      until deadline: ContinuousClock.Instant) async throws -> Response {
        do {
            var challenge = Data(count: 32)
            guard challenge.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw RuntimePreparationError.invalidRecord }
            let q = try Request(action: action, accountID: context.accountID, attemptID: context.attemptID, revision: context.revision,
                installationID: context.installationID, gate: context.gate, binding: action == .open ? nil : target ?? binding, challenge: challenge)
            guard case .bytes(let bytes) = try await invoke(q, until: deadline), let bytes else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            let response = try Response.decode(bytes, expected: q)
            if response.outcome == .refused {
                let error: AuthorityMaintenanceClientError = action == .cancel || action == .reopen ? .needsOwnerRecovery : .cancelled
                finish(error); throw error
            }
            return response
        } catch { finish(); throw (error as? AuthorityMaintenanceClientError) ?? .needsOwnerRecovery }
    }
    private func invoke(_ q: Request?, until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceClientReply {
        do { try Task.checkCancellation(); try verify() } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        guard state != .closed, lifetime.ifActive(), ContinuousClock.now < deadline else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        let id = UUID(), end = min(deadline, .now.advanced(by: timeout)), payload = try q?.encoded
        let value: AuthorityMaintenanceClientReply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                guard lifetime.begin(id) else { finish(); return }
                timer = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: end) } catch { return }; await self?.expire(id)
                }
                let reply: @Sendable (AuthorityMaintenanceClientReply) -> Void = { [weak self, lifetime] value in
                    guard lifetime.record(id, value, until: end) else { return }; Task { await self?.received(id) }
                }
                if q == nil { driver.start { [weak self, lifetime] in lifetime.invalidate(); Task { await self?.finish(preservingReply: true) } } }
                guard lifetime.ifActive({ if let payload { driver.exchange(payload, reply) } else { driver.hello(reply) } }) else { finish(); return }
            }
        } onCancel: { [weak self, lifetime, driver] in lifetime.close(); driver.close(); Task { await self?.close() } }
        do { try Task.checkCancellation(); try verify() } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        guard lifetime.reply(id) != nil else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        if !lifetime.ifActive() { finish(preservingReply: true) }; return value
    }
    private func received(_ id: UUID) {
        guard let p = pending, p.0 == id else { return }
        guard let value = lifetime.reply(id) else { finish(); return }; pending = nil; timer?.cancel(); timer = nil; p.1.resume(returning: value)
    }
    private func expire(_ id: UUID) { if pending?.0 == id { finish(preservingReply: true) } }
    private func finish(_ error: AuthorityMaintenanceClientError = .needsOwnerRecovery, preservingReply: Bool = false) {
        guard state != .closed else { return }
        let p = pending, value = preservingReply ? pending.flatMap { lifetime.reply($0.0) } : nil
        state = .closed; if preservingReply { lifetime.invalidate() } else { lifetime.close() }; timer?.cancel(); timer = nil
        pending = nil; driver.close()
        if let value { p?.1.resume(returning: value) } else { p?.1.resume(throwing: error) }
    }
}
