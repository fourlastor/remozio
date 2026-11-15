import Darwin
import Foundation

/// Setup serializes exchanges. A concurrent call closes the connection and releases its pre-arm block.
@objc protocol AuthorityMaintenanceXPCProtocol {
    func exchange(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Process-bound access. Root cannot construct a fixture; the protected native producer belongs to b4.
final class AuthorityMaintenanceChannelAccess: Sendable {
    let admission: AuthorityMaintenancePairingAdmission
    let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
    private let processID = getpid(), owner = getuid()
    private let check: @Sendable (AuthorityMaintenanceChannelRequest) throws -> Void
    private let observe: @Sendable (AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork
    private init(admission: AuthorityMaintenancePairingAdmission, acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken?,
        check: @escaping @Sendable (AuthorityMaintenanceChannelRequest) throws -> Void,
        observe: @escaping @Sendable (AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork) {
        self.admission = admission; self.acquireActivity = acquireActivity; self.check = check; self.observe = observe
    }
    static func openOwned(admission: AuthorityMaintenancePairingAdmission,
        acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken? = { nil },
        check: @escaping @Sendable (AuthorityMaintenanceChannelRequest) throws -> Void,
        observe: @escaping @Sendable (AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork) throws -> AuthorityMaintenanceChannelAccess {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return .init(admission: admission, acquireActivity: acquireActivity, check: check, observe: observe)
    }
    func validateIdentity() throws {
        guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.invalidated }
    }
    func validate(_ q: AuthorityMaintenanceChannelRequest) throws { try validateIdentity(); try check(q) }
    func capture(_ q: AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork {
        try validate(q); let result = try await observe(q); try validate(q); return result
    }
}

/// Repeated calls retain one binding. The outer owner must join closeAndWait before closing storage.
final class AuthorityMaintenanceXPCEndpoint: NSObject, AuthorityMaintenanceXPCProtocol, @unchecked Sendable {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private let lock = NSRecursiveLock()
    private let access: AuthorityMaintenanceChannelAccess, budget: AuthorityXPCWorkBudget
    private let verify: () throws -> Void
    private let invalidate: () -> Void, onHandshake: @Sendable () -> Void
    private var context: (Request, AuthorityMaintenancePairingAdmission.Connection)?
    private var tasks: [UUID: Task<Void, Never>] = [:]
    private var active: UUID?, budgetOwners = Set<UUID>()
    private var closed = false
    private init(access: AuthorityMaintenanceChannelAccess, budget: AuthorityXPCWorkBudget,
        verify: @escaping () throws -> Void, invalidate: @escaping () -> Void, onHandshake: @escaping @Sendable () -> Void) {
        self.access = access; self.budget = budget; self.verify = verify; self.invalidate = invalidate; self.onHandshake = onHandshake
    }
    convenience init(connection: NSXPCConnection, setupCode: AuthorityCodeEntry, access: AuthorityMaintenanceChannelAccess,
        budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws {
        guard getuid() == 0, geteuid() == 0, setupCode.role == .setupController, setupCode.active else { throw JournalLeaseError.rootRequired }
        try access.validateIdentity()
        let policy = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        _ = try policy.verifyCredentials(connection)
        let guardOwner = XPCInvocationGuard(connection: connection, policy: policy)
        self.init(access: access, budget: budget, verify: { _ = try guardOwner.verifyInvocation() },
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
        policy.configure(connection); connection.exportedInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self)
        connection.exportedObject = self
        connection.interruptionHandler = { [weak self] in self?.close() }; connection.invalidationHandler = { [weak self] in self?.close() }
    }
    static func openOwned(access: AuthorityMaintenanceChannelAccess, budget: AuthorityXPCWorkBudget,
        verify: @escaping () throws -> Void = {}, invalidate: @escaping () -> Void = {},
        onHandshake: @escaping @Sendable () -> Void = {}) throws -> AuthorityMaintenanceXPCEndpoint {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return .init(access: access, budget: budget, verify: verify, invalidate: invalidate, onHandshake: onHandshake)
    }
    deinit { close() }
    func close() {
        let pending = lock.withLock { () -> ([Task<Void, Never>], AuthorityMaintenancePairingAdmission.Connection?)? in
            guard !closed else { return nil }; closed = true; return (Array(tasks.values), context?.1)
        }
        if let pending { pending.1?.close(); pending.0.forEach { $0.cancel() }; invalidate() }
    }
    func closeAndWait() async { close(); let pending = lock.withLock { Array(tasks.values) }; for task in pending { await task.value } }
    func pendingOperations() -> Int { lock.withLock { tasks.count } }
    func exchange(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            // Authenticate on the original exported invocation stack before any asynchronous or protected access.
            try verify(); let q = try Request.decode(payload)
            try lock.withLock {
                guard !closed, active == nil, budget.acquire() else { throw AuthorityXPCEndpointError.unavailable }
                let id = UUID(); active = id; budgetOwners.insert(id)
                tasks[id] = Task { [self] in
                    defer { lock.withLock { releaseBudget(id); tasks[id] = nil } }
                    let result = await response(q)
                    lock.withLock { releaseBudget(id); if !closed { reply(result.0) } }
                    if result.1 { close() }
                }
            }
        } catch { close(); reply(nil) }
    }
    private func releaseBudget(_ id: UUID) {
        if active == id { active = nil }
        if budgetOwners.remove(id) != nil { budget.release() }
    }
    private func begin(_ q: Request) throws -> AuthorityMaintenancePairingAdmission.Connection {
        if q.action == .open {
            let owner = try lock.withLock {
                guard !closed, context == nil else { throw RuntimePreparationError.changedScope }
                let owner = try access.admission.openConnection(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision)
                context = (q, owner); return owner
            }
            onHandshake(); return owner
        }
        return try lock.withLock {
            guard !closed, let (original, owner) = context, original.accountID == q.accountID,
                  original.attemptID == q.attemptID, original.revision == q.revision,
                  original.installationID == q.installationID, original.gate == q.gate,
                  q.action == .cancel || q.action == .reopen || q.binding == owner.binding else { throw RuntimePreparationError.changedScope }
            return owner
        }
    }
    private func response(_ q: Request) async -> (Data?, Bool) {
        // A refused open echoes metadata only. No Connection exists until all open checks and capture succeed.
        var binding = q.binding ?? (try? access.admission.refusalBinding(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision))
        var opened = false
        var transferred: AuthorityMaintenancePairingAdmission.Shutdown?
        do {
            try Task.checkCancellation(); try access.validate(q)
            let activity = try access.acquireActivity(); defer { activity?.close() }
            try activity?.validate()
            let initialWork = q.action == .open ? try await access.capture(q) : nil
            try access.validate(q); try activity?.validate(); try Task.checkCancellation()
            let owner = try begin(q); opened = q.action == .open; binding = q.binding ?? owner.binding
            guard let binding else { throw RuntimePreparationError.changedScope }
            if q.action == .cancel || q.action == .reopen {
                let bytes = try Response(request: q, binding: binding, work: nil, outcome: .applied).encoded
                try access.validate(q); try activity?.validate(); try Task.checkCancellation()
                if let shutdown = try? access.admission.shutdownBinding(matching: binding) {
                    if q.action == .cancel { try shutdown.cancel(matching: binding) } else { try shutdown.reopen(matching: binding) }
                } else { try owner.releaseUnarmed(matching: binding) }
                // The client closes after receiving the applied release acknowledgement.
                return (bytes, false)
            }
            let outcome: Response.Outcome
            do {
                if q.action == .arm {
                    _ = try owner.blockNewStages(matching: binding)
                    try access.validate(q); try activity?.validate(); try Task.checkCancellation()
                    transferred = try owner.transferToShutdown(matching: binding)
                }
                outcome = .applied
            } catch AuthorityMaintenancePairingAdmission.TransferError.stagesPending(_) { outcome = .stagesPending }
            let work = q.action == .open ? initialWork : try await access.capture(q)
            if transferred == nil { try access.validate(q); try activity?.validate(); try Task.checkCancellation() }
            let bytes = try Response(request: q, binding: binding, work: work, outcome: outcome).encoded
            return (bytes, false)
        } catch {
            if let transferred {
                do { try transferred.cancel(matching: transferred.binding) } catch { return (nil, true) }
            }
            guard !opened, let binding else { return (nil, true) }
            return (try? Response(request: q, binding: binding, work: nil, outcome: .refused).encoded, true)
        }
    }
}
