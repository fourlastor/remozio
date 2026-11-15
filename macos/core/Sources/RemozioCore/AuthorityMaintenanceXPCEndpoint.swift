import Darwin
import Foundation

/// Setup serializes exchanges. A concurrent call closes the connection and releases its pre-arm block.
@objc protocol AuthorityMaintenanceXPCProtocol {
    func hello(reply: @escaping @Sendable (UInt64) -> Void)
    func exchange(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
    func readGate(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void)
}

/// Process-bound access. Root construction uses the installed registration and actual runtime owners.
final class AuthorityMaintenanceChannelAccess: Sendable {
    let admission: AuthorityMaintenancePairingAdmission
    let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
    private let processID = getpid(), owner = getuid()
    private let marker: @Sendable (AuthorityMaintenanceBinding, AuthorityMaintenanceChannelRequest) throws -> AuthorityMaintenanceCloseMarker?
    private let reopen: @Sendable (AuthorityMaintenanceChannelRequest, @Sendable () throws -> Void) throws -> Void
    private let readGate: @Sendable (AuthorityMaintenanceGateRequest) throws -> AuthorityMaintenanceGateResponse
    private let check: @Sendable (AuthorityMaintenanceChannelRequest) throws -> Void
    private let observe: @Sendable (AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork
    private init(admission: AuthorityMaintenancePairingAdmission, acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken?,
        check: @escaping @Sendable (AuthorityMaintenanceChannelRequest) throws -> Void,
        observe: @escaping @Sendable (AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork,
        marker: @escaping @Sendable (AuthorityMaintenanceBinding, AuthorityMaintenanceChannelRequest) throws -> AuthorityMaintenanceCloseMarker? = { _, _ in nil },
        reopen: @escaping @Sendable (AuthorityMaintenanceChannelRequest, @Sendable () throws -> Void) throws -> Void = { _, release in try release() },
        readGate: @escaping @Sendable (AuthorityMaintenanceGateRequest) throws -> AuthorityMaintenanceGateResponse = { _ in throw RuntimePreparationError.changedScope }) {
        self.admission = admission; self.acquireActivity = acquireActivity; self.check = check; self.observe = observe; self.marker = marker; self.reopen = reopen; self.readGate = readGate
    }
    static func openOwned(admission: AuthorityMaintenancePairingAdmission,
        acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken? = { nil },
        check: @escaping @Sendable (AuthorityMaintenanceChannelRequest) throws -> Void,
        observe: @escaping @Sendable (AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelWork,
        reopen: @escaping @Sendable (AuthorityMaintenanceChannelRequest, @Sendable () throws -> Void) throws -> Void = { _, release in try release() },
        readGate: @escaping @Sendable (AuthorityMaintenanceGateRequest) throws -> AuthorityMaintenanceGateResponse = { _ in throw RuntimePreparationError.changedScope }) throws -> AuthorityMaintenanceChannelAccess {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return .init(admission: admission, acquireActivity: acquireActivity, check: check, observe: observe, reopen: reopen, readGate: readGate)
    }
    static func openNative(service: AuthorityWakeService, registration: InstalledAuthorityCommandRegistration) async throws -> AuthorityMaintenanceChannelAccess {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let (admission, incarnation) = try await service.nativeMaintenanceScope()
        let account = try registration.captureMaintenanceAccount(); try admission.requireAccount(account.accountID)
        return .init(admission: admission, acquireActivity: { try registration.releaseActivity.acquireShared() }, check: {
            try service.validateNativeMaintenanceIdentity()
            try registration.validateMaintenanceCommand($0, account: account, incarnation: incarnation, admission: admission)
            try service.validateNativeMaintenanceIdentity()
        }, observe: { _ in try await service.captureNativeMaintenanceWork() }, marker: { binding, q in
            try registration.makeCloseMarker(binding: binding, gate: q.gate, account: account)
        }, reopen: { q, release in
            try service.validateNativeMaintenanceIdentity()
            try registration.reopenMaintenanceAdmission(q, account: account, incarnation: incarnation, admission: admission, releaseBinding: release)
            try service.validateNativeMaintenanceIdentity()
        }, readGate: { request in
            try service.validateNativeMaintenanceIdentity()
            let result = try registration.observeMaintenanceGate(request, account: account, incarnation: incarnation)
            try service.validateNativeMaintenanceIdentity(); return result
        })
    }
    func observeGate(_ request: AuthorityMaintenanceGateRequest) throws -> AuthorityMaintenanceGateResponse {
        try validateIdentity(); let result = try readGate(request); try validateIdentity(); return result
    }
    func retainCloseMarker(_ shutdown: AuthorityMaintenancePairingAdmission.Shutdown, request: AuthorityMaintenanceChannelRequest) throws {
        if let value = try marker(shutdown.binding, request) { try shutdown.retainCloseMarker(value) }
    }
    func reopenAdmission(_ request: AuthorityMaintenanceChannelRequest, releaseBinding: @Sendable () throws -> Void) throws {
        guard request.action == .reopen else { throw RuntimePreparationError.changedScope }
        try validate(request); try reopen(request, releaseBinding); try validateIdentity()
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
    private var closed = false, helloAccepted = false
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
    func hello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            try verify()
            try lock.withLock { guard !closed else { throw AuthorityXPCEndpointError.unavailable }
                helloAccepted = true; reply(AuthorityMaintenanceChannelScope.protocolVersion) }
        } catch { close(); reply(0) }
    }
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
    func readGate(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do {
            try verify(); let request = try AuthorityMaintenanceGateRequest.decode(payload)
            try lock.withLock {
                guard !closed, helloAccepted, active == nil, budget.acquire() else { throw AuthorityXPCEndpointError.unavailable }
                let id = UUID(); active = id; budgetOwners.insert(id)
                tasks[id] = Task { [self] in
                    defer { lock.withLock { releaseBudget(id); tasks[id] = nil } }
                    let bytes: Data?
                    do {
                        try Task.checkCancellation()
                        let activity = try access.acquireActivity(); defer { activity?.close() }
                        try activity?.validate(); let encoded = try access.observeGate(request).encoded
                        try activity?.validate(); try Task.checkCancellation(); onHandshake(); bytes = encoded
                    } catch { bytes = nil }
                    lock.withLock { releaseBudget(id); if !closed { reply(bytes) } }
                    if bytes == nil { close() }
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
            // A reconnect sends hello then the saved reopen target. It creates no new pairing reservation.
            if q.action == .reopen, lock.withLock({ context == nil }) {
                guard let target = q.binding else { throw RuntimePreparationError.changedScope }
                let shutdown = try access.admission.reopenTarget(matching: target)
                try access.reopenAdmission(q, releaseBinding: { try shutdown?.reopen(matching: target) })
                return (try Response(request: q, binding: target, work: nil, outcome: .applied).encoded, false)
            }
            let owner = try begin(q); opened = q.action == .open; binding = q.binding ?? owner.binding
            guard let binding else { throw RuntimePreparationError.changedScope }
            if q.action == .cancel || q.action == .reopen {
                let bytes = try Response(request: q, binding: binding, work: nil, outcome: .applied).encoded
                try access.validate(q); try activity?.validate(); try Task.checkCancellation()
                if q.action == .reopen {
                    let target = binding, shutdown = try access.admission.reopenTarget(matching: target)
                    try access.reopenAdmission(q, releaseBinding: { try shutdown?.reopen(matching: target) })
                } else if let shutdown = try? access.admission.shutdownBinding(matching: binding) {
                    try shutdown.cancel(matching: binding)
                } else { try owner.releaseUnarmed(matching: binding) }
                // The client closes after receiving the applied release acknowledgement.
                return (bytes, false)
            }
            let outcome: Response.Outcome
            do {
                if q.action == .arm {
                    _ = try owner.blockNewStages(matching: binding)
                    try access.validate(q); try activity?.validate(); try Task.checkCancellation()
                    let shutdown = try owner.transferToShutdown(matching: binding); transferred = shutdown
                    try access.retainCloseMarker(shutdown, request: q)
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
