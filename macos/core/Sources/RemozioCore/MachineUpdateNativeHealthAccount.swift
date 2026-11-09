import Foundation

protocol OwnedMachineUpdateAuthorityHealth: AnyObject, Sendable {
    func answerRestartReadiness(_ request: MachineUpdateAuthorityReadinessRequest) throws -> Data
    func validateHealthScope() throws
    func requireGatewayHealth(_ proof: MachineUpdateConsumerHealthProof) throws
    func close() throws
}
extension MachineUpdateAuthorityHealthOwner: OwnedMachineUpdateAuthorityHealth {}

protocol OwnedMachineUpdateGatewayJournalHealth: AnyObject, Sendable {
    func accept(_ proof: MachineUpdateConsumerHealthProof) throws
    func validateHealthScope() throws
    func close() throws
}
extension MachineUpdateGatewayPairedHealthReader: OwnedMachineUpdateGatewayJournalHealth {}

protocol OwnedMachineUpdateHealthConnection: AnyObject, Sendable {
    var proof: MachineUpdateConsumerHealthProof { get }
    var exchange: MachineUpdateConsumerHealthExchange { get }
    func validate() throws
    func close() async
}
extension MachineUpdateConsumerHealthConnectionScope: OwnedMachineUpdateHealthConnection {}

/// Uses the existing native factories. The injected operations support owned composition tests only.
final class MachineUpdateNativeHealthAccount: OwnedMachineUpdateRestartAccount, @unchecked Sendable {
    struct Operations: Sendable {
        let verifyCurrent: @Sendable () throws -> Void
        let makeAuthority: @Sendable () throws -> any OwnedMachineUpdateAuthorityHealth
        let makeGatewayReader: @Sendable () throws -> any OwnedMachineUpdateGatewayJournalHealth
        let makeConnection: @Sendable (MachineUpdateRestartHealthPlan.Requirement, Data?) async throws -> any OwnedMachineUpdateHealthConnection
    }
    let accountID: Data
    private let requirements: [MachineUpdateRestartHealthPlan.Requirement]
    private let operations: Operations
    private let lock = NSLock()
    private var started = false, checked = false, retired = false, closing = false, closed = false
    private var authority: (any OwnedMachineUpdateAuthorityHealth)?
    private var gatewayReader: (any OwnedMachineUpdateGatewayJournalHealth)?
    private var connections: [ObjectIdentifier: any OwnedMachineUpdateHealthConnection] = [:]
    private var gatewayProof: MachineUpdateConsumerHealthProof?
    private var operation: Task<[MachineUpdateAuthenticatedRoleReply], Error>?
    private var settlement: (id: UUID, task: Task<Void, Error>)?

    init(accountID: Data, requirements: [MachineUpdateRestartHealthPlan.Requirement], operations: Operations) throws {
        let inventory = try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: [])
        guard inventory.accountIDs == [accountID] else { throw MachineUpdateHealthCoordinatorError.invalidInventory }
        self.accountID = accountID; self.requirements = inventory.requirements; self.operations = operations
    }
    func check() async throws -> [MachineUpdateAuthenticatedRoleReply] {
        let task = try lock.withLock { () -> Task<[MachineUpdateAuthenticatedRoleReply], Error> in
            guard !started, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed }
            started = true
            let task = Task { [self] in try await perform() }; operation = task; return task
        }
        do {
            let value = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
            try Task.checkCancellation(); try validate(); return value
        } catch MachineUpdateHealthSourceError.busy {
            throw MachineUpdateHealthSourceError.busy
        } catch { lock.withLock { retired = true }; throw error }
    }
    private func perform() async throws -> [MachineUpdateAuthenticatedRoleReply] {
        try operations.verifyCurrent(); try Task.checkCancellation()
        var replies: [MachineUpdateAuthenticatedRoleReply] = []
        let authorityAttempt: (owner: any OwnedMachineUpdateAuthorityHealth, session: MachineUpdateRoleChallengeSession)?
        if let requirement = requirements.first(where: { $0.role == .authority }) {
            let opened = try operations.makeAuthority()
            lock.withLock { authority = opened }
            try operations.verifyCurrent(); try Task.checkCancellation(); try opened.validateHealthScope()
            let current = operations.verifyCurrent
            let session = try MachineUpdateRoleChallengeSession(requirement: requirement,
                verifyCurrent: { try current(); try opened.validateHealthScope() })
            authorityAttempt = (opened, session)
        } else {
            guard requirements.contains(where: { $0.role == .notificationGateway }) else {
                throw MachineUpdateHealthCoordinatorError.invalidInventory
            }
            let opened = try operations.makeGatewayReader()
            lock.withLock { gatewayReader = opened }
            try operations.verifyCurrent(); try Task.checkCancellation()
            authorityAttempt = nil
        }
        defer { authorityAttempt?.session.close() }

        var gatewayConnection: (any OwnedMachineUpdateHealthConnection)?
        for requirement in requirements where requirement.role != .authority {
            try operations.verifyCurrent(); try Task.checkCancellation()
            let authorityChallenge = try requirement.role == .notificationGateway ? authorityAttempt?.session.request : nil
            let connection = try await operations.makeConnection(requirement, authorityChallenge)
            try lock.withLock {
                let id = ObjectIdentifier(connection)
                guard connections[id] == nil else { throw MachineUpdateHealthCoordinatorError.duplicateOwner }
                connections[id] = connection
            }
            try Task.checkCancellation(); try operations.verifyCurrent(); try connection.validate()
            let proof = connection.proof
            guard proof.role.requirement == requirement else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
            if requirement.role == .notificationGateway {
                if authorityAttempt == nil {
                    guard let reader = lock.withLock({ gatewayReader }) else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
                    try reader.accept(proof)
                }
                gatewayConnection = connection
                lock.withLock { gatewayProof = proof }
            }
            replies.append(proof.role)
        }
        if let (owner, session) = authorityAttempt {
            try Task.checkCancellation(); try operations.verifyCurrent()
            let request = try MachineUpdateAuthorityReadinessRequest(challenge: session.request, gateway: gatewayConnection?.exchange)
            try gatewayConnection?.validate()
            let reply = try owner.answerRestartReadiness(request)
            replies.insert(try session.accept(reply, authenticatePeer: { _ in try owner.validateHealthScope() }), at: 0)
            try gatewayConnection?.validate()
        }
        let inventory = try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: [])
        try inventory.requireReplies(replies, accountID: accountID)
        try operations.verifyCurrent(); try Task.checkCancellation()
        try lock.withLock {
            guard !closing, !closed, !retired else { throw MachineUpdateHealthCoordinatorError.closed }
            checked = true
        }
        try validate(); return replies
    }
    func validate() throws {
        let owners = try lock.withLock { () -> ((any OwnedMachineUpdateAuthorityHealth)?, (any OwnedMachineUpdateGatewayJournalHealth)?,
                                                [any OwnedMachineUpdateHealthConnection], MachineUpdateConsumerHealthProof?) in
            guard checked, !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed }
            return (authority, gatewayReader, Array(connections.values), gatewayProof)
        }
        do {
            try operations.verifyCurrent()
            try owners.0?.validateHealthScope()
            for connection in owners.2 { try connection.validate() }
            if let proof = owners.3 {
                if let authority = owners.0 { try authority.requireGatewayHealth(proof) }
                else if let gatewayReader = owners.1 { try gatewayReader.validateHealthScope() }
                else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
            }
            try operations.verifyCurrent()
            try lock.withLock { guard !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed } }
        } catch MachineUpdateHealthSourceError.busy {
            throw MachineUpdateHealthSourceError.busy
        } catch { lock.withLock { retired = true }; throw error }
    }

    func close() async throws {
        let pending = lock.withLock { () -> (id: UUID, task: Task<Void, Error>)? in
            if closed { return nil }
            closing = true; operation?.cancel()
            if let settlement { return settlement }
            let operation = operation
            let pending = (UUID(), Task { [self] in _ = await operation?.result; try await closeResources() })
            settlement = pending; return pending
        }
        guard let pending else { return }
        do {
            try await pending.task.value
            lock.withLock { if settlement?.id == pending.id { settlement = nil; operation = nil; closed = true } }
        } catch {
            lock.withLock { if settlement?.id == pending.id { settlement = nil } }
            throw error
        }
    }
    private func closeResources() async throws {
        let snapshot = lock.withLock { (connections, authority, gatewayReader) }
        for (id, connection) in snapshot.0 {
            await connection.close(); lock.withLock { _ = connections.removeValue(forKey: id) }
        }
        var failure: Error?
        do { try snapshot.1?.close(); lock.withLock { authority = nil } } catch { failure = error }
        do { try snapshot.2?.close(); lock.withLock { gatewayReader = nil } } catch { if failure == nil { failure = error } }
        if let failure { throw failure }
        lock.withLock { gatewayProof = nil }
    }
    deinit {
        if closed { return }
        let operation = operation, settlement = settlement?.task
        let connections = Array(connections.values), authority = authority, reader = gatewayReader
        operation?.cancel()
        Task {
            if let settlement, (try? await settlement.value) != nil { return }
            _ = await operation?.result
            for connection in connections { await connection.close() }
            var pendingAuthority = authority, pendingReader = reader
            while pendingAuthority != nil || pendingReader != nil {
                do { try pendingAuthority?.close(); pendingAuthority = nil } catch {}
                do { try pendingReader?.close(); pendingReader = nil } catch {}
                if pendingAuthority != nil || pendingReader != nil { try? await Task.sleep(for: .milliseconds(100)) }
            }
        }
    }
}
