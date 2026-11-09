import Foundation

/// Installed owners also recheck their ordinary runtime before terminal publication.
protocol OwnedMachineUpdateInstalledReadinessAccount: OwnedMachineUpdateRestartAccount {
    func validateOrdinaryReadiness() throws
}

protocol OwnedMachineUpdateInstalledRootChannel: AnyObject, Sendable {
    func prepareChallenge() async throws -> Data
    func connect(gateway: MachineUpdateConsumerHealthExchange?) async throws -> any OwnedMachineUpdateHealthConnection
    func close() async
}

private final class NativeMachineUpdateInstalledRootChannel: OwnedMachineUpdateInstalledRootChannel, Sendable {
    private let channel: MachineUpdateConsumerHealthChannel
    init(_ channel: MachineUpdateConsumerHealthChannel) { self.channel = channel }
    func prepareChallenge() async throws -> Data { try await channel.prepareAuthorityReadinessChallenge() }
    func connect(gateway: MachineUpdateConsumerHealthExchange?) async throws -> any OwnedMachineUpdateHealthConnection {
        try await channel.openScope(authorityGatewayExchange: gateway)
    }
    func close() async { await channel.close() }
}

/// Retains each live peer through the final callback. It opens no private key and no Root journal.
final class MachineUpdateNativeInstalledReadinessAccount: OwnedMachineUpdateInstalledReadinessAccount, @unchecked Sendable {
    struct Operations: Sendable {
        let verifyCurrent: @Sendable () throws -> Void
        let clock: @Sendable () throws -> AuthorityMoment
        let makeRoot: @Sendable () throws -> any OwnedMachineUpdateInstalledRootChannel
        let makeConsumer: @Sendable (MachineUpdateRestartHealthPlan.Requirement, Data?) async throws -> any OwnedMachineUpdateHealthConnection
        let release: @Sendable () -> Void
    }
    let accountID: Data
    private let inventory: MachineUpdateHealthInventory
    private let operations: Operations
    private let lifetimeMilliseconds: UInt64
    private let lock = NSLock()
    private var started = false, checked = false, retired = false, closing = false, closed = false, released = false
    private var deadline: (epoch: UUID, end: UInt64, last: UInt64)?
    private var root: (any OwnedMachineUpdateInstalledRootChannel)?
    private var peers: [ObjectIdentifier: any OwnedMachineUpdateHealthConnection] = [:]
    private var operation: Task<[MachineUpdateAuthenticatedRoleReply], Error>?
    private var settlement: Task<Void, Never>?

    /// The installed owner supplies its protected selection and the original activity factory.
    static func native(scope: MachineUpdateAuthorityReadinessScope,
        requirements: [MachineUpdateRestartHealthPlan.Requirement],
        transport: GatewaySettingsConsumerHostConfiguration,
        gateway: GatewaySettingsConsumerHostConfiguration?, registration: GatewayRegistrationIdentity?,
        release: SignedReleaseEvidence
    ) throws -> MachineUpdateNativeInstalledReadinessAccount {
        try scope.validate()
        let root = scope.requirement
        let inventory = try nativeInventory(root: root, requirements: requirements,
            transport: transport, gateway: gateway, registration: registration, release: release)

        let activity = try scope.acquireActivity()
        do {
            let verify: @Sendable () throws -> Void = {
                try activity.validate(); try scope.validate(); try activity.validate()
            }
            try verify()
            let clock = try AuthorityClock()
            return try Self(accountID: root.binding.accountID, requirements: inventory.requirements,
                operations: .init(verifyCurrent: verify, clock: { try clock.now() },
                    makeRoot: { NativeMachineUpdateInstalledRootChannel(try .nativeAuthorityReadiness(scope: scope)) },
                    makeConsumer: { requirement, rootRequest in
                        try verify()
                        let (host, selectedRegistration) = try consumerSelection(role: requirement.role,
                            rootRequest: rootRequest, transport: transport, gateway: gateway, registration: registration)
                        let loan = try scope.acquireActivity()
                        let channel = try MachineUpdateConsumerHealthChannel.nativeConsumer(host: host, requirement: requirement,
                            registration: selectedRegistration, release: release, purpose: .installedReadiness,
                            authorityReadinessRequest: rootRequest,
                            verifyCurrent: { try verify(); try loan.validate() }, releaseScope: { loan.close() })
                        return try await channel.openScope()
                    }, release: { activity.close() }))
        } catch { activity.close(); throw error }
    }

    /// Selects retained operands only. The native entry still authenticates the process and activity.
    static func nativeInventory(root: MachineUpdateRestartHealthPlan.Requirement,
        requirements: [MachineUpdateRestartHealthPlan.Requirement],
        transport: GatewaySettingsConsumerHostConfiguration,
        gateway: GatewaySettingsConsumerHostConfiguration?, registration: GatewayRegistrationIdentity?,
        release: SignedReleaseEvidence
    ) throws -> MachineUpdateHealthInventory {
        let inventory = try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: [])
        guard inventory.accountIDs == [root.binding.accountID],
              inventory.requirements.first(where: { $0.role == .authority }) == root,
              let selectedTransport = inventory.requirements.first(where: { $0.role == .transport }),
              (gateway != nil) == inventory.requirements.contains(where: { $0.role == .notificationGateway }),
              (registration != nil) == (gateway != nil),
              transport.bundlePath == MachineBootstrap.bundlePath,
              gateway.map({ $0.bundlePath == transport.bundlePath && $0.runtime == transport.runtime }) ?? true else {
            throw MachineUpdateHealthCoordinatorError.invalidInventory
        }
        _ = try MachineUpdateConsumerHealthChannel.peerPins(host: transport, requirement: selectedTransport,
            registration: nil, release: release, purpose: .installedReadiness)
        if let gateway, let selected = inventory.requirements.first(where: { $0.role == .notificationGateway }) {
            _ = try MachineUpdateConsumerHealthChannel.peerPins(host: gateway, requirement: selected,
                registration: registration, release: release, purpose: .installedReadiness)
        }
        return inventory
    }

    static func consumerSelection(role: AuthorityCodeRole, rootRequest: Data?,
        transport: GatewaySettingsConsumerHostConfiguration,
        gateway: GatewaySettingsConsumerHostConfiguration?, registration: GatewayRegistrationIdentity?
    ) throws -> (GatewaySettingsConsumerHostConfiguration, GatewayRegistrationIdentity?) {
        switch role {
        case .transport:
            guard rootRequest == nil else { throw RuntimePreparationError.changedScope }
            return (transport, nil)
        case .notificationGateway:
            guard rootRequest != nil, let gateway, let registration else { throw RuntimePreparationError.changedScope }
            return (gateway, registration)
        default:
            throw RuntimePreparationError.changedScope
        }
    }

    /// Owned callbacks exercise lifecycle and proof coverage. They grant no native process or store access.
    init(accountID: Data, requirements: [MachineUpdateRestartHealthPlan.Requirement], lifetimeMilliseconds: UInt64 = 30000,
        operations: Operations) throws {
        let inventory = try MachineUpdateHealthInventory(requirements: requirements, preservedAccounts: [])
        let roles = Set(inventory.requirements.map { $0.role.rawValue })
        guard inventory.accountIDs == [accountID], (1000...60000).contains(lifetimeMilliseconds),
              roles.contains(AuthorityCodeRole.authority.rawValue), roles.contains(AuthorityCodeRole.transport.rawValue) else {
            throw MachineUpdateHealthCoordinatorError.invalidInventory
        }
        self.accountID = accountID; self.inventory = inventory; self.operations = operations
        self.lifetimeMilliseconds = lifetimeMilliseconds
    }

    func check() async throws -> [MachineUpdateAuthenticatedRoleReply] {
        let task = try lock.withLock { () -> Task<[MachineUpdateAuthenticatedRoleReply], Error> in
            guard !started, !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed }
            started = true
            let task = Task { [self] in try await perform() }; operation = task; return task
        }
        do {
            let replies = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
            try Task.checkCancellation(); try validate(); return replies
        } catch { lock.withLock { retired = true }; throw error }
    }
    private func requireCurrent() throws {
        try lock.withLock { guard !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed } }
        try operations.verifyCurrent()
        let now = try operations.clock()
        try lock.withLock {
            guard !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed }
            if let deadline {
                guard now.epoch == deadline.epoch, now.milliseconds >= deadline.last, now.milliseconds < deadline.end else {
                    retired = true; throw MachineUpdateRoleChallengeError.unavailable
                }
                self.deadline = (deadline.epoch, deadline.end, now.milliseconds)
            } else if started {
                let (end, overflow) = now.milliseconds.addingReportingOverflow(lifetimeMilliseconds)
                guard !overflow else { retired = true; throw MachineUpdateRoleChallengeError.unavailable }
                deadline = (now.epoch, end, now.milliseconds)
            }
        }
        try operations.verifyCurrent()
    }
    private func retain(_ peer: any OwnedMachineUpdateHealthConnection,
        requirement: MachineUpdateRestartHealthPlan.Requirement) throws {
        try lock.withLock {
            let id = ObjectIdentifier(peer)
            guard peers[id] == nil else { throw MachineUpdateHealthCoordinatorError.duplicateOwner }
            peers[id] = peer
        }
        // Retain a late result before cancellation, scope or signature checks can reject it.
        try Task.checkCancellation(); try requireCurrent(); try peer.validate()
        guard peer.proof.role.requirement == requirement,
              peer.proof.role.challengeDigest == MachineUpdateActivationRecord.digest(peer.exchange.request) else {
            throw MachineUpdateHealthCoordinatorError.incompleteHealth
        }
        if requirement.role == .notificationGateway {
            guard peer.proof.gatewayHead != nil else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        } else {
            guard peer.proof.gatewayHead == nil else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        }
    }
    private func perform() async throws -> [MachineUpdateAuthenticatedRoleReply] {
        try requireCurrent(); try Task.checkCancellation()
        guard let expectedRoot = inventory.requirements.first(where: { $0.role == .authority }) else {
            throw MachineUpdateHealthCoordinatorError.invalidInventory
        }
        let opened = try operations.makeRoot(); lock.withLock { root = opened }
        try Task.checkCancellation(); try requireCurrent()
        let rootRequest = try await opened.prepareChallenge()
        guard try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(rootRequest) == expectedRoot else {
            throw MachineUpdateHealthCoordinatorError.changedScope
        }
        var gateway: MachineUpdateConsumerHealthExchange?
        for requirement in inventory.requirements where requirement.role != .authority {
            try requireCurrent(); try Task.checkCancellation()
            let peer = try await operations.makeConsumer(requirement,
                requirement.role == .notificationGateway ? rootRequest : nil)
            try retain(peer, requirement: requirement)
            if requirement.role == .notificationGateway {
                try MachineUpdateRoleChallengeSession.requireGatewayChallenge(peer.exchange.request, boundTo: rootRequest)
                gateway = peer.exchange
            }
        }
        try validatePeers(); try requireCurrent(); try Task.checkCancellation()
        let rootPeer = try await opened.connect(gateway: gateway)
        try retain(rootPeer, requirement: expectedRoot)
        guard rootPeer.exchange.request == rootRequest else { throw MachineUpdateHealthCoordinatorError.changedScope }
        let replies = lock.withLock { peers.values.map { $0.proof.role } }
        try inventory.requireReplies(replies, accountID: accountID)
        try lock.withLock {
            guard !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed }; checked = true
        }
        try validate(); return replies
    }
    private func validatePeers() throws {
        let current = lock.withLock { Array(peers.values) }
        for peer in current { try peer.validate() }
    }
    func validateOrdinaryReadiness() throws {
        let state = lock.withLock { (started, checked) }
        guard !state.0 || state.1 else { throw MachineUpdateHealthCoordinatorError.incompleteHealth }
        do {
            try requireCurrent()
            if state.1 { try validatePeers() }
            try requireCurrent()
        } catch { lock.withLock { retired = true }; throw error }
    }
    func validate() throws {
        do {
            let replies = try lock.withLock { () -> [MachineUpdateAuthenticatedRoleReply] in
                guard checked, !retired, !closing, !closed else { throw MachineUpdateHealthCoordinatorError.closed }
                return peers.values.map { $0.proof.role }
            }
            try requireCurrent(); try inventory.requireReplies(replies, accountID: accountID)
            try validatePeers(); try requireCurrent()
        } catch { lock.withLock { retired = true }; throw error }
    }
    func close() async throws {
        let task = lock.withLock { () -> Task<Void, Never>? in
            if closed { return nil }
            closing = true; operation?.cancel()
            if let settlement { return settlement }
            let operation = operation
            let task = Task { [self] in
                _ = await operation?.result
                let resources = lock.withLock { (Array(peers.values), root) }
                for peer in resources.0 { await peer.close() }
                await resources.1?.close()
                let release = lock.withLock { () -> Bool in
                    peers.removeAll(); root = nil; checked = false
                    guard !released else { return false }; released = true; return true
                }
                if release { operations.release() }
                lock.withLock { closed = true }
            }
            settlement = task; return task
        }
        await task?.value
        lock.withLock { if closed { settlement = nil; operation = nil } }
    }
    deinit {
        guard !released else { return }
        let pending = operation, settlement = settlement, root = root
        let peers = Array(peers.values), release = operations.release
        pending?.cancel()
        Task {
            if let settlement { await settlement.value; return }
            _ = await pending?.result
            for peer in peers { await peer.close() }
            await root?.close(); release()
        }
    }
}
