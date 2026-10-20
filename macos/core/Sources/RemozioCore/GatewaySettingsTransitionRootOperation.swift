import Darwin
import Foundation

/// Short protected borrows for one exact pending settings revision. No machine store survives a native exchange.
final class GatewaySettingsTransitionContext: Sendable {
    enum Phase: Equatable, Sendable { case pending, complete }
    let snapshot: GatewaySettingsTransitionSnapshot
    private let processID = getpid()
    private let timeoutMilliseconds: UInt64
    private let openMachine: @Sendable () throws -> PreparationIntentStore
    private let verifyHost: @Sendable (InstallationInventory) throws -> Void
    private let verifyAccount: @Sendable (AccountPreparationIntent) throws -> Void

    init(snapshot: GatewaySettingsTransitionSnapshot,
         openMachine: @escaping @Sendable () throws -> PreparationIntentStore,
         verifyHost: @escaping @Sendable (InstallationInventory) throws -> Void,
         verifyAccount: @escaping @Sendable (AccountPreparationIntent) throws -> Void,
         timeoutMilliseconds: UInt64 = 60_000) throws {
        guard (1...60_000).contains(timeoutMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        self.timeoutMilliseconds = timeoutMilliseconds
        self.snapshot = snapshot; self.openMachine = openMachine
        self.verifyHost = verifyHost; self.verifyAccount = verifyAccount
    }
    private func borrow<Value>(_ perform: (PreparationIntentStore) throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try Task.checkCancellation()
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        var opened: PreparationIntentStore?
        while opened == nil {
            do { opened = try openMachine() }
            catch JournalLeaseError.busy {
                try Task.checkCancellation()
                guard DispatchTime.now().uptimeNanoseconds < deadline else { throw JournalLeaseError.busy }
                usleep(50_000)
            }
        }
        guard let machine = opened else { throw GatewayPreparationError.incomplete }
        do {
            try verifyBorrowed(machine); let result = try perform(machine); try verifyBorrowed(machine)
            try machine.close(); return result
        } catch { try? machine.close(); throw error }
    }
    private func verifyBorrowed(_ machine: PreparationIntentStore) throws {
        try Task.checkCancellation()
        guard getpid() == processID, try machine.inventory() == snapshot.inventory,
              try machine.initialization(accountID: snapshot.account.accountID) == snapshot.initialization else {
            throw GatewayPreparationError.changedScope
        }
        try verifyHost(snapshot.inventory); try machine.validateAccountPreparation(snapshot.account)
        try verifyAccount(snapshot.account)
    }
    func verify(_ phase: Phase) throws {
        try borrow { machine in
            switch phase {
            case .pending: try snapshot.withPendingScope(machine: machine) { _, _ in }
            case .complete: try snapshot.withCompleteScope(machine: machine) { _, _ in }
            }
        }
    }
    /// Capture a phase once. A channel rechecks this same phase before and after each native call.
    func observePhase() throws -> Phase {
        try borrow { machine in
            let state = try machine.gatewaySettingsTransition(accountID: snapshot.account.accountID)
            if state.pending != nil {
                try snapshot.withPendingScope(machine: machine) { _, _ in }; return .pending
            }
            try snapshot.withCompleteScope(machine: machine) { _, _ in }; return .complete
        }
    }
    private func release(_ phase: Phase) throws -> SignedReleaseEvidence {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try verify(phase)
        let policy = snapshot.foreground.host.codePolicy
        guard let app = policy.entries.first(where: { $0.role == .app && $0.active }),
              let setup = policy.entries.first(where: { $0.role == .setupController && $0.active }),
              let hosts = snapshot.foreground.consumerHosts else { throw GatewayPreparationError.changedScope }
        let release = try SignedReleaseInspection.inspect(URL(fileURLWithPath: snapshot.inventory.bundlePath),
            teamID: app.teamID, appIdentifier: app.identifier)
        try snapshot.foreground.host.validateRelease(release, bundlePath: snapshot.inventory.bundlePath)
        try hosts.validateRelease(release)
        let local = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        try DynamicCodeValidation.validateSelf(requirement: local.requirement)
        try verify(phase); return release
    }
    private func code(_ role: AuthorityCodeRole) throws -> AuthorityCodeEntry {
        guard let value = snapshot.foreground.host.codePolicy.entries.first(where: { $0.role == role && $0.active }) else {
            throw GatewayPreparationError.changedScope
        }
        return value
    }
    private func root(_ action: GatewaySettingsControlAction, expected: UUID?) async throws -> GatewaySettingsControlResponse {
        let phase: Phase
        switch action {
        case .quiesce: phase = .pending
        case .accept: phase = .complete
        case .observe: phase = try observePhase()
        }
        let release = try self.release(phase)
        let channel = try GatewaySettingsControlChannel(accountID: snapshot.account.accountID,
            authorityCode: code(.authority), setupCode: code(.setupController), release: release,
            expectedRootEpoch: expected, timeoutMilliseconds: timeoutMilliseconds, verifyCurrent: { [self] in try verify(phase) })
        do {
            let result = try await channel.execute(AuthorityPhonePushSettingsChange(snapshot.plan), action: action)
            await channel.close(); try verify(phase); return result
        } catch { await channel.close(); throw error }
    }
    private func consumer(_ role: GatewaySettingsConsumerRole, action: GatewaySettingsControlAction,
                          expected: UUID?) async throws -> GatewaySettingsConsumerResponse {
        let phase = Phase.pending, release = try self.release(phase)
        let channel = try GatewaySettingsConsumerChannel(role: role,
            services: snapshot.plan.pair.authority.material.runtime.services,
            consumerCode: code(role.codeRole), setupCode: code(.setupController), release: release,
            expectedGeneration: expected, timeoutMilliseconds: timeoutMilliseconds, verifyCurrent: { [self] in try verify(phase) })
        do {
            let result = try await channel.execute(GatewayRuntimeSettingsFence(snapshot.plan), action: action)
            await channel.close(); try verify(phase); return result
        } catch { await channel.close(); throw error }
    }
    private func observe(_ role: GatewaySettingsConsumerRole) async throws -> GatewaySettingsConsumerBinding {
        let phase = try observePhase(), release = try self.release(phase)
        let channel = try GatewaySettingsConsumerChannel(role: role,
            services: snapshot.plan.pair.authority.material.runtime.services,
            consumerCode: code(role.codeRole), setupCode: code(.setupController), release: release,
            expectedGeneration: nil, timeoutMilliseconds: timeoutMilliseconds, verifyCurrent: { [self] in try verify(phase) })
        do {
            let binding = try await channel.observeBinding()
            await channel.close(); try verify(phase); return binding
        } catch { await channel.close(); throw error }
    }
    func nativeOperations() throws -> GatewaySettingsTransitionOperation.Operations {
        guard snapshot.foreground.consumerHosts != nil else { throw GatewayPreparationError.incomplete }
        @Sendable func matches(_ plan: GatewayRuntimeSettingsPublicationPlan) throws {
            guard try GatewayRuntimeSettingsFence(plan).encoded == GatewayRuntimeSettingsFence(self.snapshot.plan).encoded else {
                throw GatewayPreparationError.changedScope
            }
        }
        return .init(verifyPending: { [self] plan in try matches(plan); try verify(.pending) },
            verifyComplete: { [self] plan in try matches(plan); try verify(.complete) },
            root: { [self] plan, action, epoch in try matches(plan); return try await root(action, expected: epoch) },
            publishFence: { [self] plan in
                try matches(plan); let release = try self.release(.pending)
                try borrow { machine in
                    try snapshot.withPendingScope(machine: machine) { scope, _ in
                        _ = try GatewayRuntimeSettingsFencePublication.prepare(scope, release: release,
                            verifyCurrent: { try verifyBorrowed(machine) })
                    }
                }
            }, consumer: { [self] plan, role, action, generation in
                try matches(plan); return try await consumer(role, action: action, expected: generation)
            }, observe: { [self] role in try await observe(role) },
            mark: { [self] plan, phase in
                try matches(plan)
                try borrow { machine in
                    try snapshot.withPendingScope(machine: machine) { _, _ in
                        try machine.markGatewaySettingsTransition(snapshot.plan.revision, phase: phase)
                    }
                }
            }, publish: { [self] plan, barrier in
                try matches(plan); _ = try release(.pending)
                try barrier.requireValid(for: snapshot.plan, phase: .quiesced)
                try borrow { machine in
                    try snapshot.withPendingScope(machine: machine) { _, initialization in
                        _ = try GatewayRuntimeSettingsPublication.prepare(snapshot.plan, account: snapshot.account,
                            initialization: initialization,
                            journal: machine.gatewayJournalPreparation(accountID: snapshot.account.accountID),
                            foreground: snapshot.foreground, inventory: snapshot.inventory,
                            verifyCurrent: { try verifyBorrowed(machine) },
                            requireQuiesced: { try barrier.requireValid(for: snapshot.plan, phase: .quiesced) })
                    }
                }
            }, complete: { [self] plan, barrier in
                try matches(plan); try barrier.requireValid(for: snapshot.plan, phase: .accepted)
                try borrow { machine in
                    try snapshot.withPendingScope(machine: machine) { _, _ in }
                    try machine.completeGatewaySettingsTransition(snapshot.plan.revision)
                    try barrier.requireValid(for: snapshot.plan, phase: .accepted)
                    try snapshot.withCompleteScope(machine: machine) { _, _ in }
                }
            }, removeFence: { [self] plan, barrier in
                try matches(plan); let release = try self.release(.complete)
                try barrier.requireValid(for: snapshot.plan, phase: .accepted)
                try borrow { machine in
                    try snapshot.withCompleteScope(machine: machine) { scope, _ in
                        _ = try GatewayRuntimeSettingsFencePublication.removeCompleted(scope, release: release,
                            verifyCurrent: {
                                try verifyBorrowed(machine)
                                try barrier.requireValid(for: snapshot.plan, phase: .accepted)
                            })
                    }
                }
            })
    }
}

/// The authenticated Setup owner supplies the caller and host verifier. This entry grants no administrator rights.
enum GatewaySettingsTransitionRootOperation {
    static func resumeNative(machineDirectory: String, macID: Data, ownerUID: UInt32,
                             expected: SetupGatewayActivationProgress, revision: GatewayRuntimeSettingsRevision,
                             timeoutMilliseconds: UInt64 = 60_000,
                             verifyHost: @escaping @Sendable (InstallationInventory) throws -> Void) async throws
        -> GatewaySettingsTransitionOperation.Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard (1...60_000).contains(timeoutMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: machineDirectory)
        let token = try activity.acquireShared(); defer { token.close() }
        let processID = getpid()
        let verify: @Sendable (InstallationInventory) throws -> Void = { inventory in
            guard getuid() == 0, geteuid() == 0, getpid() == processID else { throw JournalLeaseError.rootRequired }
            try activity.validate(); try token.validate(); try verifyHost(inventory)
        }
        let open: @Sendable () throws -> PreparationIntentStore = {
            try PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID)
        }
        let machine = try open()
        let snapshot: GatewaySettingsTransitionSnapshot
        do {
            guard let inventory = try machine.inventory() else { throw GatewayPreparationError.incomplete }
            try verify(inventory)
            snapshot = try .load(machine: machine, ownerUID: ownerUID, expected: expected, revision: revision)
            try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: ownerUID), uid: ownerUID,
                directoryID: snapshot.account.directoryID)
            try machine.close()
        } catch { try? machine.close(); throw error }
        let context = try GatewaySettingsTransitionContext(snapshot: snapshot, openMachine: open,
            verifyHost: verify, verifyAccount: { account in
                try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: ownerUID), uid: ownerUID,
                    directoryID: account.directoryID)
            }, timeoutMilliseconds: timeoutMilliseconds)
        return try await GatewaySettingsTransitionOperation.resume(snapshot.plan, operations: context.nativeOperations())
    }
}
