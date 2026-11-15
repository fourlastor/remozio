import Darwin
import Foundation

/// Sequences one Setup restoration after a settled body: workSettled, restoring, one registration and floors.
/// openNative runs synchronously on the stop owner's thread. Every later method is process-bound, not thread-bound,
/// so an actor can call it across await; each makes its own fresh checks and none touches the stop boundary or scope.
/// It opens no Authority journal or continuity store, never replays the body and grants no healthy reopen.
/// Setup keeps its machine activity and the account drain; the client's pending write precedes the drain release.
final class RuntimeMaintenanceRestoration: @unchecked Sendable {
    typealias Record = RuntimeMaintenanceWindowRecord
    typealias Transition = PreparationIntentStore.RuntimeMaintenanceTransition
    private enum Commit {
        case native(@Sendable (Record, Record) throws -> Transition), owned(@Sendable (Record, Record) throws -> Record)
        func write(_ next: Record, replacing previous: Record) throws -> Transition? {
            switch self {
            case .native(let persist):
                let receipt = try persist(next, previous); try receipt.requireReplacement(next, replacing: previous); return receipt
            case .owned(let persist):
                guard try persist(next, previous) == next else { throw RuntimePreparationError.changedScope }; return nil
            }
        }
    }
    typealias Floors = (Record, RuntimeMaintenanceAuthorityCohort) throws -> Void
    typealias Inspect = (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation
    typealias Observe = (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness
    /// The committed restoring row and the old incarnation's shutdown binding.
    let window: Record, stoppedBinding: AuthorityMaintenanceBinding
    let job: InstalledAccountJobManifest, code: AuthorityCodeEntry
    private let settled: Record, held: RuntimeMaintenanceRestorationHold, commit: Commit
    private let requireReceipt: () throws -> Void, floors: Floors, inspect: Inspect, observe: Observe
    private let processID = getpid()
    private let lock = NSRecursiveLock()
    private var witness: (peer: any RuntimeJobExitWitness, own: any RuntimeJobExitWitness)?
    private var witnessUsed = false, pendingIssued = false, recoveryUsed = false, drainReleased = false
    private var pending: Record?
    private init(window: Record, binding: AuthorityMaintenanceBinding, settled: Record, held: RuntimeMaintenanceRestorationHold,
        commit: Commit, requireReceipt: @escaping () throws -> Void, floors: @escaping Floors, inspect: @escaping Inspect,
        observe: @escaping Observe) {
        self.window = window; stoppedBinding = binding; job = held.cohort.job; code = held.code
        self.settled = settled; self.held = held; self.commit = commit; self.requireReceipt = requireReceipt
        self.floors = floors; self.inspect = inspect; self.observe = observe
    }

    /// Root entry. persist must return the real writer's receipt for exactly (next, previous).
    static func openNative(stop: RuntimeMaintenanceAuthorityStop, executing: Record, operation: Record.OperationOutcome,
        admission: UpdateOrdinaryAdmissionLease, release: SignedReleaseEvidence, expected: MachineUpdateStableReleaseSnapshot,
        persist: @escaping @Sendable (Record, Record) throws -> Transition) throws -> RuntimeMaintenanceRestoration {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        return try open(stop: stop, executing: executing, operation: operation, commit: .native(persist), issue: { restoring, settled, receipt in
            guard let receipt else { throw RuntimePreparationError.changedScope }
            return try stop.issueNativeRestorationPermit(restoring: receipt, replacing: settled, admission: admission)
        }, register: { try RuntimeJobRegistration.ensureRestoration($0, release: release) }, floors: { window, cohort in
            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do {
                try requireFloors(machine: machine, release: release, window: window, expected: expected,
                    machineIdentity: cohort.machineIdentity, accountID: cohort.accountID, accountIdentity: cohort.accountIdentity)
                try machine.close()
            } catch { try? machine.close(); throw error }
            guard try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath).canonicalBytes
                == configuration.canonicalBytes else { throw RuntimePreparationError.changedScope }
        }, inspect: { job in
            try RuntimeJobStopSession.classify(BoundedNativeCommand.run(executable: "/bin/launchctl",
                arguments: ["print", "system/" + job.declaration.label]), job: job)
        }, observe: { job, code, pid in try RuntimeJobProcessObservation.open(job: job, code: code, processID: pid) })
    }
    /// Same order with record-only rows and ordinary-owner callbacks. Root cannot select them.
    static func openOwned(stop: RuntimeMaintenanceAuthorityStop, executing: Record, operation: Record.OperationOutcome,
        admission: UpdateOrdinaryAdmissionLease, persist: @escaping @Sendable (Record, Record) throws -> Record,
        requireWindow: (Record) throws -> Void, inspect: @escaping () throws -> RuntimeJobStopSession.Observation,
        bootstrap: () throws -> Void, observe: @escaping (pid_t) throws -> any RuntimeJobExitWitness,
        floors: @escaping (Record) throws -> Void) throws -> RuntimeMaintenanceRestoration {
        try RuntimeMaintenanceOwnedControl.require()
        return try open(stop: stop, executing: executing, operation: operation, commit: .owned(persist), issue: { restoring, settled, _ in
            try stop.issueOwnedRestorationPermit(restoring: restoring, replacing: settled, admission: admission)
        }, register: { permit in
            try RuntimeJobRegistration.reconcileOwnedRestoration(permit, requireWindow: requireWindow, inspect: {
                switch try inspect() {
                case .absent: return .absent
                case .matching: return .matching
                case .conflicting: return .conflicting
                }
            }, bootstrap: bootstrap)
        }, floors: { window, _ in try floors(window) }, inspect: { _ in try inspect() }, observe: { _, _, pid in try observe(pid) })
    }
    private static func open(stop: RuntimeMaintenanceAuthorityStop, executing: Record, operation: Record.OperationOutcome,
        commit: Commit, issue: (Record, Record, Transition?) throws -> RuntimeMaintenanceRestorationPermit,
        register: (RuntimeMaintenanceRestorationPermit) throws -> Void, floors: @escaping Floors, inspect: @escaping Inspect,
        observe: @escaping Observe) throws -> RuntimeMaintenanceRestoration {
        guard let captured = stop.restorationWindow, captured.purpose == .retainedRuntime,
              executing.purpose == .retainedRuntime, let binding = captured.shutdownBinding, executing.phase == .executing,
              executing.id == captured.id, executing.purpose == captured.purpose, executing.scope == captured.scope,
              executing.shutdownBinding == binding, operation != .notStarted else { throw RuntimePreparationError.changedScope }
        func row(_ phase: Record.Phase, _ service: Record.ServiceOutcome, _ failure: Record.Failure? = nil) throws -> Record {
            try .init(id: executing.id, revision: AccountPreparationIntent.randomID(), purpose: executing.purpose, scope: executing.scope,
                phase: phase, operation: operation, service: service, failure: failure, shutdownBinding: binding)
        }
        // An unproved pair close or an unsettled body forbids workSettled. Record recovery once; never run the body again.
        guard try stop.beginRestoration() else {
            if let failed = try? row(.needsOwnerRecovery, .stopped, stop.bodyPairClose == .closed ? .changedScope : .cleanupPending) {
                _ = try? commit.write(failed, replacing: executing)
            }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        // A failed or uncertain commit sends nothing further.
        let settled: Record, restoring: Record, receipt: Transition?
        do {
            settled = try row(.workSettled, .stopped); _ = try commit.write(settled, replacing: executing)
            restoring = try row(.restoring, .restartPending); receipt = try commit.write(restoring, replacing: settled)
        } catch { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        var service = Record.ServiceOutcome.stopped, failure = Record.Failure.changedScope
        do {
            let permit = try issue(restoring, settled, receipt)
            service = .unknown; failure = .serviceUnavailable; try register(permit)
            service = .registered; failure = .changedScope
            // The owner keeps only the process-bound hold. No stop owner, boundary, machine scope or capture crosses this line.
            let held = try permit.transferHold()
            guard held.window == restoring else { throw RuntimePreparationError.changedScope }
            let owner = RuntimeMaintenanceRestoration(window: restoring, binding: binding, settled: settled, held: held,
                commit: commit, requireReceipt: {
                    if let receipt { try receipt.requireReplacement(restoring, replacing: settled) }
                    else { try restoring.requireReplacing(settled) }
                }, floors: floors, inspect: inspect, observe: observe)
            try owner.validateBeforePending(); return owner
        } catch {
            if let failed = try? row(.needsOwnerRecovery, service, failure) { _ = try? commit.write(failed, replacing: restoring) }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }

    /// Startup consumes fresh custody. No stop owner or old process witness is reconstructed.
    static func openStartup(_ prepared: RuntimeMaintenanceStartupRecovery.PreparedRestoration) throws -> RuntimeMaintenanceRestoration {
        let custody = try prepared.consume(), restoring = prepared.window
        guard let binding = restoring.shutdownBinding else { throw RuntimePreparationError.changedScope }
        try custody.requireRestoring(restoring)
        let held = try RuntimeMaintenanceRestorationHold.startup(custody, window: restoring)
        let commit: Commit
        if custody.native {
            commit = .native { next, previous in try custody.persistNative(next, previous: previous) }
        } else {
            try RuntimeMaintenanceOwnedControl.require()
            commit = .owned { next, previous in try custody.persistOwned(next, previous: previous) }
        }
        let owner = RuntimeMaintenanceRestoration(window: restoring, binding: binding, settled: prepared.previous,
            held: held, commit: commit, requireReceipt: { try prepared.requireReceipt() },
            floors: { window, _ in try custody.requireRestoring(window) },
            inspect: { try custody.inspect($0) }, observe: { try custody.observe($0, $1, $2) })
        try owner.validateBeforePending(); return owner
    }

    /// Repeatable. Drain, machine activity, receipt, old exit and floors; plus the accepted witness when present. Writes nothing.
    func validateBeforePending() throws {
        try lock.withLock {
            guard getpid() == processID else { throw JournalLeaseError.invalidated }
            try held.validate(); try requireReceipt()
            try floors(window, held.cohort)
            try held.validate()
            if witness != nil { try requireWitnessLiveLocked() }
        }
    }
    func openRequest(challenge: Data) throws -> AuthorityMaintenanceChannelRequest {
        try .init(action: .open, accountID: window.scope.authority.accountID, attemptID: window.id, revision: window.revision,
            installationID: window.scope.installationID, gate: held.cohort.accountIdentity, binding: nil, challenge: challenge)
    }
    /// The healthy open must bind this exact restoring row on a different Authority incarnation.
    func requireHealthyBinding(_ binding: AuthorityMaintenanceBinding) throws {
        guard binding.accountID == window.scope.authority.accountID, binding.attemptID == window.id,
              binding.revision == window.revision, binding.incarnation != stoppedBinding.incarnation else {
            throw RuntimePreparationError.changedScope
        }
    }
    /// A rejected witness can be retried before pending. One accepted witness fixes the new process for this restoration.
    func acceptWitness(_ peer: any RuntimeJobExitWitness) throws {
        try lock.withLock {
            guard getpid() == processID, !witnessUsed, !pendingIssued, !recoveryUsed else { throw JournalLeaseError.invalidated }
            try held.validate()
            let pid = peer.processID
            try held.requireNewProcess(pid)
            guard pid > 1, try !peer.hasExited(),
                  try inspect(job) == .matching(pid) else { throw RuntimePreparationError.changedScope }
            let own = try observe(job, code, pid)
            guard own.processID == pid, try !own.hasExited(), try !peer.hasExited(),
                  try inspect(job) == .matching(pid) else { throw RuntimePreparationError.changedScope }
            try held.validate(); witness = (peer, own); witnessUsed = true
        }
    }
    /// Discards only an uncommitted startup candidate. The stop-origin owner cannot select this path.
    func discardStartupCandidate() throws {
        try lock.withLock {
            guard getpid() == processID, !pendingIssued, !recoveryUsed, !drainReleased else { throw JournalLeaseError.invalidated }
            try held.requireStartupOrigin(); witness = nil; witnessUsed = false
        }
    }
    /// Cheap: no store or launchctl call.
    func requireWitnessLive() throws { try lock.withLock { try requireWitnessLiveLocked() } }
    private func requireWitnessLiveLocked() throws {
        guard getpid() == processID, let witness else { throw RuntimeActivationError.unavailable }
        try held.requireOldExit()
        guard try !witness.peer.hasExited(), try !witness.own.hasExited() else {
            throw RuntimeActivationError.unavailable
        }
    }
    /// One exact healthy pending row for the client's real writer. Afterwards the client owns the write and its failure rule.
    func pendingRecord(binding: AuthorityMaintenanceBinding) throws -> Record {
        try lock.withLock {
            guard getpid() == processID, !pendingIssued, !recoveryUsed, witness != nil else { throw JournalLeaseError.invalidated }
            try validateBeforePending(); try requireHealthyBinding(binding); try requireWitnessLiveLocked()
            let next = try Record(id: window.id, revision: AccountPreparationIntent.randomID(), purpose: window.purpose,
                scope: window.scope, phase: .reopenPending, operation: window.operation, service: .healthy, shutdownBinding: stoppedBinding)
            try next.requireReplacing(window); pendingIssued = true; pending = next; return next
        }
    }
    /// Once. The only drain close: after the real writer's receipt for exactly the issued pending row over the restoring row.
    func releaseDrain(after receipt: Transition) throws {
        try lock.withLock {
            guard getpid() == processID, case .native = commit, let pending, !drainReleased else { throw JournalLeaseError.invalidated }
            try receipt.requireReplacement(pending, replacing: window)
            try held.releaseDrain(); drainReleased = true
        }
    }
    /// Record-only release for ordinary-owner tests. Root cannot select it.
    func releaseOwnedDrain(after record: Record) throws {
        try RuntimeMaintenanceOwnedControl.require()
        try lock.withLock {
            guard getpid() == processID, case .owned = commit, let pending, !drainReleased, record == pending else {
                throw JournalLeaseError.invalidated
            }
            try held.releaseDrain(); drainReleased = true
        }
    }
    /// Once, from the restoring row, before any pending row was issued. A failed commit is uncertain and is not repeated.
    func commitOwnerRecovery(_ failure: Record.Failure) throws {
        try lock.withLock {
            guard getpid() == processID, !pendingIssued, !recoveryUsed else { throw JournalLeaseError.invalidated }
            recoveryUsed = true
            do {
                let next = try Record(id: window.id, revision: AccountPreparationIntent.randomID(), purpose: window.purpose,
                    scope: window.scope, phase: .needsOwnerRecovery, operation: window.operation, service: .registered,
                    failure: failure, shutdownBinding: stoppedBinding)
                _ = try commit.write(next, replacing: window)
            } catch { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        }
    }

    /// Reads the machine frame with the real release: frame, exact window row, frame. No floor write; B's completion is not required.
    static func requireFloors(machine: PreparationIntentStore, release: SignedReleaseEvidence, window: Record,
        expected: MachineUpdateStableReleaseSnapshot, machineIdentity: PreparationFileIdentity, accountID: Data,
        accountIdentity: PreparationFileIdentity) throws {
        let before = try machine.stableMachineUpdateSnapshot(candidate: release)
        try machine.requireRuntimeMaintenanceObservationWindow(window, candidate: release)
        let after = try machine.stableMachineUpdateSnapshot(candidate: release)
        try after.requireSame(as: before)
        guard after.inventory == expected.inventory, after.admission == expected.admission,
              after.inventory.releaseDigest == window.scope.releaseDigest, after.inventory.macID == window.scope.macID,
              after.inventory.installationID == window.scope.installationID, window.scope.authority.accountID == accountID,
              after.admission.machine == machineIdentity,
              after.admission.accounts.first(where: { $0.accountID == accountID })?.identity == accountIdentity else {
            throw RuntimePreparationError.changedScope
        }
    }
}
