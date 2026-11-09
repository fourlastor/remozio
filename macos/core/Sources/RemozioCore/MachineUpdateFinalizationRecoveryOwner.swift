import Darwin
import Foundation

/// Owns restored admission through finishing checks. It grants no native identity, startup or admission release authority.
final class MachineUpdateFinalizationRecoveryOwner: @unchecked Sendable {
    enum Stage { case beforeQuiescence, withQuiescence, writerClosed, admissionTransferred }
    private let lock = NSRecursiveLock()
    private let processID = getpid()
    private let thread = pthread_self()
    let snapshot: MachineUpdateFinalizationSnapshot
    private let candidate: SignedReleaseEvidence
    private var drain: UpdateAdmissionDrain?
    private var quiet: UpdateQuiescenceLease?
    private var admission: UpdateRestartAdmissionLease?
    private var ready = false, retired = false, closed = false, operationActive = false

    /// The caller transfers the restored drain. Validation failures keep it owned until explicit close.
    init(snapshot: MachineUpdateFinalizationSnapshot, candidate: SignedReleaseEvidence, drain: UpdateAdmissionDrain) {
        self.snapshot = snapshot; self.candidate = candidate; self.drain = drain
    }

    /// Returns false while existing activity remains. It applies no timeout or cancellation to that work.
    func resumeInLease(machine: PreparationIntentStore, directory: ReleaseDestinationLease,
        verifyStage: (Stage) throws -> Void) throws -> Bool {
        try withOperation {
            guard !ready, snapshot.schemaVersion == 23, snapshot.activation.phase == .finishing else {
                throw PreparationStoreError.invalidTransition
            }
            try snapshot.installed.validate(candidate: candidate)
            func verify() throws {
                try self.requireBoundary(directory)
                try machine.installedRuntimeSource(candidate: self.candidate, directory: directory).actual.requireSame(as: self.snapshot)
                try self.requireBoundary(directory)
            }
            if let drain {
                try drain.withClosedAdmission {
                    try verify(); try verifyStage(.beforeQuiescence); try verify()
                    guard !self.closed else { throw JournalLeaseError.invalidated }
                }
                guard let acquired = try drain.acquireQuiescence() else { return false }
                quiet = acquired; self.drain = nil
            }
            guard let quiet else { throw JournalLeaseError.invalidated }
            try quiet.withExclusiveActivity { _ in
                try verify(); try verifyStage(.withQuiescence); try verify()
                guard !self.closed else { throw JournalLeaseError.invalidated }
                try machine.close()
            }
            try verifyStage(.writerClosed)
            guard !closed else { throw JournalLeaseError.invalidated }
            let transferred = try quiet.releaseActivityForRestart()
            admission = transferred; self.quiet = nil
            try requireBoundary(directory)
            try verifyStage(.admissionTransferred)
            try requireBoundary(directory)
            guard !closed else { throw JournalLeaseError.invalidated }
            ready = true; return true
        }
    }

    func withSnapshotInLease<Value>(machine: PreparationIntentStore, directory: ReleaseDestinationLease,
        _ body: (PreparationIntentStore.CompletionFinalizationScope) throws -> Value) throws -> Value {
        try withOperation {
            guard ready, let admission else { throw PreparationStoreError.invalidTransition }
            return try machine.withCurrentMachineUpdateFinalization(candidate: candidate, directory: directory, restart: admission) { scope in
                try self.validateAdmission(directory: directory)
                guard case .installed(let current) = try scope.read() else { throw PreparationStoreError.staleRevision }
                try current.requireSame(as: self.snapshot)
                let source = try scope.readRetainedSource()
                let result = try body(scope)
                try scope.readRetainedSource().requireSame(as: source)
                try self.validateAdmission(directory: directory); return result
            }
        }
    }

    func captureNativeFinalization(configurationPath: String, machine: PreparationIntentStore,
        directory: ReleaseDestinationLease) throws -> MachineUpdateNativeFinalizationObservation {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try withSnapshotInLease(machine: machine, directory: directory) { scope in
            try MachineUpdateNativeFinalization.capture(configurationPath: configurationPath, scope: scope)
        }
    }

    /// Captures protected finishing facts before transferring live peer verification to the asynchronous owner.
    func makeNativeSettlementOwner(configurationPath: String, machine: PreparationIntentStore,
        directory: ReleaseDestinationLease) throws -> MachineUpdateInstalledSettlementOwner {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let parent = getppid()
        func requireParent() throws {
            guard parent > 1, getppid() == parent else { throw JournalLeaseError.unsafeMetadata }
        }
        try requireParent()
        let selected = try withSnapshotInLease(machine: machine, directory: directory) { scope in
            try requireParent()
            let observed = try MachineUpdateNativeFinalization.capture(configurationPath: configurationPath, scope: scope)
            guard observed.readiness != nil else { throw PreparationStoreError.invalidTransition }
            let plan = try MachineUpdateInstalledReadinessPlan(scope: scope, candidate: observed.candidate)
            try requireParent()
            return (plan, observed.candidate)
        }
        try requireParent()
        try machine.close()
        return try withOperation {
            guard ready, let admission, directory.path == MachineBootstrap.machineDirectory else {
                throw PreparationStoreError.invalidTransition
            }
            try requireBoundary(directory)
            let nativeDirectory = try ReleaseDestinationLease.acquire(path: MachineBootstrap.machineDirectory)
            let activity = try ReleaseActivityBarrier.open(machineDirectory: MachineBootstrap.machineDirectory)
            let access = try MachineUpdateRestartSharedActivity(restart: admission, activity: activity, directory: nativeDirectory,
                expectedMachine: snapshot.admission.machine, macID: snapshot.inventory.macID,
                installationID: snapshot.inventory.installationID, activationAttempt: snapshot.activation.attemptID)
            try requireParent()
            return try MachineUpdateInstalledSettlementOwner.open(configurationPath: configurationPath, plan: selected.0,
                candidate: selected.1, directory: nativeDirectory, access: access, recovery: self, parent: parent)
        }
    }

    /// A retired owner can still prove that its admission lease remains held.
    func validateAdmission(directory: ReleaseDestinationLease) throws {
        try requireThread()
        try lock.withLock { try requireBoundary(directory) }
    }

    private func requireBoundary(_ directory: ReleaseDestinationLease) throws {
        guard !closed else { throw JournalLeaseError.invalidated }
        if let drain { try drain.validateMachineBoundary(directory: directory, expected: snapshot.admission.machine) }
        else if let quiet { try quiet.validateMachineBoundary(directory: directory, expected: snapshot.admission.machine) }
        else if let admission { try admission.validateMachineBoundary(directory: directory, expected: snapshot.admission.machine) }
        else { throw JournalLeaseError.invalidated }
    }

    private func requireThread() throws {
        guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else { throw JournalLeaseError.invalidated }
    }

    private func withOperation<Value>(_ body: () throws -> Value) throws -> Value {
        try requireThread()
        return try lock.withLock {
            guard !closed, !retired else { throw JournalLeaseError.invalidated }
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            operationActive = true
            defer { operationActive = false; if closed { release() } }
            do {
                let result = try body()
                guard !closed else { throw JournalLeaseError.invalidated }
                return result
            } catch { retired = true; throw error }
        }
    }

    /// The owner holds its lock through each operation, including the lent callback.
    /// A close from another thread waits for that operation before releasing admission.
    func close() {
        guard getpid() == processID else { return }
        lock.withLock { closed = true; if !operationActive { release() } }
    }
    private func release() {
        drain?.close(); drain = nil; quiet?.close(); quiet = nil; admission?.close(); admission = nil
    }
    deinit { close() }
}
