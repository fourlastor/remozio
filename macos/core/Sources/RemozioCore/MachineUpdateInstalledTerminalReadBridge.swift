import Foundation

/// Keeps peer verification on the writer's exact frame through terminal commit and acknowledgment.
final class MachineUpdateInstalledTerminalReadBridge: @unchecked Sendable {
    typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    typealias Scope = PreparationIntentStore.StableCompletionScope
    typealias Commit = PreparationIntentStore.StableCompletionCommit
    private let lock = NSRecursiveLock()
    private let expected: MachineUpdateInstalledReadinessPlan
    private let candidate: SignedReleaseEvidence
    private let readFinishing: @Sendable () throws -> MachineUpdateInstalledReadinessPlan
    private let readStable: @Sendable () throws -> MachineUpdateStableReleaseSnapshot
    private let onActivityContention: @Sendable () -> Void
    private var scope: Scope?
    private var observedStable: MachineUpdateStableReleaseSnapshot?
    private var acknowledged: Commit?
    private var settling = false
    private var retired = false

    init(plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence,
        readFinishing: @escaping @Sendable () throws -> MachineUpdateInstalledReadinessPlan,
        readStable: @escaping @Sendable () throws -> MachineUpdateStableReleaseSnapshot,
        onActivityContention: @escaping @Sendable () -> Void = {}) throws {
        guard plan.focusedAccountID == nil else { throw PreparationStoreError.invalidTransition }
        guard try InstallationInventory.digest(candidate) == plan.view.installedInventory.releaseDigest else {
            throw PreparationStoreError.staleRevision
        }
        expected = plan
        self.candidate = candidate
        self.readFinishing = readFinishing
        self.readStable = readStable
        self.onActivityContention = onActivityContention
    }

    func requirePlan(_ plan: MachineUpdateInstalledReadinessPlan, candidate: SignedReleaseEvidence) throws {
        guard try InstallationInventory.digest(candidate) == InstallationInventory.digest(self.candidate) else {
            throw PreparationStoreError.staleRevision
        }
        try plan.requireSame(as: expected)
    }

    /// A new peer loan must wait until the current finishing read releases its admission operation.
    func acquirePeerActivity(_ acquire: () throws -> any OwnedReleaseActivity) throws -> any OwnedReleaseActivity {
        if !lock.try() {
            onActivityContention()
            lock.lock()
        }
        defer { lock.unlock() }
        guard !retired, !settling else { throw JournalLeaseError.invalidated }
        return try acquire()
    }

    func requireCurrent() throws {
        try lock.withLock {
            guard !retired else { throw JournalLeaseError.invalidated }
            do {
                if let scope {
                    switch try scope.read() {
                    case .finishing(let plan):
                        guard observedStable == nil else { throw PreparationStoreError.invalidTransition }
                        try plan.requireSame(as: expected)
                    case .stable(let current):
                        try current.requireInitialTransition(from: expected, release: candidate)
                        if let observedStable { try current.requireSame(as: observedStable) }
                    }
                } else if let acknowledged {
                    let current = try readStable()
                    try current.requireSame(as: acknowledged.read())
                    try current.requireInitialTransition(from: expected, release: candidate)
                } else {
                    guard !settling else { throw PreparationStoreError.invalidTransition }
                    try readFinishing().requireSame(as: expected)
                }
            } catch {
                retired = true
                throw error
            }
        }
    }

    /// The writer closes before returning its receipt. Peer checks may read only the lent frame inside the write.
    func settle(verifyLive: () throws -> Void,
        write: ((Stage, Scope) throws -> Void) throws -> Commit) throws -> Commit {
        try lock.withLock {
            guard !retired, !settling, acknowledged == nil else { throw PreparationStoreError.invalidTransition }
            try requireCurrent()
            settling = true
            defer { settling = false }
            do {
                let receipt = try withoutActuallyEscaping(verifyLive) { verify in
                    try write { stage, current in
                        guard !self.retired, self.scope == nil else { throw JournalLeaseError.invalidated }
                        self.scope = current
                        defer { self.scope = nil }
                        try self.requireCurrent()
                        try verify()
                        try self.requireCurrent()
                        if stage == .afterCommit {
                            guard case .stable(let actual) = try current.read() else { throw PreparationStoreError.invalidTransition }
                            self.observedStable = actual
                        }
                    }
                }
                guard !retired, let observedStable else { throw PreparationStoreError.invalidTransition }
                try receipt.requireSource(expected, candidate: candidate)
                try receipt.read().requireSame(as: observedStable)
                acknowledged = receipt
                try requireCurrent()
                return receipt
            } catch {
                retired = true
                throw error
            }
        }
    }

    func close() {
        lock.withLock { retired = true; scope = nil; observedStable = nil; acknowledged = nil }
    }
}
