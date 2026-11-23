import Darwin
import Foundation
import RemozioProtocol

/// Owns both existing writer leases through a read-only storage inspection. This grants no dispatch or cutover permission.
final class AuthorityJournalCutoverInspection: CustomStringConvertible, CustomReflectable {
    struct Snapshot: Equatable, Sendable {
        let checkpoint: ContinuityCheckpoint
        let schemaVersion: UInt64
        let totalOutcomes: Int
        let interruptedAuthorizations: Int
        let interruptedDispatches: Int
        let terminalUnknowns: Int
        var requiresStartupOutcomeRecovery: Bool { interruptedAuthorizations > 0 || interruptedDispatches > 0 }
    }
    let snapshot: Snapshot
    /// Set to closed only after storage.close returns. A failed or interrupted close never reads as closed.
    enum CloseOutcome: Equatable, Sendable { case open, closed, failed }
    private let storage: AuthorityStorage
    private let expectedPolicy: AuthorityCodePolicy?
    private let verifyCurrent: () throws -> Void
    private let closeStorage: (AuthorityStorage) throws -> Void
    private(set) var closeOutcome = CloseOutcome.open
    private let ownerPID = getpid()
    private let maintenanceThread = pthread_self()
    private var active = false
    private var closed = false
    private var invalidated = false
    var description: String { "AuthorityJournalCutoverInspection(redacted)" }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// Completed account initialization only. Empty and partial setup require their separate initialization owner.
    static func openInitialized(initialization: AuthorityInitializationIntent, policy: AuthorityCodePolicy,
                                rootActivity: ReleaseActivityToken,
                                verifyOwnerAndFence: @escaping () throws -> Void) throws -> AuthorityJournalCutoverInspection {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        func verify() throws { try rootActivity.validateExclusive(); try verifyOwnerAndFence() }
        return try openExisting(initialization: initialization, policy: policy, verify: verify)
    }
    /// Maintenance retains machine SH and the exact account EX. This factory grants read-only pair custody only.
    static func openForMaintenance(initialization: AuthorityInitializationIntent, policy: AuthorityCodePolicy,
        scope: UpdateOrdinaryAdmissionLease.Scope, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        machineIdentity: PreparationFileIdentity, accountIdentity: PreparationFileIdentity,
        verifyOwner: @escaping () throws -> Void) throws -> AuthorityJournalCutoverInspection {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try openExisting(initialization: initialization, policy: policy,
            verify: maintenanceVerification(accountID: initialization.accountID, scope: scope, drain: drain,
                directory: directory, machineIdentity: machineIdentity, accountIdentity: accountIdentity, verifyOwner: verifyOwner))
    }
    static func openOwnedForMaintenance(accountID: Data, policy: AuthorityCodePolicy, scope: UpdateOrdinaryAdmissionLease.Scope,
        drain: UpdateDrainToken, directory: ReleaseDestinationLease, machineIdentity: PreparationFileIdentity,
        accountIdentity: PreparationFileIdentity, verifyOwner: @escaping () throws -> Void,
        openStorage: () throws -> AuthorityStorage) throws -> AuthorityJournalCutoverInspection {
        try RuntimeMaintenanceOwnedControl.require()
        let verify = maintenanceVerification(accountID: accountID, scope: scope, drain: drain, directory: directory,
            machineIdentity: machineIdentity, accountIdentity: accountIdentity, verifyOwner: verifyOwner)
        try verify(); return try .init(storage: openStorage(), expectedPolicy: policy, verifyCurrent: verify)
    }
    private static func maintenanceVerification(accountID: Data, scope: UpdateOrdinaryAdmissionLease.Scope,
        drain: UpdateDrainToken, directory: ReleaseDestinationLease, machineIdentity: PreparationFileIdentity,
        accountIdentity: PreparationFileIdentity, verifyOwner: @escaping () throws -> Void) -> () throws -> Void {
        {
            try scope.validateMachineBoundary(directory: directory, expected: machineIdentity)
            try drain.validateAccountBoundary(directory: directory, accountID: accountID, expected: accountIdentity)
            try verifyOwner()
            try scope.validateMachineBoundary(directory: directory, expected: machineIdentity)
            try drain.validateAccountBoundary(directory: directory, accountID: accountID, expected: accountIdentity)
        }
    }
    private static func openExisting(initialization: AuthorityInitializationIntent, policy: AuthorityCodePolicy,
        verify: @escaping () throws -> Void) throws -> AuthorityJournalCutoverInspection {
        let paths = try RuntimePreparationPaths(accountID: initialization.accountID)
        guard initialization.complete, initialization.checkpoint != nil,
              initialization.journalPath == paths.authorityDirectory + "/Journal/journal.sqlite",
              initialization.continuityPath == paths.authorityDirectory + "/Continuity/continuity.sqlite" else {
            throw AuthorityInitializationError.invalidBoundary
        }
        try verify()
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
        let storage = try AuthorityStorage(openJournal: {
            try verify()
            return try JournalDatabase(lease: ProtectedJournalLease.acquire(directoryPath: (initialization.journalPath as NSString).deletingLastPathComponent),
                macID: initialization.macID, accountID: initialization.accountID, recordLimits: limits, descriptorLimits: limits,
                decisionLimits: limits, maximumConsumptions: 1_000_000, busyMilliseconds: 5000, initialize: false, readOnlyForCutover: true)
        }, openContinuity: { journalDirectory in
            try verify()
            return try ContinuityStore(lease: ProtectedContinuityLease.acquire(directoryPath: (initialization.continuityPath as NSString).deletingLastPathComponent,
                excludingDirectory: journalDirectory), macID: initialization.macID, accountID: initialization.accountID,
                initialize: nil, readOnlyForCutover: true)
        })
        return try .init(storage: storage, expectedPolicy: policy, verifyCurrent: verify)
    }
    // Existing ordinary-owner stores can exercise the same read-only path. No injected callback grants Root admission.
    convenience init(storage: AuthorityStorage, expectedPolicy: AuthorityCodePolicy?, verifyCurrent: @escaping () throws -> Void) throws {
        try self.init(storage: storage, expectedPolicy: expectedPolicy, verifyCurrent: verifyCurrent, closeStorage: { try $0.close() })
    }
    /// Ordinary-owner close fault seam. Root cannot replace the storage close.
    static func openOwned(storage: AuthorityStorage, expectedPolicy: AuthorityCodePolicy?, verifyCurrent: @escaping () throws -> Void,
        closeStorage: @escaping (AuthorityStorage) throws -> Void) throws -> AuthorityJournalCutoverInspection {
        try RuntimeMaintenanceOwnedControl.require()
        return try .init(storage: storage, expectedPolicy: expectedPolicy, verifyCurrent: verifyCurrent, closeStorage: closeStorage)
    }
    private init(storage: AuthorityStorage, expectedPolicy: AuthorityCodePolicy?, verifyCurrent: @escaping () throws -> Void,
        closeStorage: @escaping (AuthorityStorage) throws -> Void) throws {
        self.storage = storage; self.expectedPolicy = expectedPolicy; self.verifyCurrent = verifyCurrent; self.closeStorage = closeStorage
        do {
            guard storage.journal.readOnlyForCutover, storage.continuity.readOnlyForCutover else { throw JournalDatabaseError.readOnly }
            try verifyCurrent()
            let before = try storage.continuity.read().committed
            snapshot = try CheckpointedJournal(journal: storage.journal, continuity: storage.continuity).read { transaction in
                try Self.requirePolicy(transaction, expected: expectedPolicy)
                var total = 0, authorized = 0, executing = 0, unknown = 0, cursor: Data?
                repeat {
                    try verifyCurrent()
                    let page = try transaction.consumptionOutcomes(afterRequestID: cursor, maximumRecords: 256, maximumBytes: 67_108_864)
                    for outcome in page.outcomes {
                        guard total < 1_000_000 else { throw JournalDatabaseError.unavailable }; total += 1
                        switch outcome.phase {
                        case .authorized: authorized += 1
                        case .executing: executing += 1
                        case .unknown: unknown += 1
                        case .declined, .cancelled, .succeeded, .failed: break
                        default: throw JournalDatabaseError.incompatibleStore
                        }
                    }
                    if let next = page.nextRequestID {
                        guard !page.outcomes.isEmpty, cursor.map({ $0.lexicographicallyPrecedes(next) }) ?? true else {
                            throw JournalDatabaseError.incompatibleStore
                        }
                    }
                    cursor = page.nextRequestID
                } while cursor != nil
                return Snapshot(checkpoint: before, schemaVersion: try transaction.storageFormatVersion, totalOutcomes: total,
                    interruptedAuthorizations: authorized, interruptedDispatches: executing, terminalUnknowns: unknown)
            }
            guard try storage.continuity.read().committed == before else { throw CheckpointedJournal.Failure.boundaryMismatch }
            try verifyCurrent()
        } catch { try? storage.close(); throw error }
    }
    /// Lease checks only. Safe between cutover file reads without decoding either SQLite store again.
    func validateLifetime() throws {
        guard !closed, !invalidated, !active, getpid() == ownerPID else { throw JournalDatabaseError.unavailable }
        do {
            try verifyCurrent()
            _ = try storage.journal.directoryIdentities(); _ = try storage.continuity.directoryIdentities()
            try verifyCurrent()
        } catch { invalidated = true; throw error }
    }
    func validate() throws {
        guard !closed, !invalidated, !active, getpid() == ownerPID else { throw JournalDatabaseError.unavailable }
        active = true; defer { active = false }
        do {
            try verifyCurrent()
            try CheckpointedJournal(journal: storage.journal, continuity: storage.continuity).read { transaction in
                try Self.requirePolicy(transaction, expected: expectedPolicy)
                guard try transaction.storageFormatVersion == snapshot.schemaVersion else { throw JournalDatabaseError.incompatibleStore }
            }
            guard try storage.continuity.read().committed == snapshot.checkpoint else { throw CheckpointedJournal.Failure.boundaryMismatch }
            try verifyCurrent()
        } catch { invalidated = true; throw error }
    }
    /// Reads the same held pair. It opens no second journal or continuity lease.
    func maintenancePolicyBoundary(initialization: AuthorityInitializationIntent) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        guard !closed, !invalidated, !active, getpid() == ownerPID,
              pthread_equal(maintenanceThread, pthread_self()) != 0 else { throw JournalDatabaseError.unavailable }
        active = true; defer { active = false }
        do {
            try verifyCurrent()
            guard initialization.complete else { throw AuthorityInitializationError.invalidBoundary }
            try storage.journal.requireInitializationPath(initialization.journalPath)
            try storage.continuity.requireInitializationScope(path: initialization.continuityPath,
                mac: initialization.macID, account: initialization.accountID)
            let before = try storage.continuity.read()
            guard !before.recoveryRequired, before.pending == nil, before.committed == snapshot.checkpoint else {
                throw CheckpointedJournal.Failure.boundaryMismatch
            }
            let value = try CheckpointedJournal(journal: storage.journal, continuity: storage.continuity).read { transaction in
                try Self.requirePolicy(transaction, expected: expectedPolicy)
                guard let policy = try transaction.codePolicy(), let epoch = try transaction.epoch(before.committed.journalEpoch),
                      epoch.descriptor.macID == initialization.macID, epoch.descriptor.accountID == initialization.accountID else {
                    throw AuthorityInitializationError.invalidBoundary
                }
                return AuthorityJournal.MachineUpdatePolicyBoundary(macID: epoch.descriptor.macID,
                    accountID: epoch.descriptor.accountID, policy: policy, checkpoint: before.committed)
            }
            guard try storage.continuity.read() == before else { throw CheckpointedJournal.Failure.boundaryMismatch }
            try verifyCurrent(); return value
        } catch { invalidated = true; throw error }
    }
    private static func requirePolicy(_ transaction: JournalTransaction, expected: AuthorityCodePolicy?) throws {
        let actual = try transaction.codePolicy()?.policy.bytes
        guard try actual == expected?.bytes else { throw RuntimeActivationError.changedScope }
    }
    func close() throws {
        guard !active else { throw JournalDatabaseError.transactionActive }
        guard !closed else { guard closeOutcome == .closed else { throw JournalDatabaseError.unavailable }; return }
        closed = true; closeOutcome = .failed
        try closeStorage(storage); closeOutcome = .closed
    }
    deinit { try? storage.close() }
}
