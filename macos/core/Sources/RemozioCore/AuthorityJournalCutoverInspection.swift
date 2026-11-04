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
    private let storage: AuthorityStorage
    private let expectedPolicy: AuthorityCodePolicy?
    private let verifyCurrent: () throws -> Void
    private let ownerPID = getpid()
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
        let paths = try RuntimePreparationPaths(accountID: initialization.accountID)
        guard initialization.complete, initialization.checkpoint != nil,
              initialization.journalPath == paths.authorityDirectory + "/Journal/journal.sqlite",
              initialization.continuityPath == paths.authorityDirectory + "/Continuity/continuity.sqlite" else {
            throw AuthorityInitializationError.invalidBoundary
        }
        func verify() throws { try rootActivity.validateExclusive(); try verifyOwnerAndFence() }
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
    init(storage: AuthorityStorage, expectedPolicy: AuthorityCodePolicy?, verifyCurrent: @escaping () throws -> Void) throws {
        self.storage = storage; self.expectedPolicy = expectedPolicy; self.verifyCurrent = verifyCurrent
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
                return Snapshot(checkpoint: before, schemaVersion: try transaction.storageSchemaVersion, totalOutcomes: total,
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
                guard try transaction.storageSchemaVersion == snapshot.schemaVersion else { throw JournalDatabaseError.incompatibleStore }
            }
            guard try storage.continuity.read().committed == snapshot.checkpoint else { throw CheckpointedJournal.Failure.boundaryMismatch }
            try verifyCurrent()
        } catch { invalidated = true; throw error }
    }
    private static func requirePolicy(_ transaction: JournalTransaction, expected: AuthorityCodePolicy?) throws {
        let actual = try transaction.codePolicy()?.policy.bytes
        guard try actual == expected?.bytes else { throw RuntimeActivationError.changedScope }
    }
    func close() throws {
        guard !active else { throw JournalDatabaseError.transactionActive }
        guard !closed else { return }
        closed = true; try storage.close()
    }
    deinit { try? storage.close() }
}
