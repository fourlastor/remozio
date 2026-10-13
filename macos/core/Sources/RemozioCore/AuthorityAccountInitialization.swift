import Darwin
import Foundation
import RemozioProtocol

/// Root setup composition. The host must verify administrator consent, signed code and protected account scope first.
/// Serialize this operation with the machine store. Its result grants no service or command admission.
public enum AuthorityAccountInitialization {
    public static func resume(machine: PreparationIntentStore, expected: AuthorityInitializationIntent) throws -> AuthorityInitializationIntent {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
        let journalDirectory = (expected.journalPath as NSString).deletingLastPathComponent
        let continuityDirectory = (expected.continuityPath as NSString).deletingLastPathComponent
        return try resume(machine: machine, expected: expected,
            prepareJournal: { _ = try SetupDatabaseFileProvisioning.prepare(directoryPath: journalDirectory, kind: .journal) },
            openDirectories: {
                let journal = try ProtectedSetupDirectory(anchor: "/", relativePath: String(journalDirectory.dropFirst()), owner: 0,
                    createIfMissing: false)
                do { return try Directories(journal: journal, continuity: ProtectedSetupDirectory.createOrOpen(path: continuityDirectory)) }
                catch { journal.close(); throw error }
            },
            openJournal: { initialize, initial, directories in
                let lease = try ProtectedJournalLease.acquire(directoryPath: journalDirectory)
                do {
                    try directories.validate(journal: lease)
                    return try JournalDatabase(lease: lease, macID: expected.macID, accountID: expected.accountID,
                        recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                        maximumConsumptions: 1_000_000, busyMilliseconds: 5000, initialize: initialize,
                        initialAuthority: initialize ? initial : nil)
                } catch { lease.close(); throw error }
            },
            prepareContinuity: { _ = try SetupDatabaseFileProvisioning.prepare(directoryPath: continuityDirectory, kind: .continuity) },
            openContinuity: { checkpoint, directories in
                let lease = try ProtectedContinuityLease.acquire(directoryPath: continuityDirectory)
                do {
                    try directories.validate(continuity: lease)
                    return try ContinuityStore(lease: lease, macID: expected.macID, accountID: expected.accountID, initialize: checkpoint)
                } catch { lease.close(); throw error }
            })
    }

    enum Stage: CaseIterable { case journalProvisioned, directoriesOpened, journalOpened, checkpointCaptured, continuityProvisioned, continuityOpened, completed }
    /// Same-owner controls use actual protected leases, provisioners and SQLite stores.
    /// Product callers cannot replace these factories or inject fault hooks.
    static func resume(machine: PreparationIntentStore, expected: AuthorityInitializationIntent,
                       prepareJournal: () throws -> Void,
                       openDirectories: () throws -> Directories,
                       openJournal: (Bool, AuthorityJournalInitialization, Directories) throws -> JournalDatabase,
                       prepareContinuity: () throws -> Void,
                       openContinuity: (ContinuityCheckpoint?, Directories) throws -> ContinuityStore,
                       didStage: (Stage) throws -> Void = { _ in }) throws -> AuthorityInitializationIntent {
        try machine.validateInitialization(expected)
        // Completion is retained setup progress, not current health. Never reinitialize a completed account.
        if expected.complete { return expected }
        let initial = try expected.initialAuthority
        var progress = expected
        var journal: JournalDatabase?
        var continuity: ContinuityStore?
        var directories: Directories?
        do {
            if progress.checkpoint == nil {
                try machine.validateInitialization(progress)
                try prepareJournal(); try didStage(.journalProvisioned)
            }
            try machine.validateInitialization(progress)
            let scope = try openDirectories(); directories = scope
            try didStage(.directoriesOpened)
            try scope.validate()
            try machine.validateInitialization(progress)
            do { journal = try openJournal(false, initial, scope) }
            catch JournalDatabaseError.incompatibleStore {
                // A captured checkpoint proves the journal committed. Its loss cannot authorize initialization.
                guard progress.checkpoint == nil else { throw AuthorityInitializationError.invalidBoundary }
                try machine.validateInitialization(progress)
                try scope.validate()
                journal = try openJournal(true, initial, scope)
            }
            let liveJournal = try required(journal)
            try didStage(.journalOpened)
            try scope.validate()
            progress = try machine.captureInitialization(expected: progress, initial: initial, journal: liveJournal)
            try didStage(.checkpointCaptured)
            let checkpoint = try required(progress.checkpoint)
            try machine.validateInitialization(progress)
            try scope.validate()
            try prepareContinuity(); try didStage(.continuityProvisioned)
            try machine.validateInitialization(progress)
            try scope.validate()
            do { continuity = try openContinuity(nil, scope) }
            catch ContinuityStoreError.incompatibleStore {
                try machine.validateInitialization(progress)
                try scope.validate()
                continuity = try openContinuity(checkpoint, scope)
            }
            let liveContinuity = try required(continuity)
            try didStage(.continuityOpened)
            try scope.validate()
            progress = try machine.completeInitialization(expected: progress, journal: liveJournal, continuity: liveContinuity)
            try didStage(.completed)
            liveContinuity.close(); continuity = nil
            try liveJournal.close(); journal = nil
            scope.close(); directories = nil
            return progress
        } catch {
            continuity?.close(); try? journal?.close(); directories?.close()
            throw error
        }
    }
    /// Retain both directory walks until account stores close. String spelling does not prove independence.
    final class Directories {
        private let journal: ProtectedSetupDirectory
        private let continuity: ProtectedSetupDirectory
        init(journal: ProtectedSetupDirectory, continuity: ProtectedSetupDirectory) throws {
            self.journal = journal; self.continuity = continuity
            do { try validate() } catch { close(); throw error }
        }
        deinit { close() }
        func close() { journal.close(); continuity.close() }
        func validate() throws {
            let journalPath = try journal.directoryIdentities(), continuityPath = try continuity.directoryIdentities()
            guard let journalDirectory = journalPath.last, let continuityDirectory = continuityPath.last,
                  !journalPath.contains(continuityDirectory), !continuityPath.contains(journalDirectory) else {
                throw AuthorityInitializationError.invalidIntent
            }
        }
        func validate(journal lease: ProtectedJournalLease) throws {
            try validate()
            guard try lease.directoryIdentities().last == journal.directoryIdentities().last else {
                throw JournalLeaseError.identityChanged
            }
        }
        func validate(continuity lease: ProtectedContinuityLease) throws {
            try validate()
            guard try lease.directoryIdentities().last == continuity.directoryIdentities().last else {
                throw JournalLeaseError.identityChanged
            }
        }
    }
    private static func required<T>(_ value: T?) throws -> T {
        guard let value else { throw AuthorityInitializationError.invalidBoundary }; return value
    }
}
