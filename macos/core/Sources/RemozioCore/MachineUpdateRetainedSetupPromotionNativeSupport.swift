import Darwin
import Foundation
import RemozioProtocol

/// Borrows existing read-only stores. Native placement, custody and admission require their separate owner.
enum MachineUpdateRetainedSetupPromotionNativeSupport {
    typealias Verify = () throws -> Void

    struct Paths: Equatable, Sendable {
        let journalDirectory: String
        let continuityDirectory: String

        init(accountID: Data, journalPath: String, continuityPath: String) throws {
            let authority = try AccountPreparationController.authorityDirectory(accountID: accountID)
            let journal = authority + "/Journal", continuity = authority + "/Continuity"
            guard journalPath == journal + "/journal.sqlite", continuityPath == continuity + "/continuity.sqlite" else {
                throw MachineUpdateActivationError.wrongBoundary
            }
            journalDirectory = journal; continuityDirectory = continuity
        }
    }

    private final class VerificationLoan {
        private let processID = getpid()
        private let thread = pthread_self()
        private let lock = NSRecursiveLock()
        private var body: Verify?
        private var executing = false

        init(_ body: @escaping Verify) { self.body = body }

        func verify() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0 else {
                throw JournalLeaseError.invalidated
            }
            try lock.withLock {
                guard !executing else { body = nil; throw JournalLeaseError.invalidated }
                guard let body else { throw JournalLeaseError.invalidated }
                executing = true; defer { executing = false }
                do {
                    try body()
                    guard self.body != nil else { throw JournalLeaseError.invalidated }
                } catch { self.body = nil; throw error }
            }
        }
        func expire() { lock.withLock { body = nil } }
    }

    /// Expires the borrowed body before a retained callback can escape this synchronous invocation.
    static func withScopedVerification<Value>(_ verifyCurrent: Verify,
        perform: (@escaping Verify) throws -> Value) throws -> Value {
        try withoutActuallyEscaping(verifyCurrent) { borrowed in
            let loan = VerificationLoan(borrowed)
            defer { loan.expire() }
            return try perform(loan.verify)
        }
    }

    /// Opens no mutable connection and never initializes, migrates or repairs either database.
    static func openExistingStorage(initial: AuthorityInitializationIntent,
        openJournalLease: @Sendable () throws -> sending ProtectedJournalLease,
        openContinuityLease: @Sendable (ProtectedStorageLease.DirectoryIdentity) throws -> sending ProtectedContinuityLease)
        throws -> sending AuthorityStorage {
        guard initial.complete else { throw RuntimeActivationError.incomplete }
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
        return try AuthorityStorage(openJournal: {
            let lease = try openJournalLease()
            do {
                guard lease.databasePath == initial.journalPath else { throw MachineUpdateActivationError.wrongBoundary }
                try CutoverSQLitePreflight.validate(path: lease.databasePath, validateLease: lease.validate)
                return try JournalDatabase(lease: lease, macID: initial.macID, accountID: initial.accountID,
                    recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                    maximumConsumptions: 1_000_000, busyMilliseconds: 5000, initialize: false, readOnlyForCutover: true)
            } catch { lease.close(); throw error }
        }, openContinuity: { journalDirectory in
            let lease = try openContinuityLease(journalDirectory)
            do {
                guard lease.databasePath == initial.continuityPath else { throw MachineUpdateActivationError.wrongBoundary }
                try CutoverSQLitePreflight.validate(path: lease.databasePath, validateLease: lease.validate)
                return try ContinuityStore(lease: lease, macID: initial.macID, accountID: initial.accountID,
                    initialize: nil, readOnlyForCutover: true)
            } catch { lease.close(); throw error }
        })
    }

    /// Pins the actual pair while the caller checks its policy phase. Every return closes both stores.
    /// The G4 verifier must check app and Setup code identities and policies outside storage transactions.
    static func withReadOnlyPair<Value>(initial: AuthorityInitializationIntent, verifyCurrent: Verify,
        openStorage: () throws -> sending AuthorityStorage,
        perform: (AuthorityJournal, @escaping Verify) throws -> Value) throws -> Value {
        guard initial.complete else { throw RuntimeActivationError.incomplete }
        return try withScopedVerification(verifyCurrent) { current in
            try current()
            let journal = try AuthorityJournal(updateHealthStorage: openStorage(), validateSelf: { _ in })
            do {
                try current()
                func boundary() throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
                    try current()
                    let pair = try journal.captureRetainedSetupPolicyBoundary(expected: initial)
                    try current(); return pair
                }
                let before = try boundary(), value = try perform(journal, current)
                guard try boundary() == before else { throw PreparationStoreError.staleRevision }
                try current(); try journal.close(); return value
            } catch { try? journal.close(); throw error }
        }
    }
}
