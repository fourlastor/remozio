import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned pairs exercise the native composition helpers. No installed Root process or real native commit is proved.
final class RetainedSetupPolicyNativeEntryTests: XCTestCase {
    private typealias Entry = MachineUpdateRetainedSetupPolicyNativeEntry
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private enum Fault: Error { case stopped }
    private func fixture(_ body: (Fixture) throws -> Void) throws { try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(body) }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func initial(_ f: Fixture, _ account: Data) throws -> AuthorityInitializationIntent {
        try XCTUnwrap(f.source.runtime.setup.source.accounts.first(where: { $0.accountID == account })?.initialization)
    }
    private func open(_ f: Fixture, account: Data, access: Entry.Access,
        verify: (JournalTransaction) throws -> Void = { _ in }) throws -> AuthorityJournal {
        let first = try initial(f, account), journal = f.openJournalLease, continuity = f.openContinuityLease
        return try Entry.openJournal(access: access, initial: first,
            openJournalLease: { try journal(account) }, openContinuityLease: { try continuity(account, $0) }, verifySelf: verify)
    }
    private func read(_ f: Fixture, account: Data) throws -> Entry.Boundary {
        let journal = try open(f, account: account, access: .readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: initial(f, account))
    }
    private func commitCurrent(_ f: Fixture) throws {
        let account = f.currentAuthorityAccountID, first = try initial(f, account)
        let journal = f.openJournalLease, continuity = f.openContinuityLease
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
        let storage = try AuthorityStorage(openJournal: {
            try JournalDatabase(lease: journal(account), macID: first.macID, accountID: account,
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 1_000_000, busyMilliseconds: 5000, initialize: false)
        }, openContinuity: { excluded in
            try ContinuityStore(lease: continuity(account, excluded), macID: first.macID, accountID: account, initialize: nil)
        })
        defer { try? storage.close() }
        let policy = try storage.journal.read { try XCTUnwrap($0.codePolicy()) }, state = try storage.continuity.read()
        _ = try CheckpointedJournal(journal: storage.journal, continuity: storage.continuity).write(epoch: state.committed.journalEpoch) {
            try $0.installCodePolicy(policy.policy, expectedRevision: policy.revision)
        }
    }

    func testOrdinaryIdentityRefusesBeforeNativePathsOrPolicyReads() throws {
        try fixture { f in
            XCTAssertNotEqual(getuid(), 0)
            XCTAssertThrowsError(try Entry.resumeNative(machineDirectory: "/does-not-exist", expected: snapshot(f),
                candidate: f.candidate, currentAuthorityAccountID: f.currentAuthorityAccountID)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertNoThrow(try f.machine().inventory())
        }
    }

    func testSelectorAcceptsOnlyThePublishedAuthorityHostAndItsActualInitialization() throws {
        try fixture { f in
            let (selected, host) = try Entry.publishedAuthority(expected: snapshot(f), accountID: f.currentAuthorityAccountID)
            XCTAssertEqual(selected, try initial(f, f.currentAuthorityAccountID))
            XCTAssertEqual(host.command.accountID, f.currentAuthorityAccountID)
            XCTAssertNotEqual(selected.accountID, f.source.runtime.preparation.accountID)
            XCTAssertEqual(try read(f, account: selected.accountID).accountID, selected.accountID)
        }
    }

    func testSelectorRejectsAnIDThatHasNoPublishedAuthorityConfiguration() throws {
        try fixture { f in
            var foreign = Data(repeating: 221, count: 16)
            while f.source.runtime.setup.source.accounts.contains(where: { $0.accountID == foreign }) { foreign[0] &+= 1 }
            XCTAssertThrowsError(try Entry.publishedAuthority(expected: snapshot(f), accountID: foreign)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testSelectorRejectsTheHistoricalRetainedTargetAsTheCurrentAuthority() throws {
        try fixture { f in
            XCTAssertThrowsError(try Entry.publishedAuthority(expected: snapshot(f), accountID: f.source.runtime.preparation.accountID)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }

    func testSecondFreshReadRejectsARealNewPolicyRevisionAndCheckpoint() throws {
        try fixture { f in
            let account = f.currentAuthorityAccountID, before = try read(f, account: account), first = try initial(f, account)
            var reads = 0
            XCTAssertThrowsError(try Entry.withCurrentPolicy(initial: first, read: {
                reads += 1
                if reads == 2 { try self.commitCurrent(f) }
                return try self.read(f, account: account)
            }) { _, _ in XCTFail("A changed policy reached native custody") }) {
                XCTAssertEqual($0 as? AuthorityCodePolicyError, .staleRevision)
            }
            let after = try read(f, account: account)
            XCTAssertNotEqual(after.policy.revision, before.policy.revision)
            XCTAssertEqual(after.checkpoint.generation, before.checkpoint.generation + 1)
            XCTAssertEqual(reads, 2)
        }
    }

    func testCurrentPolicyVerifierExpiresWhenTheScopeReturnsOrThrows() throws {
        try fixture { f in
            let account = f.currentAuthorityAccountID, first = try initial(f, account)
            var escaped: Entry.Verify?
            try Entry.withCurrentPolicy(initial: first, read: { try self.read(f, account: account) }) { policy, current in
                escaped = current; XCTAssertEqual(policy, try self.read(f, account: account).policy.policy); try current()
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try Entry.withCurrentPolicy(initial: first, read: { try self.read(f, account: account) }) { _, current in
                escaped = current; throw Fault.stopped
            }) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try XCTUnwrap(escaped)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testCurrentPolicyScopeRejectsAnotherActualAccountPair() throws {
        try fixture { f in
            XCTAssertThrowsError(try Entry.withCurrentPolicy(initial: initial(f, f.source.runtime.preparation.accountID),
                read: { try self.read(f, account: f.currentAuthorityAccountID) }) { _, _ in XCTFail("A foreign pair entered the scope") }) {
                XCTAssertEqual($0 as? AuthorityInitializationError, .invalidBoundary)
            }
        }
    }

    func testTypedFactoriesKeepReadOnlyAndStartupSeparateAndCannotStartRequests() throws {
        try fixture { f in
            let account = f.source.runtime.preparation.accountID, before = try read(f, account: account)
            for access in [Entry.Access.readOnly, .startup] {
                let journal = try open(f, account: account, access: access)
                XCTAssertThrowsError(try journal.prepareRequests(clockEpoch: UUID(), maximumPayloadBytes: 1024)) {
                    XCTAssertEqual($0 as? JournalDatabaseError, .readOnly)
                }
                if access == .readOnly {
                    XCTAssertEqual(try journal.captureRetainedSetupPolicyBoundary(expected: initial(f, account)), before)
                } else {
                    XCTAssertThrowsError(try journal.captureRetainedSetupPolicyBoundary(expected: initial(f, account)))
                }
                try journal.close(); XCTAssertEqual(try read(f, account: account), before)
            }
        }
    }

    func testWrongJournalPathFailsBeforeOpeningContinuityAndReleasesItsLease() throws {
        try fixture { f in
            let target = f.source.runtime.preparation.accountID, other = f.currentAuthorityAccountID, journal = f.openJournalLease
            for access in [Entry.Access.readOnly, .startup] {
                XCTAssertThrowsError(try Entry.openJournal(access: access, initial: initial(f, target),
                    openJournalLease: { try journal(other) }, openContinuityLease: { _ in
                        XCTFail("A wrong journal reached continuity"); throw Fault.stopped
                    }, verifySelf: { _ in })) { XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary) }
                XCTAssertNoThrow(try self.read(f, account: other))
            }
        }
    }

    func testWrongContinuityPathClosesBothStoresBeforeTheNextOpen() throws {
        try fixture { f in
            let target = f.source.runtime.preparation.accountID, other = f.currentAuthorityAccountID
            let journal = f.openJournalLease, continuity = f.openContinuityLease
            for access in [Entry.Access.readOnly, .startup] {
                XCTAssertThrowsError(try Entry.openJournal(access: access, initial: initial(f, target),
                    openJournalLease: { try journal(target) }, openContinuityLease: { try continuity(other, $0) },
                    verifySelf: { _ in })) { XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary) }
                XCTAssertNoThrow(try self.read(f, account: target)); XCTAssertNoThrow(try self.read(f, account: other))
            }
        }
    }

    func testMachineProviderClosesTheExactConnectionOnReturnAndFailure() throws {
        try fixture { f in
            let machine = f.machine(); var validations = 0
            let provider = Entry.closedMachine(open: { machine }, validate: { actual in
                XCTAssertTrue(actual === machine); validations += 1
            })
            _ = try provider { actual in try actual.retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate) }
            XCTAssertEqual(validations, 2)
            XCTAssertThrowsError(try machine.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
            try f.reopen(nil); let failed = f.machine()
            XCTAssertThrowsError(try Entry.closedMachine(open: { failed }, validate: { _ in }) { _ in throw Fault.stopped }) {
                XCTAssertTrue($0 is Fault)
            }
            XCTAssertThrowsError(try failed.inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .closed) }
        }
    }

    func testOwnedCompositionUsesTheActualPinnedCurrentPairAndRecordsTheTargetOnce() throws {
        try fixture { f in
            let frame = try snapshot(f), target = f.source.runtime.preparation.accountID, account = f.currentAuthorityAccountID
            let before = try read(f, account: target), originalCurrent = try read(f, account: account)
            var startupOpens = 0
            let result = try Entry.withCurrentPolicy(initial: initial(f, account), read: { try self.read(f, account: account) }) { policy, current in
                let controls = MachineUpdateRetainedSetupPolicyNativeContext.Controls(validateCustody: {}, inspectRelease: { f.candidate },
                    validateExecutingCode: {}, lookupOwner: { _ in f.source.runtime.setup.owner }, validateServices: { _ in },
                    readMaterial: { _ in try f.material.encoded }, validateActivity: { _, _, verify in try verify() })
                return try MachineUpdateRetainedSetupPolicyNativeContext.withOwnedContext(expected: frame, candidate: f.candidate,
                    currentCodePolicy: policy, controls: controls) { context in
                    try MachineUpdateRetainedSetupPolicyOwner.resume(expected: frame, candidate: f.candidate,
                        directory: f.directory, admission: f.admission,
                        useMachine: Entry.closedMachine(open: { try f.reopen(nil); return f.machine() }, validate: { _ in }),
                        openJournal: { access in
                            if access == .startup { startupOpens += 1 }
                            return try self.open(f, account: target, access: access, verify: { _ in try current() })
                        }, verifySnapshot: { actual in try current(); try context.verify(actual); try current() })
                }
            }
            XCTAssertEqual(result.intent?.phase, .recorded); XCTAssertEqual(startupOpens, 1)
            let after = try read(f, account: target)
            try XCTUnwrap(result.intent).requireRecorded(after)
            XCTAssertEqual(after.checkpoint.generation, before.checkpoint.generation + 1)
            XCTAssertEqual(try read(f, account: account), originalCurrent)
        }
    }
}
