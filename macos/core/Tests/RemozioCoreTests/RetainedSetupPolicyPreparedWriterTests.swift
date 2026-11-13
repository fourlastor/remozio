import Foundation
import XCTest
@testable import RemozioCore

struct RetainedPolicyWriterFixture {
    enum JournalMode { case startup, completion, readOnly, foreignStartup }
    let machine: () -> PreparationIntentStore
    let source: MachineUpdateRetainedSetupActivationSource
    let material: RuntimePreparationMaterial
    let candidate: SignedReleaseEvidence
    let directory: ReleaseDestinationLease
    let admission: UpdateOrdinaryAdmissionLease
    let verifyPair: () throws -> Void
    let reopen: ((() throws -> Void)?) throws -> Void
    let scalar: (String) throws -> Int64
    let openPolicyJournal: (JournalMode) throws -> AuthorityJournal
    let currentAuthorityAccountID: Data
    let openJournalLease: @Sendable (Data) throws -> sending ProtectedJournalLease
    let openContinuityLease: @Sendable (Data, ProtectedStorageLease.DirectoryIdentity) throws -> sending ProtectedContinuityLease
}

/// Owned stores exercise SQL only. Synthetic release declarations grant no installed caller or native policy authority.
final class RetainedSetupPolicyPreparedWriterTests: XCTestCase {
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case callback, commit }
    private func fixture(writerFormats: Bool = true, migration: Bool = true, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(writerFormats: writerFormats, migration: migration, body)
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func retain(_ f: Fixture, record: Record? = nil, expected: Snapshot? = nil,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> Record {
        try f.machine().retainRetainedSetupPolicyIntent(record ?? Record(source: f.source), expected: expected ?? snapshot(f),
            candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { stage, actual in
                try f.verifyPair(); try verify(stage, actual); try f.verifyPair()
            })
    }

    func testPreparedRetentionMigratesExactly24To25AndLendsActualTransactionFrames() throws {
        try fixture { f in
            let before = try snapshot(f), prepared = try Record(source: f.source)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 24)
            var stages: [Stage] = []
            let result = try retain(f, record: prepared) { stage, actual in
                stages.append(stage)
                if actual.intent == nil { try actual.requireSame(as: before) }
                else { try actual.requireRetention(prepared, from: before) }
                XCTAssertThrowsError(try self.snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(result, prepared)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 25)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name='retained_setup_policy_intents_v1'"), 1)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM retained_setup_policy_intents_v1"), 1)
            let after = try snapshot(f)
            try after.requireRetention(prepared, from: before)
            XCTAssertFalse(after.activation.runtime.state.configurationPublished)
            try f.verifyPair()
        }
    }

    func testExactRepeatedPreparedRecordDoesNotWriteAgain() throws {
        try fixture { f in
            let prepared = try Record(source: f.source); var commits = 0
            try f.reopen { commits += 1 }
            _ = try retain(f, record: prepared)
            let before = try snapshot(f); var stages: [Stage] = []
            XCTAssertEqual(try retain(f, record: prepared, verify: { stage, _ in stages.append(stage) }), prepared)
            XCTAssertEqual(commits, 1); XCTAssertEqual(stages, [.beforeTransaction])
            try snapshot(f).requireSame(as: before); try f.verifyPair()
        }
    }

    func testDifferentPreparedIdentityAndStaleMigrationFrameCannotReplaceTheRow() throws {
        try fixture { f in
            let original = try Record(source: f.source), stale = try snapshot(f)
            _ = try retain(f, record: original)
            let after = try snapshot(f), different = try Record(source: f.source)
            XCTAssertThrowsError(try retain(f, record: different)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            XCTAssertThrowsError(try retain(f, record: original, expected: stale)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try snapshot(f).requireSame(as: after); try f.verifyPair()
        }
    }

    func testMissingWriterAndMigrationDeclarationsRefuseBeforeAdmissionAndCallbacks() throws {
        for missingWriter in [true, false] {
            try fixture(writerFormats: !missingWriter, migration: false) { f in
                let before = try snapshot(f), prepared = try Record(source: f.source); var called = false
                f.admission.close()
                XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: before,
                    candidate: f.candidate, directory: f.directory, admission: f.admission,
                    verifyScoped: { _, _ in called = true })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
                XCTAssertFalse(called); XCTAssertEqual(try f.scalar("PRAGMA user_version"), 24)
                try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testOnlyPreparedOperandsCanEnterTheInsertWriter() throws {
        try fixture { f in
            let before = try snapshot(f), prepared = try Record(source: f.source)
            let writing = try prepared.preparingWrite(expected: f.source)
            XCTAssertThrowsError(try retain(f, record: writing)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try snapshot(f).requireSame(as: before)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 24)
        }
    }

    func testCallbackFailuresBeforeCommitRollBackTheTableRowAndSchemaVersion() throws {
        for stopped: Stage in [.beforeTransaction, .inTransaction, .afterMutation] {
            try fixture { f in
                let before = try snapshot(f)
                XCTAssertThrowsError(try retain(f, verify: { stage, _ in if stage == stopped { throw Fault.callback } })) {
                    XCTAssertTrue($0 is Fault, "\($0)")
                }
                XCTAssertEqual(try f.scalar("PRAGMA user_version"), 24)
                XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name='retained_setup_policy_intents_v1'"), 0)
                try snapshot(f).requireSame(as: before); try f.verifyPair()
            }
        }
    }

    func testLostCommitAcknowledgementClosesTheWriterAndKeepsTheDurablePreparedRow() throws {
        try fixture { f in
            let prepared = try Record(source: f.source); var commits = 0
            try f.reopen { commits += 1; throw Fault.commit }
            XCTAssertThrowsError(try retain(f, record: prepared)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 25)
            XCTAssertEqual(try snapshot(f).intent, prepared); try f.verifyPair()
        }
    }

    func testAfterCommitCallbackFailureCannotTriggerARetryOrJournalWrite() throws {
        try fixture { f in
            let prepared = try Record(source: f.source); var commits = 0
            try f.reopen { commits += 1 }
            XCTAssertThrowsError(try retain(f, record: prepared, verify: { stage, _ in
                if stage == .afterCommit { throw Fault.callback }
            })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil)
            XCTAssertEqual(try snapshot(f).intent, prepared); try f.verifyPair()
        }
    }

    func testActualLoanExcludesNestedPolicyMaterialAndPromotionWriters() throws {
        try fixture { f in
            let prepared = try Record(source: f.source)
            _ = try retain(f, record: prepared, verify: { _, actual in
                XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: actual,
                    candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().requireRetainedSetupPromotionWriterAvailable()) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                let frame = try MachineUpdateRetainedSetupMaterialSnapshot(runtime: actual.activation.runtime,
                    activation: actual.activation.state)
                let reference = try XCTUnwrap(frame.runtime.state.reference)
                XCTAssertThrowsError(try f.machine().retainRetainedSetupRuntimeMaterial(reference, expected: frame,
                    candidate: f.candidate, directory: f.directory, admission: f.admission,
                    fileCustodyAccepted: true, verifyScoped: { _, _ in })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
            })
            try f.verifyPair()
        }
    }
}
