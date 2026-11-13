import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned journals exercise an internal hook. No production caller or native policy custody is supplied.
final class RetainedSetupPolicyJournalTests: XCTestCase {
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Receipt = PreparationIntentStore.RetainedSetupPolicyWriteReceipt
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private typealias Stage = AuthorityJournal.MachineUpdatePolicyCommitStage
    private enum Fault: Error { case callback }
    private final class SharedVerification: @unchecked Sendable {
        let use: Receipt.Use
        let candidate: SignedReleaseEvidence
        init(use: Receipt.Use, candidate: SignedReleaseEvidence) { self.use = use; self.candidate = candidate }
    }
    private func fixture(noPolicyChange: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(noPolicyChange: noPolicyChange, body)
    }
    private func snapshot(_ f: Fixture) throws -> MachineUpdateRetainedSetupPolicySnapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func writing(_ f: Fixture) throws -> Receipt {
        let prepared = try Record(source: f.source)
        _ = try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: snapshot(f), candidate: f.candidate,
            directory: f.directory, admission: f.admission, verifyScoped: { _, _ in try f.verifyPair() })
        return try f.machine().beginRetainedSetupPolicyWrite(prepared.preparingWrite(expected: f.source), source: f.source,
            expected: snapshot(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
            verifyScoped: { _, _ in try f.verifyPair() })
    }
    private func read(_ f: Fixture) throws -> Boundary {
        let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(f.source.runtime.setup.account?.initialization))
    }
    private func commit(_ f: Fixture, journal: AuthorityJournal, use: Receipt.Use,
        verify: (Stage) throws -> Void = { _ in }) throws -> AuthorityJournal.MachineUpdatePolicyCommitReceipt {
        try journal.commitRetainedSetupStartupPolicy(source: f.source, use: use, candidate: f.candidate, verifyExternal: verify)
    }
    private func changeMarkerToRecordedNoOp(_ f: Fixture, writing: Record) throws {
        guard case .recorded(let recorded) = try writing.reconciling(f.source.accountPolicy) else {
            return XCTFail("The actual no-op boundary must produce a recorded proposal")
        }
        _ = try f.machine().recordRetainedSetupPolicyWrite(recorded, boundary: f.source.accountPolicy, expected: snapshot(f),
            candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
    }

    func testActualStartupCommitReturnsTheExactPairedReceiptAndBlocksReentry() throws {
        try fixture { f in
            let acknowledged = try writing(f); try f.machine().close()
            var stages: [Stage] = []
            let result = try acknowledged.withFirstWritingUse { use in
                let journal = try f.openPolicyJournal(.startup); defer { try? journal.close() }
                return try commit(f, journal: journal, use: use) { stage in
                    stages.append(stage)
                    XCTAssertThrowsError(try journal.captureMachineUpdatePolicyBoundaryForRecoveryRead()) {
                        XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
                    }
                }
            }
            XCTAssertEqual(stages, [.beforeCommit, .inTransaction, .afterMutation, .afterCommit])
            let actual = try read(f)
            XCTAssertEqual(result.source, f.source.accountPolicy); XCTAssertEqual(result.policy, actual.policy)
            XCTAssertEqual(result.checkpoint, actual.checkpoint)
            XCTAssertEqual(actual.policy.policy, f.source.policy.startupPolicy)
            XCTAssertEqual(actual.checkpoint.generation, f.source.accountPolicy.checkpoint.generation + 1)
            XCTAssertEqual(actual.checkpoint.currentAuthorityGeneration, f.source.accountPolicy.checkpoint.currentAuthorityGeneration + 1)
            let recorded = try acknowledged.current.recording(result); try recorded.requireRecorded(actual)
        }
    }

    func testActualNoOpLeavesThePairUnchangedAndCannotClaimAnotherCommit() throws {
        try fixture(noPolicyChange: true) { f in
            let acknowledged = try writing(f); try f.machine().close(); var stages: [Stage] = []
            try acknowledged.withFirstWritingUse { use in
                let journal = try f.openPolicyJournal(.startup); defer { try? journal.close() }
                let result = try commit(f, journal: journal, use: use) { stages.append($0) }
                XCTAssertEqual(result.policy, f.source.accountPolicy.policy)
                XCTAssertEqual(result.checkpoint, f.source.accountPolicy.checkpoint)
                XCTAssertThrowsError(try commit(f, journal: journal, use: use)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
            }
            XCTAssertEqual(stages, [.beforeCommit, .afterCommit]); XCTAssertEqual(try read(f), f.source.accountPolicy)
        }
    }

    func testSecondStoreCannotSubstituteTheDiskMarkerBehindAClosedOriginalConnection() throws {
        try fixture(noPolicyChange: true) { f in
            let acknowledged = try writing(f), originalMachine = f.machine()
            try originalMachine.close(); try f.reopen(nil)
            try changeMarkerToRecordedNoOp(f, writing: acknowledged.current)
            try withExtendedLifetime(originalMachine) {
                try acknowledged.withFirstWritingUse { use in
                    let journal = try f.openPolicyJournal(.startup); defer { try? journal.close() }
                    XCTAssertThrowsError(try commit(f, journal: journal, use: use)) {
                        XCTAssertEqual($0 as? JournalLeaseError, .busy)
                    }
                    try f.machine().close()
                    XCTAssertThrowsError(try commit(f, journal: journal, use: use)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                    }
                }
            }
            XCTAssertEqual(try read(f), f.source.accountPolicy)
        }
    }

    func testCompletionReadOnlyAndForeignJournalModesCannotUseTheStartupHook() throws {
        try fixture { f in
            let acknowledged = try writing(f); try f.machine().close()
            try acknowledged.withFirstWritingUse { use in
                for mode: RetainedPolicyWriterFixture.JournalMode in [.completion, .readOnly, .foreignStartup] {
                    let journal = try f.openPolicyJournal(mode); defer { try? journal.close() }
                    XCTAssertThrowsError(try commit(f, journal: journal, use: use))
                }
            }
            XCTAssertEqual(try read(f), f.source.accountPolicy)
        }
    }

    func testFailuresBeforeCommitKeepTheActualPolicyAndCheckpointUnchanged() throws {
        for stopped: Stage in [.beforeCommit, .inTransaction, .afterMutation] {
            try fixture { f in
                let acknowledged = try writing(f); try f.machine().close()
                XCTAssertThrowsError(try acknowledged.withFirstWritingUse { use in
                    let journal = try f.openPolicyJournal(.startup); defer { try? journal.close() }
                    return try commit(f, journal: journal, use: use) { if $0 == stopped { throw Fault.callback } }
                }) { XCTAssertTrue($0 is Fault, "\($0)") }
                XCTAssertThrowsError(try acknowledged.withFirstWritingUse { _ in })
                XCTAssertEqual(try read(f), f.source.accountPolicy)
            }
        }
    }

    func testLostPostCommitAcknowledgementRecoversOnlyFromTheActualFreshPair() throws {
        try fixture { f in
            let acknowledged = try writing(f); try f.machine().close()
            XCTAssertThrowsError(try acknowledged.withFirstWritingUse { use in
                let journal = try f.openPolicyJournal(.startup); defer { try? journal.close() }
                return try commit(f, journal: journal, use: use) { if $0 == .afterCommit { throw Fault.callback } }
            }) { XCTAssertTrue($0 is Fault) }
            let actual = try read(f)
            XCTAssertEqual(actual.policy.policy, f.source.policy.startupPolicy)
            guard case .recorded(let recovered) = try acknowledged.current.reconciling(actual) else {
                return XCTFail("The actual paired successor must produce a recorded proposal")
            }
            try recovered.requireRecorded(actual)
            XCTAssertThrowsError(try acknowledged.withFirstWritingUse { _ in })
        }
    }

    func testMarkerChangedDuringTheVerifierIsRereadBeforeAnyJournalWrite() throws {
        try fixture(noPolicyChange: true) { f in
            let acknowledged = try writing(f), originalMachine = f.machine()
            try originalMachine.close()
            try withExtendedLifetime(originalMachine) {
                XCTAssertThrowsError(try acknowledged.withFirstWritingUse { use in
                    let journal = try f.openPolicyJournal(.startup); defer { try? journal.close() }
                    return try commit(f, journal: journal, use: use) { stage in
                        if stage == .beforeCommit {
                            try f.reopen(nil); try self.changeMarkerToRecordedNoOp(f, writing: acknowledged.current)
                            try f.machine().close()
                        }
                    }
                }) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            }
            XCTAssertEqual(try read(f), f.source.accountPolicy)
        }
    }

    func testEscapedDiskVerifierRefusesBeforeOpeningAnotherMachineConnection() throws {
        try fixture { f in
            let acknowledged = try writing(f), originalMachine = f.machine()
            try originalMachine.close(); var escaped: Receipt.Use?
            try acknowledged.withFirstWritingUse { escaped = $0; try $0.verifyCurrentMarker(candidate: f.candidate) }
            try f.reopen(nil)
            try withExtendedLifetime(originalMachine) {
                XCTAssertThrowsError(try XCTUnwrap(escaped).verifyCurrentMarker(candidate: f.candidate)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
            }
            try f.machine().close(); XCTAssertEqual(try read(f), f.source.accountPolicy)
        }
    }

    func testDiskVerificationRefusesAnotherThreadBeforeReadingReceiptOrStorage() throws {
        try fixture { f in
            let acknowledged = try writing(f); try f.machine().close()
            try acknowledged.withFirstWritingUse { use in
                let shared = SharedVerification(use: use, candidate: f.candidate)
                let refused = Mutex(false), done = DispatchSemaphore(value: 0)
                Thread.detachNewThread {
                    do { try shared.use.verifyCurrentMarker(candidate: shared.candidate) }
                    catch { refused.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                    done.signal()
                }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success); XCTAssertTrue(refused.withLock { $0 })
                try use.verifyCurrentMarker(candidate: f.candidate)
            }
            XCTAssertEqual(try read(f), f.source.accountPolicy)
        }
    }
}
