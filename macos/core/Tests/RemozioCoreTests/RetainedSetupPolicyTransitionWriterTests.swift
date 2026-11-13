import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned stores test metadata acknowledgements. No journal permit or native policy writer is constructed.
final class RetainedSetupPolicyTransitionWriterTests: XCTestCase {
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Receipt = PreparationIntentStore.RetainedSetupPolicyWriteReceipt
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case callback, commit }
    private final class SharedUse: @unchecked Sendable {
        let use: Receipt.Use
        init(_ use: Receipt.Use) { self.use = use }
    }
    private func fixture(noPolicyChange: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(noPolicyChange: noPolicyChange, body)
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func prepare(_ f: Fixture) throws -> Record {
        let prepared = try Record(source: f.source)
        return try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: snapshot(f), candidate: f.candidate,
            directory: f.directory, admission: f.admission, verifyScoped: { _, _ in try f.verifyPair() })
    }
    private func begin(_ f: Fixture, _ writing: Record, expected: Snapshot? = nil,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> Receipt {
        try f.machine().beginRetainedSetupPolicyWrite(writing, source: f.source, expected: expected ?? snapshot(f),
            candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { stage, actual in
                try f.verifyPair(); try verify(stage, actual); try f.verifyPair()
            })
    }
    private func record(_ f: Fixture, _ recorded: Record, expected: Snapshot? = nil) throws -> Receipt {
        try f.machine().recordRetainedSetupPolicyWrite(recorded, boundary: f.source.accountPolicy,
            expected: expected ?? snapshot(f), candidate: f.candidate, directory: f.directory,
            admission: f.admission, verifyScoped: { _, _ in try f.verifyPair() })
    }
    private func changed(_ value: Record, _ edit: (inout [String: Any]) -> Void) throws -> Record {
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: value.encoded) as? [String: Any]); edit(&fields)
        return try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
    }

    func testExactWritingUpdateAcknowledgesActualFramesAndOneClosedConnectionUse() throws {
        try fixture { f in
            let prepared = try prepare(f), before = try snapshot(f), writing = try prepared.preparingWrite(expected: f.source)
            var stages: [Stage] = []
            let receipt = try begin(f, writing, expected: before) { stage, actual in
                stages.append(stage)
                if actual.intent == prepared { try actual.requireSame(as: before) }
                else { try actual.requireTransition(writing, from: before) }
                XCTAssertThrowsError(try self.begin(f, writing, expected: actual)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
            }
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertTrue(receipt.changed); XCTAssertEqual(receipt.previous, prepared); XCTAssertEqual(receipt.current, writing)
            try receipt.snapshot.requireSame(as: snapshot(f))
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 25)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM retained_setup_policy_intents_v1"), 1)
            XCTAssertThrowsError(try receipt.withFirstWritingUse { try $0.validate() }) {
                XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
            }
            try f.machine().close(); try f.machine().requireClosedForRetainedSetupPolicyWrite()
            var escaped: Receipt.Use?
            try receipt.withFirstWritingUse { use in
                escaped = use; XCTAssertEqual(use.intent, writing); try use.validate(); try use.claimJournalWrite()
                XCTAssertThrowsError(try use.claimJournalWrite()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                XCTAssertThrowsError(try receipt.withFirstWritingUse { _ in })
            }
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try receipt.withFirstWritingUse { _ in }); try f.verifyPair()
        }
    }

    func testRepeatedWritingMarkerReturnsNoNewWriteAuthority() throws {
        try fixture { f in
            let prepared = try prepare(f), writing = try prepared.preparingWrite(expected: f.source)
            var commits = 0; try f.reopen { commits += 1 }
            let first = try begin(f, writing), before = try snapshot(f); var stages: [Stage] = []
            let repeated = try begin(f, writing) { stage, _ in stages.append(stage) }
            XCTAssertEqual(commits, 1); XCTAssertEqual(stages, [.beforeTransaction])
            XCTAssertTrue(first.changed); XCTAssertFalse(repeated.changed)
            XCTAssertEqual(repeated.previous, writing); XCTAssertEqual(repeated.current, writing)
            try snapshot(f).requireSame(as: before); try f.machine().close()
            XCTAssertThrowsError(try repeated.withFirstWritingUse { _ in }) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            try f.verifyPair()
        }
    }

    func testStaleRevisionAndDifferentIdentityCannotReplaceTheCurrentRow() throws {
        try fixture { f in
            let prepared = try prepare(f), before = try snapshot(f), writing = try prepared.preparingWrite(expected: f.source)
            for wrong in [try changed(writing, { $0["id"] = UUID().uuidString }),
                          try changed(writing, { $0["revision"] = prepared.revision.uuidString })] {
                var called = false
                XCTAssertThrowsError(try begin(f, wrong, expected: before, verify: { _, _ in called = true }))
                XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
            }
            _ = try begin(f, writing, expected: before)
            let after = try snapshot(f), competing = try prepared.preparingWrite(expected: f.source)
            XCTAssertThrowsError(try begin(f, competing, expected: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try snapshot(f).requireSame(as: after); try f.verifyPair()
        }
    }

    func testActualNoOpBoundaryCanBeRecordedWithoutAnotherFirstWriteUse() throws {
        try fixture(noPolicyChange: true) { f in
            let prepared = try prepare(f), writing = try prepared.preparingWrite(expected: f.source)
            XCTAssertEqual(f.source.policy.startupPolicy, f.source.policy.source.policy)
            _ = try begin(f, writing); let before = try snapshot(f)
            guard case .recorded(let recorded) = try writing.reconciling(f.source.accountPolicy) else {
                return XCTFail("The unchanged actual no-op pair must produce a recorded proposal")
            }
            let receipt = try record(f, recorded)
            XCTAssertTrue(receipt.changed); XCTAssertEqual(receipt.previous, writing); XCTAssertEqual(receipt.current, recorded)
            try receipt.snapshot.requireTransition(recorded, from: before)
            try recorded.requireRecorded(f.source.accountPolicy)
            let repeated = try record(f, recorded); XCTAssertFalse(repeated.changed)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM retained_setup_policy_intents_v1"), 1)
            try f.machine().close()
            for value in [receipt, repeated] { XCTAssertThrowsError(try value.withFirstWritingUse { _ in }) }
            try f.verifyPair()
        }
    }

    func testCallbackFailuresBeforeCommitLeaveThePreparedRevisionUnchanged() throws {
        try fixture { f in
            let prepared = try prepare(f), before = try snapshot(f)
            for stopped: Stage in [.beforeTransaction, .inTransaction, .afterMutation] {
                let writing = try prepared.preparingWrite(expected: f.source)
                XCTAssertThrowsError(try begin(f, writing, verify: { stage, _ in
                    if stage == stopped { throw Fault.callback }
                })) { XCTAssertTrue($0 is Fault, "\($0)") }
                try snapshot(f).requireSame(as: before); XCTAssertEqual(try snapshot(f).intent, prepared)
            }
            try f.verifyPair()
        }
    }

    func testLostCommitAcknowledgementKeepsWritingWithoutGrantingARetry() throws {
        try fixture { f in
            let prepared = try prepare(f), writing = try prepared.preparingWrite(expected: f.source)
            var commits = 0; try f.reopen { commits += 1; throw Fault.commit }
            XCTAssertThrowsError(try begin(f, writing)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil); XCTAssertEqual(try snapshot(f).intent, writing)
            let recovered = try begin(f, writing); XCTAssertFalse(recovered.changed)
            try f.machine().close(); XCTAssertThrowsError(try recovered.withFirstWritingUse { _ in }); try f.verifyPair()
        }
    }

    func testAfterCommitCallbackFailureClosesTheWriterWithoutReturningAReceipt() throws {
        try fixture { f in
            let prepared = try prepare(f), writing = try prepared.preparingWrite(expected: f.source)
            var commits = 0; try f.reopen { commits += 1 }
            XCTAssertThrowsError(try begin(f, writing, verify: { stage, _ in
                if stage == .afterCommit { throw Fault.callback }
            })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil); XCTAssertEqual(try snapshot(f).intent, writing)
            XCTAssertFalse(try begin(f, writing).changed); try f.verifyPair()
        }
    }

    func testThrowingUseConsumesTheReceiptAndExpiresTheLoan() throws {
        try fixture { f in
            let prepared = try prepare(f), receipt = try begin(f, prepared.preparingWrite(expected: f.source))
            try f.machine().close(); var escaped: Receipt.Use?
            XCTAssertThrowsError(try receipt.withFirstWritingUse { use in
                escaped = use; try use.claimJournalWrite(); throw Fault.callback
            }) { XCTAssertTrue($0 is Fault) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).validate())
            XCTAssertThrowsError(try receipt.withFirstWritingUse { _ in }); try f.verifyPair()
        }
    }

    func testUseRefusesAnotherThreadWhileItsSynchronousLoanIsActive() throws {
        try fixture { f in
            let prepared = try prepare(f), receipt = try begin(f, prepared.preparingWrite(expected: f.source))
            try f.machine().close()
            try receipt.withFirstWritingUse { use in
                let shared = SharedUse(use), refused = Mutex(false), done = DispatchSemaphore(value: 0)
                Thread.detachNewThread {
                    do { try shared.use.validate() }
                    catch { refused.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                    done.signal()
                }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
                XCTAssertTrue(refused.withLock { $0 }); try use.validate(); try use.claimJournalWrite()
            }
            try f.verifyPair()
        }
    }
}
