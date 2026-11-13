import Foundation
import XCTest
@testable import RemozioCore

/// Owned SQL tests prove metadata changes only. The caller still needs real file checks, paired reads and native custody.
final class RetainedSetupInitialPublicationWriterTests: XCTestCase {
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case callback, commit }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func pair(_ f: Fixture) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(f.source.runtime.setup.account?.initialization))
    }
    private func fixture(_ body: (Fixture, Snapshot) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let before = try snapshot(f)
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            try f.reopen(nil); defer { try? f.machine().close() }
            try XCTUnwrap(recorded.intent).requireRecorded(pair(f)); try body(f, recorded)
        }
    }
    private func complete(_ f: Fixture, expected: Snapshot? = nil, reference: RuntimeMaterialReference? = nil,
        policy: Record? = nil, custody: Bool = true, admission: UpdateOrdinaryAdmissionLease? = nil,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> Snapshot {
        let expected = try expected ?? snapshot(f), record = try policy ?? XCTUnwrap(expected.intent)
        return try f.machine().completeRetainedSetupRuntimePublication(reference ?? XCTUnwrap(expected.activation.runtime.state.reference),
            expected: expected.activation.runtime, policy: record, candidate: f.candidate,
            directory: f.directory, admission: admission ?? f.admission, fileCustodyAccepted: custody,
            verifyScoped: { stage, actual in
                try record.requireRecorded(pair(f)); try verify(stage, actual); try record.requireRecorded(pair(f))
            })
    }
    private func changed(_ value: Record, _ edit: (inout [String: Any]) -> Void) throws -> Record {
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: value.encoded) as? [String: Any]); edit(&fields)
        return try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
    }

    /// Seeds only owned import storage. The body receives a fresh snapshot after the seed, never a proposed native receipt.
    static func withRecordedInitialSelectionFixture(seed: (RetainedPolicyWriterFixture) throws -> Void = { _ in },
        body: (RetainedPolicyWriterFixture, MachineUpdateRetainedSetupPolicySnapshot,
            AuthorityJournal.MachineUpdatePolicyBoundary) throws -> Void) throws {
        let suite = RetainedSetupInitialPublicationWriterTests(selector: NSSelectorFromString(
            "testOneActualUpdateRereadsTheExactPublicationTransitionAndClosesPolicyWriters"))
        try suite.fixture { f, _ in
            try seed(f); let before = try suite.snapshot(f)
            try body(f, before, suite.pair(f)); try suite.snapshot(f).requireSame(as: before)
        }
    }

    func testOneActualUpdateRereadsTheExactPublicationTransitionAndClosesPolicyWriters() throws {
        try fixture { f, before in
            let reference = try XCTUnwrap(before.activation.runtime.state.reference), record = try XCTUnwrap(before.intent)
            let rows = try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1"), boundary = try pair(f)
            var commits = 0, stages: [Stage] = []; try f.reopen { commits += 1 }
            let result = try complete(f, expected: before) { stage, actual in
                stages.append(stage)
                if actual.activation.runtime.state.configurationPublished { try actual.requirePublication(from: before, reference: reference) }
                else { try actual.requireSame(as: before) }
                XCTAssertThrowsError(try self.snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }
            let after = try snapshot(f)
            try after.requireSame(as: result); try after.requirePublication(from: before, reference: reference)
            XCTAssertEqual(commits, 1); XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1"), rows)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1 WHERE account=x'\(hex(reference.services.accountID))' AND record=x'\(try hex(reference.encoded))' AND complete=1"), 1)
            XCTAssertEqual(after.intent, record); XCTAssertEqual(try pair(f), boundary)
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            var called = false
            let verify: (Stage, Snapshot) throws -> Void = { _, _ in called = true }
            XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: after,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: verify)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try f.machine().beginRetainedSetupPolicyWrite(writing, source: f.source, expected: after,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: verify)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try f.machine().recordRetainedSetupPolicyWrite(record, boundary: boundary, expected: after,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: verify)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: after)
        }
    }

    func testFreshPublishedRecoveryDoesNotUpdateAndTheOldUnpublishedFrameIsStale() throws {
        try fixture { f, before in
            var commits = 0; try f.reopen { commits += 1 }
            _ = try complete(f, expected: before); let actual = try snapshot(f); var stages: [Stage] = []
            let repeated = try complete(f, expected: actual) { stage, frame in
                stages.append(stage); try frame.requireSame(as: actual)
            }
            try repeated.requireSame(as: actual); XCTAssertEqual(commits, 1); XCTAssertEqual(stages, [.beforeTransaction])
            var called = false
            XCTAssertThrowsError(try complete(f, expected: before, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertFalse(called); XCTAssertEqual(commits, 1); try snapshot(f).requireSame(as: actual)
        }
    }

    func testOrdinaryWriterStillRejectsRetainedAndRetainedWriterExplicitlyRejectsCurrentRelease() throws {
        try fixture { f, before in
            let reference = try XCTUnwrap(before.activation.runtime.state.reference), policy = try XCTUnwrap(before.intent)
            var called = false
            XCTAssertThrowsError(try f.machine().completeStableRuntimePublication(reference, expected: before.activation.runtime,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { _, _ in called = true })) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
            try StableRuntimePreparationWriterTests.withCurrentReleasePublicationRefusalFixture { current, runtime, validReference in
                XCTAssertEqual(runtime.setup.account?.origin, .currentRelease)
                XCTAssertNoThrow(try validReference.validate(account: runtime.preparation, services: runtime.plan))
                XCTAssertThrowsError(try current.machine().completeRetainedSetupRuntimePublication(validReference,
                    expected: runtime, policy: policy, candidate: current.candidate, directory: current.directory,
                    admission: current.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in called = true })) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
                XCTAssertFalse(called)
            }
        }
    }

    func testPreparedWritingForeignReferenceAndChangedRecordedRowRefuseBeforeCallbacks() throws {
        try fixture { f, before in
            let original = try XCTUnwrap(before.intent), reference = try XCTUnwrap(before.activation.runtime.state.reference)
            for phase in [Record.Phase.prepared, .writing] {
                let wrong = try changed(original) { fields in
                    fields["phase"] = phase.rawValue; fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil
                }
                var called = false
                XCTAssertThrowsError(try complete(f, expected: before, policy: wrong, verify: { _, _ in called = true })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
                XCTAssertFalse(called)
            }
            let foreign = try RuntimeMaterialReference(materialID: AccountPreparationIntent.randomID(), services: reference.services,
                materialDigest: reference.materialDigest, transportPublicKeyInfo: reference.transportPublicKeyInfo, gateway: reference.gateway)
            var called = false
            XCTAssertThrowsError(try complete(f, expected: before, reference: foreign, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertThrowsError(try complete(f, expected: before, custody: false, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            let revised = try changed(original) { $0["revision"] = UUID().uuidString }
            XCTAssertThrowsError(try complete(f, expected: before, policy: revised, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
        }
    }

    func testMissingWriterFormatsRefuseBeforeAdmissionAndBeforeAnyCallback() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(writerFormats: false, migration: false, noPolicyChange: true) { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            guard case .recorded(let recorded) = try writing.reconciling(f.source.accountPolicy) else { return XCTFail("Owned no-op pair must reconcile") }
            try f.machine().close()
            _ = try f.scalar(MachineUpdateRetainedSetupPolicyStorage.createSQL); _ = try f.scalar("PRAGMA user_version=25")
            let id = recorded.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = recorded.revision.uuidString.replacingOccurrences(of: "-", with: "")
            _ = try f.scalar("INSERT INTO retained_setup_policy_intents_v1 VALUES(x'\(hex(recorded.accountID))',x'\(id)',x'\(revision)',x'\(try hex(recorded.encoded))')")
            try f.reopen(nil); let before = try snapshot(f); f.admission.close(); var called = false
            XCTAssertThrowsError(try complete(f, expected: before, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before); try f.verifyPair()
        }
    }

    func testEachPrecommitFailureRollsBackTheBitAndReleasesTheAuthorization() throws {
        try fixture { f, before in
            var commits = 0; try f.reopen { commits += 1 }
            for stopped: Stage in [.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertThrowsError(try complete(f, expected: before, verify: { stage, _ in
                    if stage == stopped { throw Fault.callback }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(commits, 0); try snapshot(f).requireSame(as: before)
                XCTAssertFalse(try snapshot(f).activation.runtime.state.configurationPublished)
                XCTAssertNoThrow(try f.machine().requireRetainedSetupPromotionWriterAvailable())
            }
            _ = try complete(f, expected: before); XCTAssertEqual(commits, 1)
        }
    }

    func testAfterCommitCallbackFailureClosesTheStoreAndFreshRecoveryMakesNoUpdate() throws {
        try fixture { f, before in
            var commits = 0; try f.reopen { commits += 1 }
            XCTAssertThrowsError(try complete(f, expected: before, verify: { stage, _ in
                if stage == .afterCommit { throw Fault.callback }
            })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil); let actual = try snapshot(f)
            try actual.requirePublication(from: before, reference: XCTUnwrap(before.activation.runtime.state.reference))
            let observed = try complete(f, expected: actual); try observed.requireSame(as: actual); XCTAssertEqual(commits, 1)
        }
    }

    func testLostCommitAcknowledgementRequiresFreshStateAndCannotRepeatTheUpdate() throws {
        try fixture { f, before in
            var commits = 0; try f.reopen { commits += 1; throw Fault.commit }
            XCTAssertThrowsError(try complete(f, expected: before)) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil); let actual = try snapshot(f)
            try actual.requirePublication(from: before, reference: XCTUnwrap(before.activation.runtime.state.reference))
            var stages: [Stage] = []
            _ = try complete(f, expected: actual, verify: { stage, _ in stages.append(stage) })
            XCTAssertEqual(stages, [.beforeTransaction]); XCTAssertEqual(commits, 1)
        }
    }

    func testAnUnrelatedRowChangedAfterCommitCannotBeAcknowledgedAsSuccess() throws {
        try fixture { f, before in
            var commits = 0
            let flip = "UPDATE runtime_activation_v1 SET registered=1-registered"
            try f.reopen { commits += 1; _ = try f.scalar(flip) }
            XCTAssertThrowsError(try complete(f, expected: before)); XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            _ = try f.scalar(flip); try f.reopen(nil)
            XCTAssertTrue(try snapshot(f).activation.runtime.state.configurationPublished)
        }
    }

    func testACatalogChangeAfterCommitCannotBeAcknowledgedAsSuccess() throws {
        try fixture { f, before in
            var commits = 0
            try f.reopen { commits += 1; _ = try f.scalar("CREATE INDEX publication_fixture_extra ON runtime_preparation_v1(complete)") }
            XCTAssertThrowsError(try complete(f, expected: before)); XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            _ = try f.scalar("DROP INDEX publication_fixture_extra"); try f.reopen(nil)
            XCTAssertTrue(try snapshot(f).activation.runtime.state.configurationPublished)
        }
    }

    func testPublicationAndPolicyAuthorizationsExcludeEachOtherAndOrdinaryWrites() throws {
        try fixture { f, before in
            let policy = try XCTUnwrap(before.intent), boundary = try pair(f)
            _ = try f.machine().recordRetainedSetupPolicyWrite(policy, boundary: boundary, expected: before,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, actual in
                    XCTAssertThrowsError(try self.complete(f, expected: actual)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                })
            _ = try complete(f, expected: before) { _, actual in
                XCTAssertThrowsError(try self.complete(f, expected: actual)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().requireRetainedSetupPromotionWriterAvailable()) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().writeInventory(actual.activation.runtime.setup.source.actual.inventory,
                    expectedRevision: actual.activation.runtime.setup.source.actual.inventory.revision)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                if !actual.activation.runtime.state.configurationPublished {
                    let prepared = try Record(source: f.source)
                    XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: actual,
                        candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    let material = try MachineUpdateRetainedSetupMaterialSnapshot(runtime: actual.activation.runtime,
                        activation: actual.activation.state)
                    XCTAssertThrowsError(try f.machine().retainRetainedSetupRuntimeMaterial(XCTUnwrap(material.runtime.state.reference),
                        expected: material, candidate: f.candidate, directory: f.directory, admission: f.admission,
                        fileCustodyAccepted: true, verifyScoped: { _, _ in })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                }
            }
        }
    }

    func testForeignAndClosedAdmissionRefuseWithoutChangingTheRecordedRowOrBit() throws {
        try fixture { f, before in
            try fixture { other, _ in
                var called = false
                XCTAssertThrowsError(try complete(f, expected: before, admission: other.admission, verify: { _, _ in called = true })) {
                    XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
                }
                XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
            }
            f.admission.close(); var called = false
            XCTAssertThrowsError(try complete(f, expected: before, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
        }
    }
}
