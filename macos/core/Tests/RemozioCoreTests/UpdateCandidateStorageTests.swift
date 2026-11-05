import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class UpdateCandidateStorageTests: XCTestCase {
    private enum Fault: Error { case injected }

    func testExplicitUpgradePreservesRuntimeInventoryAndCopies() throws {
        for enroll in [false, true] {
            let f = try UpdateCandidateStorageFixture(enable: false, enroll: enroll)
            let copy = try f.copy()
            let before = try f.store.retainedRuntimeCompatibilityInputs()
            XCTAssertEqual(before.schemaVersion, enroll ? 7 : 6)
            XCTAssertNil(try f.store.updateCandidate())
            try f.enable()
            let after = try f.store.retainedRuntimeCompatibilityInputs()
            XCTAssertEqual(after.schemaVersion, 15)
            XCTAssertEqual(after.inventory, before.inventory)
            XCTAssertEqual(after.runtimes, before.runtimes)
            XCTAssertEqual(try f.store.records(), [copy])
            XCTAssertNil(try f.store.updateCandidate())
            try f.enable()
            try f.reopen()
            XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs(), after)
        }
    }

    func testWrongInstalledDigestCannotUpgradeStorage() throws {
        let f = try UpdateCandidateStorageFixture(enable: false)
        XCTAssertThrowsError(try f.store.upgradeUpdateCandidateStorage(expectedInstalledReleaseDigest: Data(repeating: 99, count: 32)))
        XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 7)
    }

    func testMissingCandidateAndStorageReadersCannotEnableStorage() throws {
        for name in [UpdateSchedulingCandidateRecord.formatName, "authority.installation-preparation"] {
            let f = try UpdateCandidateStorageFixture(enable: false)
            XCTAssertThrowsError(try UpdateSchedulingCurrentCandidate.enableStorageInLease(
                installedRelease: f.changedRelease(removing: name), policy: f.policy, store: f.store))
            XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 7)
        }
    }

    func testExistingRuntimeReadersRemainRequiredBeforeUpgrade() throws {
        let f = try UpdateCandidateStorageFixture(enable: false)
        let release = try f.changedRelease(removing: RuntimeMaterialReference.formatName)
        XCTAssertNoThrow(try UpdateSchedulingCandidateRecord.validateReaders(release, policy: f.policy))
        XCTAssertThrowsError(try UpdateSchedulingCurrentCandidate.enableStorageInLease(installedRelease: release, policy: f.policy, store: f.store))
        XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 7)
    }

    func testSchemaFifteenRequiresCandidateReadersBeforeAnySelection() throws {
        let f = try UpdateCandidateStorageFixture()
        XCTAssertNil(try f.store.updateCandidate())
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.store)
        for role in [AuthorityCodeRole.authority, .setupController] {
            let format = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == role && $0.name == UpdateSchedulingCandidateRecord.formatName })
            XCTAssertEqual(format.readVersions, [1])
            XCTAssertEqual(format.writeVersions, [1])
            XCTAssertTrue(try XCTUnwrap(snapshot.requirements.formats.first {
                $0.role == role && $0.name == "authority.installation-preparation"
            }).readVersions.contains(15))
        }
    }

    func testSelectionSurvivesReopenAndSameCopyKeepsItsGeneration() throws {
        let f = try UpdateCandidateStorageFixture()
        let copy = try f.copy(), selected = try f.select(copy)
        XCTAssertEqual(selected.generation, 1)
        XCTAssertEqual(selected.preparation, copy)
        XCTAssertEqual(try f.select(copy, replacing: selected), selected)
        try f.reopen()
        XCTAssertEqual(try f.store.updateCandidate(), selected)
        XCTAssertEqual(try f.withCurrent(selected) { validate in try validate(); return 73 }, 73)
    }

    func testReplacementNeedsTheExactPreviousSelection() throws {
        let f = try UpdateCandidateStorageFixture()
        let first = try f.select(f.copy()), copy = try f.copy()
        XCTAssertThrowsError(try f.select(copy))
        let second = try f.select(copy, replacing: first)
        XCTAssertEqual(second.generation, first.generation + 1)
        XCTAssertNotEqual(second.revision, first.revision)
        XCTAssertThrowsError(try f.select(first.preparation, replacing: first))
        XCTAssertThrowsError(try f.withCurrent(first) { _ in XCTFail("The old selection reached the callback.") })
        XCTAssertEqual(try f.store.updateCandidate(), second)
    }

    func testWithdrawalRetainsTheGenerationAndCannotReviveAnOldSelection() throws {
        let f = try UpdateCandidateStorageFixture()
        let first = try f.select(f.copy())
        let retired = try f.store.retireUpdateCandidate(first)
        XCTAssertFalse(retired.selected)
        XCTAssertEqual(retired.generation, first.generation)
        XCTAssertEqual(try f.store.retireUpdateCandidate(retired), retired)
        XCTAssertThrowsError(try f.withCurrent(retired) { _ in XCTFail("A withdrawn selection reached the callback.") })
        let next = try f.select(first.preparation, replacing: retired)
        XCTAssertEqual(next.generation, first.generation + 1)
        XCTAssertThrowsError(try f.withCurrent(first) { _ in XCTFail("The old generation reached the callback.") })
    }

    func testASelectedCopyCannotBeAbandonedBeforeWithdrawal() throws {
        let f = try UpdateCandidateStorageFixture()
        let copy = try f.copy(), selected = try f.select(copy)
        XCTAssertThrowsError(try f.store.abandon(id: copy.id, expectedRevision: copy.revision)) {
            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
        }
        _ = try f.store.retireUpdateCandidate(selected)
        XCTAssertEqual(try f.store.abandon(id: copy.id, expectedRevision: copy.revision).phase, .abandoned)
    }

    func testUnrecordedAndAbandonedCopiesCannotBeSelected() throws {
        let f = try UpdateCandidateStorageFixture(), other = try UpdateCandidateStorageFixture()
        XCTAssertThrowsError(try f.select(other.copy()))
        let copy = try f.copy()
        _ = try f.store.abandon(id: copy.id, expectedRevision: copy.revision)
        XCTAssertThrowsError(try f.select(copy))
        XCTAssertNil(try f.store.updateCandidate())
    }

    func testTheCallbackCannotReenterSelectionWithdrawalOrCloseTheStore() throws {
        let f = try UpdateCandidateStorageFixture()
        let selected = try f.select(f.copy())
        try f.withCurrent(selected) { validate in
            XCTAssertThrowsError(try f.store.retireUpdateCandidate(selected)) {
                XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
            }
            XCTAssertThrowsError(try f.store.close()) {
                XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
            }
            try validate()
        }
        XCTAssertEqual(try f.store.updateCandidate(), selected)
    }

    func testTheValidationClosureExpiresAfterTheCallbackReturns() throws {
        let f = try UpdateCandidateStorageFixture()
        let selected = try f.select(f.copy())
        var escaped: (() throws -> Void)?
        try f.withCurrent(selected) { validate in escaped = validate; try validate() }
        XCTAssertThrowsError(try XCTUnwrap(escaped)()) {
            XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .expired)
        }
    }

    func testAThrowingCallbackExpiresTheClosureAndKeepsTheSelection() throws {
        let f = try UpdateCandidateStorageFixture()
        let selected = try f.select(f.copy())
        var escaped: (() throws -> Void)?
        XCTAssertThrowsError(try f.withCurrent(selected) { validate -> Void in escaped = validate; throw Fault.injected })
        XCTAssertThrowsError(try XCTUnwrap(escaped)()) {
            XCTAssertEqual($0 as? UpdateSchedulingCandidateLeaseError, .expired)
        }
        XCTAssertEqual(try f.store.updateCandidate(), selected)
        XCTAssertEqual(try f.withCurrent(selected) { _ in 31 }, 31)
    }

    func testChangedRuntimeInputsCannotReachTheSelectionCallback() throws {
        let f = try UpdateCandidateStorageFixture(enroll: false)
        let selected = try f.select(f.copy())
        let before = try f.store.retainedRuntimeCompatibilityInputs()
        try f.store.retainRuntimeActivation(f.f.plan)
        XCTAssertThrowsError(try f.store.withValidatedUpdateCandidate(selected, runtime: before) { _ in
            XCTFail("Changed runtime inputs reached the callback.")
        })
    }

    func testCorruptGenerationRevisionAndRecordBytesAreRejected() throws {
        for assignment in ["generation=X'0000000000000002'", "revision=zeroblob(16)", "record=X'7B7D'"] {
            let f = try UpdateCandidateStorageFixture()
            _ = try f.select(f.copy())
            try f.sql("UPDATE update_scheduling_candidate_v1 SET \(assignment) WHERE id=1")
            XCTAssertThrowsError(try f.store.updateCandidate()) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testGenerationExhaustionCannotWrapOrReplaceTheSelection() throws {
        let f = try UpdateCandidateStorageFixture()
        let selected = try f.select(f.copy())
        let exhausted = try UpdateSchedulingCandidateRecord(macID: selected.macID, installationID: selected.installationID,
            inventoryRevision: selected.inventoryRevision, preparation: selected.preparation, generation: UInt64.max,
            revision: selected.revision)
        let hex = try exhausted.encoded.map { String(format: "%02X", $0) }.joined()
        try f.sql("UPDATE update_scheduling_candidate_v1 SET generation=X'FFFFFFFFFFFFFFFF',record=X'\(hex)' WHERE id=1")
        XCTAssertEqual(try f.store.updateCandidate(), exhausted)
        XCTAssertThrowsError(try f.select(f.copy(), replacing: exhausted)) {
            XCTAssertEqual($0 as? RuntimePreparationError, .exhausted)
        }
        XCTAssertEqual(try f.store.updateCandidate(), exhausted)
    }

    func testUnexpectedTablesRemainIncompatibleAtSchemaFifteen() throws {
        let f = try UpdateCandidateStorageFixture()
        try f.sql("CREATE TABLE unexpected(value INTEGER) STRICT")
        XCTAssertThrowsError(try f.store.updateCandidate()) {
            XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
        }
    }

    func testACommitReceiptFailureRequiresReconciliationInsteadOfASelectionRetry() throws {
        let f = try UpdateCandidateStorageFixture()
        let copy = try f.copy()
        try f.reopen { throw Fault.injected }
        XCTAssertThrowsError(try f.select(copy))
        XCTAssertThrowsError(try f.store.updateCandidate())
        try f.reopen()
        let selected = try XCTUnwrap(f.store.updateCandidate())
        XCTAssertEqual(selected.preparation, copy)
        XCTAssertEqual(selected.generation, 1)
    }
}
