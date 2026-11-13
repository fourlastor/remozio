import Foundation
import XCTest
@testable import RemozioCore

struct RetainedMaterialWriterFixture {
    let machine: () throws -> PreparationIntentStore
    let owner: LocalAccountIdentity
    let candidate: SignedReleaseEvidence
    let directory: ReleaseDestinationLease
    let admission: UpdateOrdinaryAdmissionLease
    let material: RuntimePreparationMaterial
    let reopen: ((() throws -> Void)?) throws -> Void
    let scalar: (String) throws -> Int64
}

/// Owned SQL proves metadata isolation and rollback, without protected native files or running services.
final class MachineUpdateRetainedSetupMaterialWriterTests: XCTestCase {
    private typealias Frame = MachineUpdateRetainedSetupMaterialSnapshot
    private typealias Fixture = RetainedMaterialWriterFixture
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case callback }
    private func fixture(hasReference: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(hasReference: hasReference, body)
    }
    private func snapshot(_ f: Fixture) throws -> Frame {
        try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func retain(_ f: Fixture, expected: Frame? = nil, reference: RuntimeMaterialReference? = nil,
        custody: Bool = true, verify: (Stage, Frame) throws -> Void = { _, _ in }) throws -> RuntimePreparationState {
        try f.machine().retainRetainedSetupRuntimeMaterial(reference ?? f.material.reference,
            expected: expected ?? snapshot(f), candidate: f.candidate, directory: f.directory,
            admission: f.admission, fileCustodyAccepted: custody, verifyScoped: verify)
    }

    func testInsertRereadsTheActualSourceAndRuntimeViewWithoutPublication() throws {
        try fixture { f in
            let before = try snapshot(f), count = try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1")
            XCTAssertNil(before.runtime.state.reference)
            var stages: [Stage] = []
            let state = try retain(f) { stage, actual in
                stages.append(stage)
                if actual.runtime.state.reference == nil { try actual.requireSame(as: before) }
                else { try actual.requireRetained(f.material.reference, from: before) }
                XCTAssertThrowsError(try self.snapshot(f)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().requireRetainedSetupPromotionWriterAvailable()) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
            }
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1"), count + 1)
            XCTAssertEqual(state.reference, try f.material.reference); XCTAssertFalse(state.configurationPublished)
            let after = try snapshot(f), source = try f.machine().stableRuntimeSource(candidate: f.candidate)
            try after.requireRetained(f.material.reference, from: before)
            try after.runtime.setup.source.requireSame(as: source)
            let inputs = try f.machine().stableRuntimeViewInputs(expected: source, retained: [], candidate: f.candidate)
            let view = try MachineUpdateStableRuntimeView(compatibility: inputs, candidate: f.candidate)
            let selected = try XCTUnwrap(view.accounts.first { $0.scope.accountID == before.runtime.preparation.accountID })
            XCTAssertEqual(selected.runtime?.reference, state.reference)
            XCTAssertEqual(selected.runtime?.configurationPublished, false)
            XCTAssertNil(selected.configuration); XCTAssertNil(selected.ordinaryActivation)
            try view.requireCurrent(machine: f.machine(), candidate: f.candidate)
            XCTAssertThrowsError(try view.startupAccount(before.runtime.preparation.accountID, ownerUID: f.owner.uid))
        }
    }

    func testIdenticalHistoricalReferenceDoesNotWriteOrAcknowledgePublication() throws {
        try fixture(hasReference: true) { f in
            var commits = 0; try f.reopen { commits += 1 }
            let before = try snapshot(f)
            XCTAssertEqual(try retain(f), before.runtime.state)
            XCTAssertEqual(commits, 0)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testConflictingHistoricalReferenceStopsAndKeepsItsOriginalBytes() throws {
        try fixture(hasReference: true) { f in
            let before = try snapshot(f), now = Date()
            let different = try RuntimePreparationMaterial.create(services: before.runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600)).reference
            var called = false
            XCTAssertThrowsError(try retain(f, reference: different, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
        }
    }

    func testRetainedAndCurrentEntriesRefuseEachOthersOrigins() throws {
        try fixture { f in
            let before = try snapshot(f)
            XCTAssertThrowsError(try f.machine().retainStableRuntimeMaterial(f.material.reference,
                expected: before.runtime, candidate: f.candidate, directory: f.directory, admission: f.admission,
                fileCustodyAccepted: true, verifyScoped: { _, _ in XCTFail("Ordinary retained callback") })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try snapshot(f).requireSame(as: before)
        }
        try StableRuntimePreparationValueTests.withCurrentRuntimeFrame { f, current in
            XCTAssertEqual(current.setup.account?.origin, .currentRelease)
            XCTAssertEqual(current.setup.account?.inInventory, false)
            XCTAssertThrowsError(try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try current.requireCurrent(machine: f.machine(), candidate: f.candidate)
        }
    }

    func testStaleMissingReferenceCannotReplayAnAlreadyCommittedInsert() throws {
        try fixture { f in
            let before = try snapshot(f)
            _ = try retain(f, expected: before)
            let after = try snapshot(f)
            XCTAssertThrowsError(try retain(f, expected: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try snapshot(f).requireSame(as: after)
        }
    }

    func testCallbackFailuresBeforeCommitRollBackTheOnlyPermittedRow() throws {
        for stopped: Stage in [.beforeTransaction, .inTransaction, .afterMutation] {
            try fixture { f in
                let before = try snapshot(f), count = try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1")
                XCTAssertThrowsError(try retain(f, verify: { stage, _ in if stage == stopped { throw Fault.callback } })) {
                    XCTAssertTrue($0 is Fault)
                }
                try snapshot(f).requireSame(as: before)
                XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1"), count)
            }
        }
    }

    func testPostCommitFailureClosesTheWriterWithoutRetryingTheInsert() throws {
        try fixture { f in
            var commits = 0; try f.reopen { commits += 1 }
            XCTAssertThrowsError(try retain(f, verify: { stage, _ in if stage == .afterCommit { throw Fault.callback } }))
            XCTAssertThrowsError(try snapshot(f)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            XCTAssertEqual(commits, 1)
            try f.reopen(nil)
            XCTAssertEqual(try snapshot(f).runtime.state.reference, try f.material.reference)
            XCTAssertFalse(try snapshot(f).runtime.state.configurationPublished)
        }
    }

    func testCustodyRefusalPrecedesCallbacksAndLeavesAllMetadataUnchanged() throws {
        try fixture { f in
            let before = try snapshot(f); var called = false
            XCTAssertThrowsError(try retain(f, custody: false, verify: { _, _ in called = true })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
        }
    }
}
