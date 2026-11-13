import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Actual SQL and admission with modeled account completion. No native initialization or OS directory proof is supplied.
final class StableServiceAccountWriterTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableServiceAccountSnapshot
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Operation: CaseIterable { case retain, complete }
    private enum Fault: Error { case stage, commit }
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
    private func setup(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> MachineUpdateStableAccountSetupSnapshot {
        try f.machine().stableAccountSetupSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func fixture(prepared: Bool = true, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: f.initial, verifyScoped: { _, _ in })
            if prepared {
                let pinned = try f.machine().pinStableAccountPreparation(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                    expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
                let root = try AccountPreparationController.authorityDirectory(accountID: pinned.accountID)
                let initial = try f.machine().beginStableAccountInitialization(journalPath: root + "/Journal/journal.sqlite",
                    continuityPath: root + "/Continuity/continuity.sqlite", expected: setup(f), candidate: f.candidate,
                    directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
                // This checkpoint is a value fixture. No production initialization writer consumes it.
                let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: Data(repeating: 201, count: 32),
                    ledgerDigest: Data(repeating: 202, count: 32), journalEpoch: initial.initialAuthority.descriptor.epoch,
                    journalHead: 0, authorityGeneration: 1)
                let complete = try initial.advancing(checkpoint: checkpoint, complete: true)
                let value = try pinned.prepared(initialization: complete)
                try f.mutate("UPDATE authority_initialization_v1 SET revision=x'\(hex(complete.revision))',record=x'\(try hex(complete.bytes))' WHERE account=x'\(hex(value.accountID))'")
                try f.mutate("UPDATE account_preparation_v1 SET revision=x'\(hex(value.revision))',record=x'\(try hex(value.bytes))' WHERE owner=\(value.ownerUID)")
            }
            try body(f)
        }
    }
    private func plan(_ expected: Snapshot) throws -> ServiceAccountPlan {
        var next: UInt32 = 39999
        return try ServiceAccountAllocator.plan(account: expected.preparation, reserved: expected.reservedNumbers,
            candidate: { next += 1; return next }, available: { _ in true })
    }
    private func perform(_ operation: Operation, _ f: Fixture, plan: ServiceAccountPlan, expected: Snapshot? = nil,
        admission: UpdateOrdinaryAdmissionLease? = nil,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> ServiceAccountPlanStorage.State {
        switch operation {
        case .retain:
            return try f.machine().retainStableServiceAccountPlan(plan, expected: expected ?? snapshot(f), candidate: f.candidate,
                directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
        case .complete:
            return try f.machine().completeStableServiceAccountPlan(plan, expected: expected ?? snapshot(f), candidate: f.candidate,
                directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
        }
    }
    private func requireHeld(_ f: Fixture) throws {
        try f.admission.validate()
        XCTAssertThrowsError(try f.gate.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertThrowsError(try f.activity.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
    }

    func testRetainCommitsTheExactPlanAndNumbersUnderActualAdmission() throws {
        try fixture { f in
            let before = try snapshot(f), chosen = try plan(before)
            let rows = try f.scalar("SELECT COUNT(*) FROM service_accounts_v1")
            var stages: [Stage] = []
            let state = try perform(.retain, f, plan: chosen, verify: { stage, actual in
                stages.append(stage); try self.requireHeld(f)
                XCTAssertEqual(actual.setup.source.actual.inventory, before.setup.source.actual.inventory)
            })
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(state, .init(plan: chosen, complete: false))
            let after = try snapshot(f)
            try after.requireChange(plan: chosen, complete: false, from: before)
            XCTAssertEqual(after.preparation, before.preparation)
            XCTAssertEqual(after.setup.account?.initialization, before.setup.account?.initialization)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM service_accounts_v1"), rows + 1)
            XCTAssertEqual(try f.machine().serviceAccountPlan(accountID: chosen.accountID).plan?.encoded, try chosen.encoded)
        }
    }

    func testCompleteChangesOnlyTheMarkerAndKeepsTheRecordedPlan() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f))
            _ = try perform(.retain, f, plan: chosen)
            let before = try snapshot(f), rows = try f.scalar("SELECT COUNT(*) FROM service_accounts_v1")
            var stages: [Stage] = []
            let state = try perform(.complete, f, plan: chosen, verify: { stage, _ in stages.append(stage); try self.requireHeld(f) })
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(state, .init(plan: chosen, complete: true))
            let after = try snapshot(f)
            try after.requireChange(plan: chosen, complete: true, from: before)
            XCTAssertEqual(after.reservedNumbers, before.reservedNumbers)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM service_accounts_v1"), rows)
            XCTAssertEqual(try after.state.plan?.encoded, try before.state.plan?.encoded)
        }
    }

    func testExactRetainAndCompletionRecoveryPerformNoAdditionalCommit() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f)); var commits = 0
            try f.reopen { commits += 1 }
            for operation in Operation.allCases {
                let first = try perform(operation, f, plan: chosen), before = try snapshot(f), count = commits
                var stages: [Stage] = []
                XCTAssertEqual(try perform(operation, f, plan: chosen, verify: { stage, _ in stages.append(stage) }), first)
                XCTAssertEqual(stages, [.beforeTransaction]); XCTAssertEqual(commits, count)
                try snapshot(f).requireSame(as: before)
            }
            XCTAssertEqual(commits, 2)
        }
    }

    func testMissingPlanNumberCollisionsAndReplacementPlansCannotAdvanceState() throws {
        try fixture { f in
            let before = try snapshot(f), chosen = try plan(before)
            XCTAssertThrowsError(try perform(.complete, f, plan: chosen)) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .missingRecord)
            }
            let reserved = before.reservedNumbers.sorted()
            XCTAssertGreaterThanOrEqual(reserved.count, 2)
            let claims = try zip(ServiceAccountPlan.roles, reserved).map { role, number in
                try ServiceAccountClaim(accountID: before.preparation.accountID, role: role, number: number,
                    userID: UUID(), groupID: UUID())
            }
            let collision = try ServiceAccountPlan(account: before.preparation, planID: AccountPreparationIntent.randomID(), claims: claims)
            XCTAssertThrowsError(try perform(.retain, f, plan: collision)) {
                XCTAssertEqual($0 as? ServiceAccountProvisioningError, .conflictingRecord)
            }
            try snapshot(f).requireSame(as: before)
            _ = try perform(.retain, f, plan: chosen)
            let retained = try snapshot(f), replacement = try plan(before)
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, plan: replacement)) {
                    XCTAssertEqual($0 as? ServiceAccountProvisioningError, .conflictingRecord)
                }
                try snapshot(f).requireSame(as: retained)
            }
        }
    }

    func testPrecommitFailuresRollBackBothTransitionsAndReleaseThePrivateGate() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f))
            for operation in Operation.allCases {
                let before = try snapshot(f)
                for failure in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                    XCTAssertThrowsError(try perform(operation, f, plan: chosen, verify: { stage, _ in
                        if stage == failure { throw Fault.stage }
                    })) { XCTAssertTrue($0 is Fault) }
                    try snapshot(f).requireSame(as: before); try requireHeld(f)
                }
                XCTAssertNoThrow(try perform(operation, f, plan: chosen))
            }
        }
    }

    func testUncertainCommitsKeepTheActualRowsAndNeverReplayEitherWrite() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f))
            for operation in Operation.allCases {
                var commits = 0, committed: Snapshot?
                try f.reopen { commits += 1; throw Fault.commit }
                XCTAssertThrowsError(try perform(operation, f, plan: chosen, verify: { stage, actual in
                    if stage == .afterMutation { committed = actual }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(commits, 1)
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                try snapshot(f).requireSame(as: XCTUnwrap(committed))
                XCTAssertEqual(try perform(operation, f, plan: chosen), try XCTUnwrap(committed).state)
                XCTAssertEqual(commits, 1)
            }
        }
    }

    func testAfterCommitVerificationFailureRetiresTheStoreAndKeepsTheCommittedState() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f))
            for operation in Operation.allCases {
                var committed: Snapshot?
                XCTAssertThrowsError(try perform(operation, f, plan: chosen, verify: { stage, actual in
                    if stage == .afterMutation { committed = actual }
                    if stage == .afterCommit { throw Fault.stage }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                try snapshot(f).requireSame(as: XCTUnwrap(committed))
                XCTAssertEqual(try perform(operation, f, plan: chosen), try XCTUnwrap(committed).state)
            }
        }
    }

    func testChangedOtherRowsAndCatalogCannotBeAcknowledgedAsSuccessfulWrites() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f)); var commits = 0
            let flip = "UPDATE runtime_activation_v1 SET registered=1-registered"
            try f.reopen { commits += 1; _ = try f.scalar(flip) }
            XCTAssertThrowsError(try perform(.retain, f, plan: chosen))
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            _ = try f.scalar(flip); try f.reopen(nil)
            XCTAssertEqual(try snapshot(f).state, .init(plan: chosen, complete: false))
            try f.reopen { commits += 1; _ = try f.scalar("CREATE INDEX service_gate_fixture_extra ON service_accounts_v1(complete)") }
            XCTAssertThrowsError(try perform(.complete, f, plan: chosen))
            XCTAssertEqual(commits, 2)
            XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            // Undo only this fixture's injection. The product writer repairs no row or catalog entry.
            _ = try f.scalar("DROP INDEX service_gate_fixture_extra"); try f.reopen(nil)
            XCTAssertEqual(try snapshot(f).state, .init(plan: chosen, complete: true))
        }
    }

    func testStaleFramesAndForeignOrClosedAdmissionCannotChangeThePlan() throws {
        try fixture { f in
            let before = try snapshot(f), chosen = try plan(before)
            _ = try perform(.retain, f, plan: chosen)
            let retained = try snapshot(f)
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, plan: chosen, expected: before)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            try fixture { other in
                for operation in Operation.allCases {
                    XCTAssertThrowsError(try perform(operation, f, plan: chosen, expected: retained, admission: other.admission))
                }
            }
            f.admission.close()
            for operation in Operation.allCases { XCTAssertThrowsError(try perform(operation, f, plan: chosen, expected: retained)) }
            try snapshot(f).requireSame(as: retained)
        }
    }

    func testReentryAndOtherStableWritersCannotBorrowTheServiceGate() throws {
        try fixture { f in
            let chosen = try plan(snapshot(f))
            for operation in Operation.allCases {
                _ = try perform(operation, f, plan: chosen, verify: { _, actual in
                    try self.requireHeld(f)
                    XCTAssertThrowsError(try self.perform(operation, f, plan: chosen, expected: actual)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    XCTAssertThrowsError(try f.machine().pinStableAccountPreparation(publicKey: XCTUnwrap(actual.preparation.authorityPublicKey),
                        expected: actual.setup, candidate: f.candidate, directory: f.directory, admission: f.admission,
                        verifyScoped: { _, _ in })) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                    XCTAssertThrowsError(try f.machine().beginStableAccountPreparation(owner: f.owner,
                        allowedTargetUIDs: actual.preparation.commandPolicy.allowedTargetUIDs, disclosureAccepted: true,
                        expected: actual.setup, candidate: f.candidate, directory: f.directory, admission: f.admission,
                        makeInitial: f.initial, verifyScoped: { _, _ in })) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                    XCTAssertThrowsError(try f.machine().writeInventory(actual.setup.source.actual.inventory,
                        expectedRevision: actual.setup.source.actual.inventory.revision)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                })
            }
        }
    }
}
