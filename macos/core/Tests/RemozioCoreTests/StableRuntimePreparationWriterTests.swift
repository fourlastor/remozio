import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned SQL models completed account and service metadata. It proves no native initialization, directory state, or runtime file publication.
final class StableRuntimePreparationWriterTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableRuntimePreparationSnapshot
    private func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
    private func setup(_ f: Fixture) throws -> MachineUpdateStableAccountSetupSnapshot {
        try f.machine().stableAccountSetupSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func snapshot(_ f: Fixture) throws -> Snapshot {
        try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: f.initial, verifyScoped: { _, _ in })
            let pinned = try f.machine().pinStableAccountPreparation(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                expected: setup(f), candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            let root = try AccountPreparationController.authorityDirectory(accountID: pinned.accountID)
            let initial = try f.machine().beginStableAccountInitialization(journalPath: root + "/Journal/journal.sqlite",
                continuityPath: root + "/Continuity/continuity.sqlite", expected: setup(f), candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            // Fixture SQL installs this modeled checkpoint. No production initialization writer consumes it.
            let checkpoint = try ContinuityCheckpoint(generation: 1, authorityDigest: Data(repeating: 201, count: 32),
                ledgerDigest: Data(repeating: 202, count: 32), journalEpoch: initial.initialAuthority.descriptor.epoch,
                journalHead: 0, authorityGeneration: 1)
            let complete = try initial.advancing(checkpoint: checkpoint, complete: true)
            let account = try pinned.prepared(initialization: complete)
            try f.mutate("UPDATE authority_initialization_v1 SET revision=x'\(hex(complete.revision))',record=x'\(try hex(complete.bytes))' WHERE account=x'\(hex(account.accountID))'")
            try f.mutate("UPDATE account_preparation_v1 SET revision=x'\(hex(account.revision))',record=x'\(try hex(account.bytes))' WHERE owner=\(account.ownerUID)")
            let services = try f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate)
            var next: UInt32 = 39999
            let plan = try ServiceAccountAllocator.plan(account: account, reserved: services.reservedNumbers,
                candidate: { next += 1; return next }, available: { _ in true })
            _ = try f.machine().retainStableServiceAccountPlan(plan, expected: services, candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            _ = try f.machine().completeStableServiceAccountPlan(plan,
                expected: f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate), candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            try body(f)
        }
    }
    private func reference(_ plan: ServiceAccountPlan) throws -> RuntimeMaterialReference {
        try .init(materialID: AccountPreparationIntent.randomID(), services: plan, materialDigest: Data(repeating: 171, count: 32),
            transportPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation,
            gateway: GatewayRegistrationIdentity(ownerID: AccountPreparationIntent.randomID(), macID: plan.macID,
                accountID: plan.accountID, gatewayID: AccountPreparationIntent.randomID(),
                lifecycleEpoch: AccountPreparationIntent.randomID(), rootPublicKey: plan.authorityPublicKey))
    }
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case stage, commit, acknowledgment }
    private enum Operation: CaseIterable { case retain, publish }
    private func perform(_ operation: Operation, _ f: Fixture, reference: RuntimeMaterialReference,
        expected: Snapshot? = nil, custody: Bool = true,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> RuntimePreparationState {
        let expected = try expected ?? snapshot(f)
        switch operation {
        case .retain: return try f.machine().retainStableRuntimeMaterial(reference, expected: expected, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: custody, verifyScoped: verify)
        case .publish: return try f.machine().completeStableRuntimePublication(reference, expected: expected, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: custody, verifyScoped: verify)
        }
    }
    private func bytes(_ f: Fixture) throws -> Int64 {
        try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1")
    }

    func testBothSQLTransitionsUseExactFramesAndExcludeOtherGatesInBothDirections() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan), count = try bytes(f)
            let services = try f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate)
            for operation in Operation.allCases {
                let original = try snapshot(f); var stages: [Stage] = []
                let state = try perform(operation, f, reference: selected, verify: { stage, actual in
                    stages.append(stage); try f.admission.validate()
                    XCTAssertThrowsError(try f.machine().stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    XCTAssertThrowsError(try f.machine().requireRetainedSetupPromotionWriterAvailable()) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    for nested in Operation.allCases {
                        XCTAssertThrowsError(try self.perform(nested, f, reference: selected, expected: actual)) {
                            XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                        }
                    }
                    XCTAssertThrowsError(try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0],
                        disclosureAccepted: true, expected: actual.setup, candidate: f.candidate, directory: f.directory,
                        admission: f.admission, makeInitial: { _, _ in XCTFail("Nested reservation factory"); throw Fault.stage },
                        verifyScoped: { _, _ in XCTFail("Nested reservation callback") })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    XCTAssertThrowsError(try f.machine().pinStableAccountPreparation(publicKey: XCTUnwrap(actual.preparation.authorityPublicKey),
                        expected: actual.setup, candidate: f.candidate, directory: f.directory, admission: f.admission,
                        verifyScoped: { _, _ in XCTFail("Nested storage callback") })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    XCTAssertThrowsError(try f.machine().retainStableServiceAccountPlan(before.plan, expected: services,
                        candidate: f.candidate, directory: f.directory, admission: f.admission,
                        verifyScoped: { _, _ in XCTFail("Nested service callback") })) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    if stage == .afterMutation || stage == .afterCommit {
                        try actual.requireChange(reference: selected, published: operation == .publish, from: original)
                    } else { try actual.requireSame(as: original) }
                })
                XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
                XCTAssertEqual(state, .init(reference: selected, configurationPublished: operation == .publish))
                XCTAssertNoThrow(try f.machine().requireRetainedSetupPromotionWriterAvailable())
            }
            let published = try snapshot(f); try published.requirePublished(from: before)
            XCTAssertEqual(try bytes(f), count + 1)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1 WHERE account=x'\(hex(before.preparation.accountID))' AND material=x'\(hex(selected.materialID))' AND pin=x'\(hex(selected.transportPublicKeyInfo))' AND digest=x'\(hex(selected.materialDigest))' AND complete=1 AND record=x'\(try hex(selected.encoded))'"), 1)
            var reverseRefusals = 0
            func reverse() throws {
                for operation in Operation.allCases {
                    XCTAssertThrowsError(try perform(operation, f, reference: selected, expected: published)) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                    reverseRefusals += 1
                }
            }
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: published.setup, candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: { _, _ in XCTFail("Recovery allocation"); throw Fault.stage }, verifyScoped: { _, _ in try reverse() })
            _ = try f.machine().pinStableAccountPreparation(publicKey: XCTUnwrap(published.preparation.authorityPublicKey),
                expected: published.setup, candidate: f.candidate, directory: f.directory, admission: f.admission,
                verifyScoped: { _, _ in try reverse() })
            _ = try f.machine().completeStableServiceAccountPlan(before.plan,
                expected: f.machine().stableServiceAccountSnapshot(owner: f.owner, candidate: f.candidate), candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in try reverse() })
            XCTAssertEqual(reverseRefusals, 6); try snapshot(f).requireSame(as: published)
        }
    }

    func testPublicationWithoutRetentionRefusesAndExactRecoveryMakesNoCommit() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan), count = try bytes(f)
            var commits = 0
            try f.reopen { commits += 1 }
            XCTAssertThrowsError(try perform(.publish, f, reference: selected)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .incomplete)
            }
            XCTAssertEqual(commits, 0); XCTAssertEqual(try bytes(f), count)
            try snapshot(f).requireSame(as: before)
            for operation in Operation.allCases {
                let actual = try perform(operation, f, reference: selected), recorded = commits
                var stages: [Stage] = []
                XCTAssertEqual(try perform(operation, f, reference: selected, verify: { stage, _ in stages.append(stage) }), actual)
                XCTAssertEqual(stages, [.beforeTransaction]); XCTAssertEqual(commits, recorded)
            }
            XCTAssertEqual(commits, 2)
            let published = try snapshot(f)
            XCTAssertEqual(try perform(.retain, f, reference: selected), published.state)
            XCTAssertEqual(commits, 2); try snapshot(f).requireSame(as: published)
        }
    }

    func testOtherAccountsMaterialIdentifiersAndPinsCannotBeReusedOrReplaceRetainedMaterial() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan)
            let other = try f.machine().stableRuntimePreparationSnapshot(owner: f.retainedOwner, candidate: f.candidate)
            let foreign = try XCTUnwrap(other.state.reference)
            let conflicting = [try RuntimeMaterialReference(materialID: foreign.materialID, services: selected.services,
                materialDigest: selected.materialDigest, transportPublicKeyInfo: selected.transportPublicKeyInfo, gateway: selected.gateway),
                try RuntimeMaterialReference(materialID: selected.materialID, services: selected.services,
                    materialDigest: selected.materialDigest, transportPublicKeyInfo: foreign.transportPublicKeyInfo, gateway: selected.gateway)]
            for value in conflicting {
                XCTAssertThrowsError(try perform(.retain, f, reference: value)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
                }
                try snapshot(f).requireSame(as: before)
            }
            _ = try perform(.retain, f, reference: selected)
            let retained = try snapshot(f), replacement = try reference(before.plan)
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, reference: replacement)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
                }
                try snapshot(f).requireSame(as: retained)
            }
        }
    }

    func testCustodyStaleSourceRetainedOriginAndClosedAdmissionRefuseWithoutMutation() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan)
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, reference: selected, custody: false)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
                }
            }
            try snapshot(f).requireSame(as: before)
            let retained = try f.machine().stableRuntimePreparationSnapshot(owner: f.retainedOwner, candidate: f.candidate)
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, reference: XCTUnwrap(retained.state.reference), expected: retained)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
            }
            try retained.requireCurrent(machine: f.machine(), candidate: f.candidate)
            try f.mutate("UPDATE runtime_activation_v1 SET registered=1-registered")
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, reference: selected, expected: before)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            let actual = try snapshot(f)
            f.admission.close()
            for operation in Operation.allCases { XCTAssertThrowsError(try perform(operation, f, reference: selected, expected: actual)) }
            try snapshot(f).requireSame(as: actual)
        }
    }

    func testEveryPrecommitStageRollsBackAndReleasesTheGateForBothTransitions() throws {
        try fixture { f in
            let selected = try reference(snapshot(f).plan)
            for operation in Operation.allCases {
                let before = try snapshot(f)
                for failure in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                    XCTAssertThrowsError(try perform(operation, f, reference: selected, verify: { stage, _ in
                        if stage == failure { throw Fault.stage }
                    })) { XCTAssertTrue($0 is Fault) }
                    try snapshot(f).requireSame(as: before)
                    XCTAssertNoThrow(try f.machine().requireRetainedSetupPromotionWriterAvailable())
                    try f.admission.validate()
                }
                _ = try perform(operation, f, reference: selected)
            }
        }
    }

    func testUncertainCommitsKeepActualRowsAndRecoveryDoesNotRepeatTheWrite() throws {
        try fixture { f in
            let selected = try reference(snapshot(f).plan)
            for operation in Operation.allCases {
                var commits = 0, committed: Snapshot?
                try f.reopen { commits += 1; throw Fault.commit }
                XCTAssertThrowsError(try perform(operation, f, reference: selected, verify: { stage, actual in
                    if stage == .afterMutation { committed = actual }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(commits, 1)
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                try snapshot(f).requireSame(as: XCTUnwrap(committed))
                XCTAssertEqual(try perform(operation, f, reference: selected), try XCTUnwrap(committed).state)
                XCTAssertEqual(commits, 1)
            }
        }
    }

    func testFailedPostcommitAcknowledgmentsRetireTheWriterAndRecoverOnlyRecordedState() throws {
        try fixture { f in
            let selected = try reference(snapshot(f).plan)
            for operation in Operation.allCases {
                var committed: Snapshot?
                XCTAssertThrowsError(try perform(operation, f, reference: selected, verify: { stage, actual in
                    if stage == .afterCommit { committed = actual; throw Fault.acknowledgment }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                try snapshot(f).requireSame(as: XCTUnwrap(committed))
                XCTAssertEqual(try perform(operation, f, reference: selected), try XCTUnwrap(committed).state)
            }
        }
    }

    func testOtherRuntimeRowsAndTheCatalogRemainPinnedThroughCommitAcknowledgment() throws {
        try fixture { f in
            let selected = try reference(snapshot(f).plan)
            let other = try f.machine().stableRuntimePreparationSnapshot(owner: f.retainedOwner, candidate: f.candidate)
            let account = hex(other.preparation.accountID)
            let flip = "UPDATE runtime_preparation_v1 SET complete=1-complete WHERE account=x'\(account)'"
            var commits = 0
            try f.reopen { commits += 1; _ = try f.scalar(flip) }
            XCTAssertThrowsError(try perform(.retain, f, reference: selected)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(commits, 1)
            _ = try f.scalar(flip); try f.reopen(nil)
            let retained = try snapshot(f); XCTAssertEqual(retained.state, .init(reference: selected, configurationPublished: false))
            try f.reopen { commits += 1; _ = try f.scalar("CREATE INDEX runtime_gate_fixture_extra ON runtime_preparation_v1(complete)") }
            XCTAssertThrowsError(try perform(.publish, f, reference: selected)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(commits, 2)
            _ = try f.scalar("DROP INDEX runtime_gate_fixture_extra"); try f.reopen(nil)
            XCTAssertEqual(try snapshot(f).state, .init(reference: selected, configurationPublished: true))
            let unchanged = try f.machine().stableRuntimePreparationSnapshot(owner: f.retainedOwner, candidate: f.candidate)
            XCTAssertEqual(unchanged.state, other.state); XCTAssertEqual(unchanged.preparation, other.preparation)
            XCTAssertEqual(unchanged.plan, other.plan); XCTAssertEqual(unchanged.reservedNumbers, other.reservedNumbers)
            _ = try perform(.publish, f, reference: selected)
            XCTAssertEqual(commits, 2)
        }
    }
}
