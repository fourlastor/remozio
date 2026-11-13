import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned SQL models completed account and service metadata. It proves no native initialization, directory state, or runtime file publication.
final class StableRuntimePreparationValueTests: XCTestCase {
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
    private func value(_ before: Snapshot, reference: RuntimeMaterialReference?, published: Bool,
        plan: ServiceAccountPlan? = nil, numbers: Set<UInt32>? = nil,
        setup: MachineUpdateStableAccountSetupSnapshot? = nil) throws -> Snapshot {
        try .init(setup: setup ?? before.setup, services: .init(plan: plan ?? before.plan, complete: true),
            state: .init(reference: reference, configurationPublished: published), reservedNumbers: numbers ?? before.reservedNumbers)
    }
    private func replacingFrame(_ before: Snapshot, candidate: SignedReleaseEvidence,
        schema: Int64? = nil, rows: Data? = nil) throws -> MachineUpdateStableAccountSetupSnapshot {
        let actual = before.setup.source.actual
        let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: schema ?? actual.schemaVersion, inventory: actual.inventory,
            activation: actual.activation, admission: actual.admission, candidate: actual.candidate,
            installed: actual.installed, seal: actual.seal, currentRowsDigest: rows ?? actual.currentRowsDigest)
        let source = try MachineUpdateStableRuntimeSource(actual: frame, preparations: before.setup.source.preparations,
            initializations: before.setup.source.initializations, candidate: candidate)
        return try .init(source: source, owner: before.setup.owner)
    }

    func testExistingCurrentAndRetainedReadersStayReadOnlyAndRetainedTransitionsRefuse() throws {
        try fixture { f in
            var commits = 0
            try f.reopen { commits += 1 }
            let current = try snapshot(f)
            XCTAssertEqual(current.setup.account?.origin, .currentRelease)
            XCTAssertNil(current.state.reference); XCTAssertFalse(current.state.configurationPublished)
            try current.requireCurrent(machine: f.machine(), candidate: f.candidate)
            let retained = try f.machine().stableRuntimePreparationSnapshot(owner: f.retainedOwner, candidate: f.candidate)
            XCTAssertEqual(retained.setup.account?.origin, .retained)
            let selected = try XCTUnwrap(retained.state.reference)
            let copy = try value(retained, reference: selected, published: retained.state.configurationPublished)
            try copy.requireSame(as: retained)
            try retained.requireCurrent(machine: f.machine(), candidate: f.candidate)
            XCTAssertThrowsError(try copy.requirePublished(from: retained)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            XCTAssertThrowsError(try copy.requireChange(reference: selected, published: true, from: retained)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            let published = try value(current, reference: reference(current.plan), published: true)
            XCTAssertThrowsError(try published.requirePublished(from: retained)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            XCTAssertThrowsError(try copy.requirePublished(from: current)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
            try snapshot(f).requireSame(as: current); XCTAssertEqual(commits, 0)
        }
    }

    func testExactMaterialRetentionPublicationAndRecoveryCannotRegressOrReplaceTheReference() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan)
            let retained = try value(before, reference: selected, published: false)
            let published = try value(before, reference: selected, published: true)
            try retained.requireChange(reference: selected, published: false, from: before)
            try retained.requireChange(reference: selected, published: false, from: retained)
            try published.requireChange(reference: selected, published: true, from: retained)
            try published.requireChange(reference: selected, published: true, from: published)
            for prior in [before, retained, published] { try published.requirePublished(from: prior) }
            XCTAssertThrowsError(try published.requireChange(reference: selected, published: true, from: before))
            XCTAssertThrowsError(try retained.requireChange(reference: selected, published: false, from: published))
            XCTAssertThrowsError(try retained.requirePublished(from: before))
            XCTAssertThrowsError(try published.requireChange(reference: selected, published: false, from: retained))
            XCTAssertThrowsError(try value(before, reference: nil, published: true))
            XCTAssertThrowsError(try Snapshot(setup: before.setup, services: .init(plan: before.plan, complete: false),
                state: before.state, reservedNumbers: before.reservedNumbers))
            let another = try reference(before.plan)
            let replacements = [another,
                try RuntimeMaterialReference(materialID: another.materialID, services: selected.services,
                    materialDigest: selected.materialDigest, transportPublicKeyInfo: selected.transportPublicKeyInfo, gateway: selected.gateway),
                try RuntimeMaterialReference(materialID: selected.materialID, services: selected.services,
                    materialDigest: Data(repeating: 172, count: 32), transportPublicKeyInfo: selected.transportPublicKeyInfo, gateway: selected.gateway),
                try RuntimeMaterialReference(materialID: selected.materialID, services: selected.services,
                    materialDigest: selected.materialDigest, transportPublicKeyInfo: another.transportPublicKeyInfo, gateway: selected.gateway),
                try RuntimeMaterialReference(materialID: selected.materialID, services: selected.services,
                    materialDigest: selected.materialDigest, transportPublicKeyInfo: selected.transportPublicKeyInfo, gateway: another.gateway)]
            for replacement in replacements {
                XCTAssertNotEqual(replacement, selected)
                let changed = try value(before, reference: replacement, published: true)
                XCTAssertThrowsError(try changed.requireChange(reference: replacement, published: true, from: retained)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
                }
                XCTAssertThrowsError(try changed.requirePublished(from: retained)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
                }
            }
            try snapshot(f).requireSame(as: before)
        }
    }

    func testTransitionsKeepServiceClaimsReservationsAndStableInstallationInputsExact() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan)
            let retained = try value(before, reference: selected, published: false)
            let extra = try value(before, reference: selected, published: false, numbers: before.reservedNumbers.union([61000]))
            XCTAssertThrowsError(try extra.requireChange(reference: selected, published: false, from: before))
            XCTAssertThrowsError(try value(before, reference: selected, published: true,
                numbers: before.reservedNumbers.union([61000])).requirePublished(from: before))
            let owned = Set(before.plan.claims.map(\.number))
            XCTAssertFalse(before.reservedNumbers.subtracting(owned).isEmpty)
            let missing = try value(before, reference: selected, published: false, numbers: owned)
            XCTAssertThrowsError(try missing.requireChange(reference: selected, published: false, from: before))
            let replaced = try ServiceAccountPlan(account: before.preparation, planID: AccountPreparationIntent.randomID(),
                claims: before.plan.claims)
            let foreign = try reference(replaced), changedPlan = try value(before, reference: foreign, published: false, plan: replaced)
            XCTAssertThrowsError(try changedPlan.requireChange(reference: foreign, published: false, from: before))
            XCTAssertThrowsError(try value(before, reference: foreign, published: true, plan: replaced).requirePublished(from: before))
            let changedSchema = try replacingFrame(before, candidate: f.candidate, schema: before.setup.source.actual.schemaVersion + 1)
            XCTAssertThrowsError(try value(before, reference: selected, published: false, setup: changedSchema)
                .requireChange(reference: selected, published: false, from: before))
            XCTAssertThrowsError(try value(before, reference: selected, published: true, setup: changedSchema).requirePublished(from: before))
            // Only the private writer can prove which row changed behind this opaque digest.
            let changedRows = try replacingFrame(before, candidate: f.candidate, rows: Data(repeating: 173, count: 32))
            let opaqueChange = try value(before, reference: selected, published: false, setup: changedRows)
            try opaqueChange.requireChange(reference: selected, published: false, from: before)
            XCTAssertThrowsError(try opaqueChange.requireSame(as: retained))
            try snapshot(f).requireSame(as: before)
        }
    }

    func testActualReadersDetectStaleSourcesAndOrdinaryRuntimeWritersRemainClosed() throws {
        try fixture { f in
            let before = try snapshot(f), selected = try reference(before.plan)
            try f.mutate("UPDATE runtime_activation_v1 SET registered=1-registered")
            let actual = try snapshot(f)
            XCTAssertThrowsError(try before.requireCurrent(machine: f.machine(), candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try actual.requireCurrent(machine: f.machine(), candidate: f.candidate)
            XCTAssertThrowsError(try f.machine().retainRuntimeMaterial(selected)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try f.machine().completeRuntimePublication(selected)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try snapshot(f).requireSame(as: actual); try f.admission.validate()
        }
    }
}
