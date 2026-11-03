import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Real owned machine/import SQLite and synthetic file fixtures. No native barrier or installed cutover is qualified.
final class RuntimeAuditUpgradeCutoverTests: XCTestCase {
    private struct Interrupted: Error {}
    final class Fixture {
        let imported: RuntimeAuditUpgradeImportTests.Fixture?
        let collector: RuntimeAuditUpgradeCollectorTests.Fixture
        let graph: RuntimeAuditUpgradeGraph
        let stored: RuntimeAuditUpgradeGraphRecord
        var runtime: RuntimeActivationFixture { collector.files.f }
        var policy: AuthorityCodePolicy { collector.files.preparation.source.host.codePolicy }
        var release: SignedReleaseEvidence { get throws { try XCTUnwrap(runtime.nativeRelease) } }
        init(gateway: Bool = false, activeAndPending: Bool = false, partialGateway: Bool = false,
             imported: RuntimeAuditUpgradeImportTests.Fixture? = nil, registered: Bool = true) throws {
            self.imported = imported
            collector = try .init(imported: imported, registered: registered)
            var input = try gateway ? collector.gateway(pending: true) : nil
            if partialGateway {
                let material = try RuntimeAuditUpgradeDependenciesTests().gateway(collector.files.preparation)
                input = try .init(material: material, reference: material.reference, journal: .init(intent: nil, initialized: false),
                    activation: .init(plan: nil, filesPublished: false, jobRegistered: false), settings: .empty, service: nil, fence: nil)
                try collector.files.f.machine.retainGatewayMaterial(material.reference)
                try collector.files.install(collector.files.plan(gateway: XCTUnwrap(input)))
            }
            if activeAndPending, let old = input, let first = old.settings.pending, let activation = old.activation.plan {
                try collector.files.f.machine.markGatewaySettingsTransition(first, phase: .filesPublished)
                try collector.files.f.machine.markGatewaySettingsTransition(first, phase: .consumersObserved)
                try collector.files.f.machine.completeGatewaySettingsTransition(first)
                let second = try GatewayRuntimeSettingsRevision(id: Data(repeating: 32, count: 16),
                    selection: GatewaySetupForm().settingsSelection(), activation: activation, previous: first,
                    journal: old.journal, foreground: collector.files.preparation.source,
                    inventory: XCTUnwrap(collector.files.f.machine.inventory()))
                try collector.files.f.machine.retainGatewaySettingsTransition(second)
                try collector.files.f.machine.markGatewaySettingsTransition(second, phase: .quiesced)
                let publication = try GatewayRuntimeSettingsPublicationPlan(revision: second, previous: first, activation: activation,
                    journal: old.journal, foreground: collector.files.preparation.source,
                    inventory: XCTUnwrap(collector.files.f.machine.inventory()))
                input = .init(material: old.material, reference: old.reference, journal: old.journal, activation: old.activation,
                    settings: .init(active: first, pending: second, phase: .quiesced), service: old.service, fence: try .init(publication))
                try collector.files.install(collector.files.plan(gateway: XCTUnwrap(input)), pending: true)
            }
            collector.record = try RuntimeAuditUpgradeStaging.stageOwned(machine: collector.files.f.machine,
                account: collector.files.f.account, expected: collector.record, currentPolicy: collector.files.preparation.source.host.codePolicy,
                installedRelease: XCTUnwrap(collector.files.f.nativeRelease), directory: XCTUnwrap(collector.files.directories[.runtime]),
                owner: getuid(), verifyCurrent: {}, verifyActivity: { _ in })
            let scope = try collector.scope(); defer { scope.close() }
            graph = try .init(observation: collector.collect(scope, journal: { input?.journal.intent?.files }), upgrade: collector.record,
                installedRelease: XCTUnwrap(collector.files.f.nativeRelease), currentPolicy: collector.files.preparation.source.host.codePolicy)
            let retained = try collector.files.f.machine.retainRuntimeAuditGraph(graph,
                installedRelease: XCTUnwrap(collector.files.f.nativeRelease), currentPolicy: collector.files.preparation.source.host.codePolicy)
            stored = try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: collector.files.f.machine, expected: retained,
                installedRelease: XCTUnwrap(collector.files.f.nativeRelease), currentPolicy: collector.files.preparation.source.host.codePolicy,
                directory: XCTUnwrap(collector.files.directories[.runtime]), owner: getuid(), verifyOwner: {})
        }
        func select() throws -> RuntimeAuditUpgradeCutoverRecord {
            try runtime.machine.selectRuntimeAuditCutover(graph, record: stored, installedRelease: release, currentPolicy: policy)
        }
        func advance(_ record: RuntimeAuditUpgradeCutoverRecord, _ phase: RuntimeAuditUpgradeCutoverRecord.Phase,
                     verify: () throws -> Void = {}) throws -> RuntimeAuditUpgradeCutoverRecord {
            try runtime.machine.advanceRuntimeAuditCutover(record, graph: graph, to: phase, installedRelease: release,
                currentPolicy: policy, verifyBarrierAndArtifacts: verify)
        }
        func verified() throws -> RuntimeAuditUpgradeCutoverRecord {
            let selected = try select(), changing = try advance(selected, .filesChanging)
            if let imported, let target = graph.snapshot.plan.sourceImport?.targetReference {
                let path = imported.runPath
                try target.encoded.write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o600), 0)
            }
            return try advance(changing, .filesVerified)
        }
        func commit(_ record: RuntimeAuditUpgradeCutoverRecord, verify: () throws -> Void = {},
                    update: (PreparationIntentStore.AuditCutoverMetadataStage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeCutoverRecord {
            try runtime.machine.commitRuntimeAuditCutover(record, graph: graph, installedRelease: release, currentPolicy: policy,
                verifyBarrierAndTargets: verify, didUpdate: update)
        }
        func assertTarget(_ test: XCTestCase) throws {
            let p = graph.snapshot.plan, machine = runtime.machine, account = runtime.account.accountID
            XCTAssertEqual(try machine.runtimePreparation(accountID: account).reference, p.preparation.intent.target)
            let foreground = try machine.runtimeActivation(accountID: account)
            XCTAssertEqual(try foreground.plan?.encoded, try p.preparation.target.encoded)
            XCTAssertEqual(foreground.jobsRegistered, p.sourceJobsRegistered)
            XCTAssertEqual(try machine.gatewayPreparation(accountID: account).reference, p.gateway.reference)
            XCTAssertEqual(try machine.gatewayJournalPreparation(accountID: account), p.gateway.journal)
            let gateway = try machine.gatewayRuntimeActivation(accountID: account)
            XCTAssertEqual(try gateway.plan?.encoded, try p.gateway.activation.plan?.encoded)
            XCTAssertEqual(gateway.filesPublished, p.gateway.activation.filesPublished)
            XCTAssertEqual(gateway.jobRegistered, p.gateway.activation.jobRegistered)
            let settings = try machine.gatewaySettingsTransition(accountID: account)
            XCTAssertEqual(try settings.active?.encoded, try p.gateway.settings.active?.encoded)
            XCTAssertEqual(try settings.pending?.encoded, try p.gateway.settings.pending?.encoded)
            XCTAssertEqual(settings.phase, p.sourceGateway.settings.phase)
            XCTAssertEqual(try machine.inventory(), p.sourceInventory)
            XCTAssertEqual(try machine.runtimeAuditUpgrade(accountID: account), graph.upgrade)
        }
    }
    func testCanonicalPublicCutoverRecordRejectsUnknownFieldsVersionsAndPhases() throws {
        let f = try Fixture(), record = try RuntimeAuditUpgradeCutoverRecord(graph: f.stored)
        XCTAssertEqual(try RuntimeAuditUpgradeCutoverRecord.decode(record.encoded), record)
        XCTAssertEqual(String(reflecting: record), "RuntimeAuditUpgradeCutoverRecord(redacted)")
        XCTAssertNil(try record.encoded.range(of: f.runtime.material.transportIdentity))
        let limits = try CBORLimits(maxBytes: 30720, maxDepth: 1, maxItems: 13)
        guard case .map(let fields) = try DeterministicCBOR.decode(record.encoded, limits: limits) else { return XCTFail() }
        for (key, value) in [(UInt64(0), CBORValue.unsigned(2)), (3, .unsigned(5)), (4, .bytes(Data())), (5, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try RuntimeAuditUpgradeCutoverRecord.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        XCTAssertThrowsError(try RuntimeAuditUpgradeCutoverRecord(graph: .init(upgrade: f.graph.upgrade, contentDigest: f.graph.digest)))
    }
    func testSelectionAdvancesOnlyTheSchemaAndRetainsHistoricalPreparationState() throws {
        let f = try Fixture(), before = try f.runtime.machine.retainedRuntimeCompatibilityInputs(), selected = try f.select()
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 14)
        XCTAssertEqual(selected.phase, .selected); XCTAssertEqual(try f.select(), selected)
        let after = try f.runtime.machine.retainedRuntimeCompatibilityInputs()
        XCTAssertEqual(after.runtimes, before.runtimes); XCTAssertEqual(after.gateways, before.gateways)
        XCTAssertEqual(after.inventory, before.inventory); XCTAssertEqual(after.auditUpgrades, before.auditUpgrades)
        XCTAssertEqual(after.auditCutovers, [selected]); XCTAssertEqual(after.auditGraphs, before.auditGraphs)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.runtime.machine)
        XCTAssertTrue(snapshot.requirements.formats.contains { $0.name == RuntimeAuditUpgradeCutoverRecord.formatName && $0.role == .authority })
        XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), selected)
    }
    func testStrictProgressAndUnknownReplyReplayDoNotSkipTheFileBoundary() throws {
        let f = try Fixture(), selected = try f.select()
        XCTAssertThrowsError(try f.advance(selected, .filesVerified))
        XCTAssertThrowsError(try f.commit(selected))
        let changing = try f.advance(selected, .filesChanging)
        XCTAssertEqual(try f.advance(selected, .filesChanging), changing)
        XCTAssertThrowsError(try f.advance(changing, .selected))
        let verified = try f.advance(changing, .filesVerified)
        XCTAssertEqual(try f.advance(changing, .filesVerified), verified)
        let stale = try RuntimeAuditUpgradeCutoverRecord(graph: selected.graph, phase: .filesVerified)
        XCTAssertThrowsError(try f.commit(stale))
    }
    func testForegroundCommitPreservesKeysEnrollmentAndPendingRegistration() throws {
        for registered in [false, true] {
            let f = try Fixture(registered: registered), verified = try f.verified()
            let result = try f.commit(verified)
            XCTAssertEqual(result.phase, .metadataCommitted); XCTAssertEqual(try f.commit(verified), result)
            try f.assertTarget(self)
            XCTAssertEqual(try f.runtime.machine.runtimeAuditGraphBytes(f.stored), f.graph.bytes)
            XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), result)
            let after = try f.runtime.machine.retainedRuntimeCompatibilityInputs()
            XCTAssertEqual(after.auditCutovers, [result]); XCTAssertEqual(after.auditUpgrades, [f.graph.upgrade])
        }
    }
    func testGatewayActiveAndPendingRevisionsMoveTogetherWithTheirExistingPhase() throws {
        for activeAndPending in [false, true] {
            let f = try Fixture(gateway: true, activeAndPending: activeAndPending), verified = try f.verified()
            let before = f.graph.snapshot.plan.sourceGateway, result = try f.commit(verified)
            try f.assertTarget(self)
            XCTAssertEqual(result.phase, .metadataCommitted)
            let settings = try f.runtime.machine.gatewaySettingsTransition(accountID: f.runtime.account.accountID)
            XCTAssertEqual(settings.active?.id, before.settings.active?.id)
            XCTAssertEqual(settings.pending?.id, before.settings.pending?.id)
            XCTAssertEqual(settings.phase, before.settings.phase)
            XCTAssertEqual(try settings.active?.selection.bytes, try before.settings.active?.selection.bytes)
            XCTAssertEqual(try settings.pending?.selection.bytes, try before.settings.pending?.selection.bytes)
        }
    }
    func testEveryMetadataStageRollsBackAllRowsIncludingTheCommitMarker() throws {
        for stop in PreparationIntentStore.AuditCutoverMetadataStage.allCases {
            let f = try Fixture(gateway: true, activeAndPending: true), verified = try f.verified()
            let before = try f.runtime.machine.retainedRuntimeCompatibilityInputs()
            XCTAssertThrowsError(try f.commit(verified, update: { if $0 == stop { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertEqual(try f.runtime.machine.retainedRuntimeCompatibilityInputs(), before)
            XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), verified)
            _ = try f.commit(verified); try f.assertTarget(self)
        }
    }
    func testExpiredBarrierRejectsProgressAndRollsBackLateMetadataWrites() throws {
        let f = try Fixture(gateway: true), selected = try f.select()
        XCTAssertThrowsError(try f.advance(selected, .filesChanging, verify: { throw Interrupted() }))
        XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), selected)
        let changing = try f.advance(selected, .filesChanging), verified = try f.advance(changing, .filesVerified)
        let before = try f.runtime.machine.retainedRuntimeCompatibilityInputs(); var valid = true
        XCTAssertThrowsError(try f.commit(verified, verify: { if !valid { throw Interrupted() } }, update: {
            if $0 == .gatewayActivation { valid = false }
        }))
        XCTAssertEqual(try f.runtime.machine.retainedRuntimeCompatibilityInputs(), before)
    }
    func testRelayReferenceMustBeReboundBeforeVerificationAndNeverRegeneratesPrivateCredentials() throws {
        for published in [false, true] {
            let imported = try RuntimeAuditUpgradeImportTests.Fixture(published: published), f = try Fixture(imported: imported)
            let selected = try f.select(), changing = try f.advance(selected, .filesChanging)
            let privateBytes = try XCTUnwrap(f.graph.snapshot.leaves.first { $0.entry.file.name == "relay-run-material.cbor" }?.source)
            if published {
                XCTAssertThrowsError(try f.advance(changing, .filesVerified))
                try XCTUnwrap(f.graph.snapshot.plan.sourceImport?.targetReference).encoded.write(to: URL(fileURLWithPath: imported.runPath))
                XCTAssertEqual(chmod(imported.runPath, 0o600), 0)
            }
            let verified = try f.advance(changing, .filesVerified); _ = try f.commit(verified)
            try f.assertTarget(self)
            XCTAssertEqual(try f.graph.snapshot.plan.sourceImport?.targetMaterial?.reference.credentialDigest,
                try f.graph.snapshot.plan.sourceImport?.sourceMaterial?.reference.credentialDigest)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: XCTUnwrap(f.collector.files.directories[.runtime]).path + "/relay-run-material.cbor")), privateBytes)
            if !published { XCTAssertFalse(FileManager.default.fileExists(atPath: imported.runPath)) }
        }
    }
    func testChangedSettingsOrImportPhaseCannotCommitTheSelectedGraph() throws {
        let f = try Fixture(gateway: true), verified = try f.verified()
        let pending = try XCTUnwrap(f.graph.snapshot.plan.sourceGateway.settings.pending)
        try f.runtime.machine.markGatewaySettingsTransition(pending, phase: .filesPublished)
        XCTAssertThrowsError(try f.commit(verified))
        XCTAssertEqual(try f.runtime.machine.runtimePreparation(accountID: f.runtime.account.accountID).reference, f.graph.upgrade.intent.source)
        let imported = try RuntimeAuditUpgradeImportTests.Fixture(), other = try Fixture(imported: imported), selected = try other.select()
        try other.runtime.machine.withSharedImportJournal { journal in
            _ = try XCTUnwrap(journal).advance(imported.expected, to: .gatewayPrepared)
        }
        XCTAssertThrowsError(try other.advance(selected, .filesChanging))
    }
    func testLostCommitReplyReopensWithTargetMetadataAndTheOriginalPreparationRecord() throws {
        let f = try Fixture(gateway: true, activeAndPending: true), verified = try f.verified()
        try f.runtime.machine.close(); var armed = false
        let writer = try f.runtime.f.open(hook: { if armed { throw Interrupted() } }); armed = true
        XCTAssertThrowsError(try writer.commitRuntimeAuditCutover(verified, graph: f.graph, installedRelease: f.release,
            currentPolicy: f.policy, verifyBarrierAndTargets: {})) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertThrowsError(try writer.runtimeAuditCutover(accountID: f.runtime.account.accountID)); try writer.close()
        let reopened = try f.runtime.f.open(); defer { try? reopened.close() }
        let committed = try XCTUnwrap(reopened.runtimeAuditCutover(accountID: f.runtime.account.accountID))
        XCTAssertEqual(committed.phase, .metadataCommitted)
        XCTAssertEqual(try reopened.runtimePreparation(accountID: f.runtime.account.accountID).reference, f.graph.upgrade.intent.target)
        XCTAssertEqual(try reopened.runtimeAuditUpgrade(accountID: f.runtime.account.accountID), f.graph.upgrade)
        XCTAssertEqual(try reopened.commitRuntimeAuditCutover(verified, graph: f.graph, installedRelease: f.release,
            currentPolicy: f.policy, verifyBarrierAndTargets: {}), committed)
        XCTAssertEqual(try reopened.retainedRuntimeCompatibilityInputs().auditCutovers, [committed])
    }
    func testUnstartedSelectionCanMoveToANewerGraphButStartedSelectionCannot() throws {
        let f = try Fixture(), selected = try f.select()
        let files = f.collector.files, source = try files.entry("runtime-material.cbor", files.plan())
        try files.write(f.runtime.material.encoded, source)
        let scope = try f.collector.scope(); defer { scope.close() }
        let newer = try RuntimeAuditUpgradeGraph(observation: f.collector.collect(scope), upgrade: f.collector.record,
            installedRelease: f.release, currentPolicy: f.policy)
        XCTAssertNotEqual(newer.digest, f.graph.digest)
        let retained = try f.runtime.machine.retainRuntimeAuditGraph(newer, installedRelease: f.release, currentPolicy: f.policy)
        let stored = try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: f.runtime.machine, expected: retained,
            installedRelease: f.release, currentPolicy: f.policy, directory: XCTUnwrap(files.directories[.runtime]), owner: getuid(), verifyOwner: {})
        XCTAssertThrowsError(try f.runtime.machine.selectRuntimeAuditCutover(newer, record: stored, installedRelease: f.release, currentPolicy: f.policy))
        let replacement = try f.runtime.machine.selectRuntimeAuditCutover(newer, record: stored, replacing: selected,
            installedRelease: f.release, currentPolicy: f.policy)
        XCTAssertNotEqual(replacement.revision, selected.revision)
        _ = try f.runtime.machine.advanceRuntimeAuditCutover(replacement, graph: newer, to: .filesChanging,
            installedRelease: f.release, currentPolicy: f.policy, verifyBarrierAndArtifacts: {})
        XCTAssertThrowsError(try f.runtime.machine.selectRuntimeAuditCutover(f.graph, record: f.stored, replacing: replacement,
            installedRelease: f.release, currentPolicy: f.policy))
        XCTAssertEqual(try f.runtime.machine.runtimeAuditGraphBytes(f.stored), f.graph.bytes)
    }
    func testSourceReadersDoNotAcceptAnUncommittedTargetReference() throws {
        let f = try Fixture(), verified = try f.verified(), target = f.graph.upgrade.intent.target
        let encoded = try target.encoded.map { String(format: "%02x", $0) }.joined()
        let digest = target.materialDigest.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(try f.runtime.f.sql("UPDATE runtime_preparation_v1 SET digest=x'" + digest + "',record=x'" + encoded + "'"), 0)
        XCTAssertThrowsError(try f.runtime.machine.runtimeAuditUpgrade(accountID: f.runtime.account.accountID))
        XCTAssertThrowsError(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID))
        XCTAssertThrowsError(try f.commit(verified))
    }
    func testCorruptCutoverColumnsCannotBecomeARecoveryRecord() throws {
        let f = try Fixture(); _ = try f.select()
        XCTAssertEqual(try f.runtime.f.sql("UPDATE runtime_audit_cutover_v1 SET phase=4"), 0)
        XCTAssertThrowsError(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID))
        XCTAssertThrowsError(try f.runtime.machine.retainedRuntimeCompatibilityInputs())
    }
    func testAnotherSignedReleaseWithTheSameCapabilitiesCannotDriveTheRetainedCutover() throws {
        let f = try Fixture()
        let otherRelease = try NativeHostReleaseFixture.make(policy: f.policy, phoneAudit: true, auditDelivery: true, edit: { component in
            guard component.role == .app else { return component }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: component.formats + [.init(name: "fixture.extra", readers: [1], writers: [])])
        })
        try RuntimeAuditUpgradeCutoverRecord.validateCapabilities(otherRelease, policy: f.policy)
        XCTAssertNotEqual(try InstallationInventory.digest(otherRelease), f.graph.upgrade.intent.source.services.releaseDigest)
        XCTAssertThrowsError(try f.runtime.machine.selectRuntimeAuditCutover(f.graph, record: f.stored,
            installedRelease: otherRelease, currentPolicy: f.policy))
        XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 13)
        let selected = try f.select(); var checks = 0
        XCTAssertThrowsError(try f.runtime.machine.advanceRuntimeAuditCutover(selected, graph: f.graph, to: .filesChanging,
            installedRelease: otherRelease, currentPolicy: f.policy, verifyBarrierAndArtifacts: { checks += 1 }))
        XCTAssertEqual(checks, 0)
        let changing = try f.advance(selected, .filesChanging), verified = try f.advance(changing, .filesVerified)
        XCTAssertThrowsError(try f.runtime.machine.commitRuntimeAuditCutover(verified, graph: f.graph,
            installedRelease: otherRelease, currentPolicy: f.policy, verifyBarrierAndTargets: { checks += 1 }))
        XCTAssertEqual(checks, 0)
        XCTAssertEqual(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID), verified)
    }
    func testAChangedPreparationRecordCannotMatchTheSelectedGraph() throws {
        let f = try Fixture(); _ = try f.select()
        let changed = try RuntimeAuditUpgradeRecord(intent: f.graph.upgrade.intent, phase: .retained)
        let encoded = try changed.encoded, digest = Data(SHA256.hash(data: encoded))
        let hex: (Data) -> String = { $0.map { String(format: "%02x", $0) }.joined() }
        XCTAssertEqual(try f.runtime.f.sql("UPDATE runtime_audit_upgrade_v1 SET revision=x'" + hex(changed.revision) +
            "',phase=1,digest=x'" + hex(digest) + "',record=x'" + hex(encoded) + "'"), 0)
        XCTAssertThrowsError(try f.runtime.machine.runtimeAuditCutover(accountID: f.runtime.account.accountID))
        XCTAssertThrowsError(try f.runtime.machine.retainedRuntimeCompatibilityInputs())
    }
    func testPartialGatewayPreparationRemainsPartialAfterTheMetadataCommit() throws {
        let f = try Fixture(partialGateway: true), verified = try f.verified(); _ = try f.commit(verified)
        try f.assertTarget(self)
        XCTAssertNotNil(try f.runtime.machine.gatewayPreparation(accountID: f.runtime.account.accountID).reference)
        XCTAssertNil(try f.runtime.machine.gatewayJournalPreparation(accountID: f.runtime.account.accountID).intent)
        let gateway = try f.runtime.machine.gatewayRuntimeActivation(accountID: f.runtime.account.accountID)
        XCTAssertNil(gateway.plan); XCTAssertFalse(gateway.filesPublished); XCTAssertFalse(gateway.jobRegistered)
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.runtime.machine)
        try snapshot.validate(f.release, policy: f.policy, machine: f.runtime.machine)
    }
    func testReboundPendingSettingsCanCompleteWithoutReplayingTheOldUpgrade() throws {
        let f = try Fixture(gateway: true, activeAndPending: true), verified = try f.verified(); _ = try f.commit(verified)
        let pending = try XCTUnwrap(f.runtime.machine.gatewaySettingsTransition(accountID: f.runtime.account.accountID).pending)
        try f.runtime.machine.markGatewaySettingsTransition(pending, phase: .filesPublished)
        try f.runtime.machine.markGatewaySettingsTransition(pending, phase: .consumersObserved)
        try f.runtime.machine.completeGatewaySettingsTransition(pending)
        let current = try f.runtime.machine.gatewaySettingsTransition(accountID: f.runtime.account.accountID)
        XCTAssertNil(current.pending); XCTAssertNil(current.phase)
        XCTAssertEqual(try current.active?.encoded, try pending.encoded)
        XCTAssertEqual(try f.runtime.machine.runtimeAuditUpgrade(accountID: f.runtime.account.accountID), f.graph.upgrade)
        XCTAssertThrowsError(try f.commit(verified))
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.runtime.machine)
        try snapshot.validate(f.release, policy: f.policy, machine: f.runtime.machine)
    }
    func testMissingCutoverCapabilityRefusesBeforeSchemaMutation() throws {
        let f = try Fixture()
        for role in [AuthorityCodeRole.authority, .setupController] {
            let release = try NativeHostReleaseFixture.make(policy: f.policy, phoneAudit: true, auditDelivery: true, edit: { component in
                guard component.role == role else { return component }
                return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                    relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                    teamID: component.teamID, formats: component.formats.filter { $0.name != RuntimeAuditUpgradeCutoverRecord.formatName })
            })
            XCTAssertThrowsError(try f.runtime.machine.selectRuntimeAuditCutover(f.graph, record: f.stored,
                installedRelease: release, currentPolicy: f.policy))
            XCTAssertEqual(try f.runtime.f.sql("PRAGMA user_version"), 13)
        }
    }
}
