import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Disposable material and owned files only. No native service ownership, journal quiescence or live cutover is qualified.
final class RuntimeAuditUpgradeArtifactTests: XCTestCase {
    final class Fixture {
        let f: RuntimeActivationFixture
        let preparation: RuntimeAuditUpgradePreparation
        let inventory: InstallationInventory
        let clients: RuntimeActivationClients
        var directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory] = [:]
        init(imported: RuntimeAuditUpgradeImportTests.Fixture? = nil) throws {
            if let imported { f = imported.runtime; preparation = imported.preparation; inventory = imported.inventory }
            else { (f, preparation, inventory) = try RuntimeAuditUpgradeDependenciesTests().fixture() }
            let bundle = try preparation.source.configurationBundle(account: f.account,
                initialization: XCTUnwrap(f.machine.initialization(accountID: f.account.accountID)), inventory: inventory)
            clients = .init(presence: bundle.presenceClient, pairing: bundle.pairingClient, frontend: bundle.frontendClient)
            guard chmod(f.f.root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            for area in RuntimeAuditUpgradeArtifactPlan.Directory.allCases {
                if area == .imports, let imported { directories[area] = imported.directory; continue }
                let visibility: ProtectedSetupDirectory.Visibility = area == .runtime || area == .imports ? .privateState : .sharedMetadata
                directories[area] = try .init(anchor: f.f.root.path, relativePath: "artifacts-\(area.rawValue)", owner: getuid(), visibility: visibility)
            }
        }
        deinit { for d in directories.values { d.close() } }
        func plan(gateway: RuntimeAuditUpgradeArtifactPlan.GatewayInputs = .empty,
                  imported: RuntimeAuditUpgradeImportPreparation? = nil,
                  transport: RelayRunCredentialReference? = nil) throws -> RuntimeAuditUpgradeArtifactPlan {
            try .init(preparation, material: f.material, account: f.account,
                initialization: XCTUnwrap(f.machine.initialization(accountID: f.account.accountID)), inventory: inventory,
                clients: clients, installedRelease: XCTUnwrap(f.nativeRelease), gateway: gateway, imported: imported,
                transportRelayReference: transport)
        }
        func install(_ plan: RuntimeAuditUpgradeArtifactPlan, pending: Bool = false, omitOptional: Bool = false) throws {
            for entry in plan.entries {
                let selected = pending ? entry.variants.last(where: { $0.source != nil }) : entry.variants.first
                let bytes = omitOptional && entry.variants.contains(where: { $0.source == nil }) ? nil : selected?.source
                if let bytes { try write(bytes, entry) }
            }
        }
        func write(_ bytes: Data, _ entry: RuntimeAuditUpgradeArtifactPlan.Entry) throws {
            let path = try XCTUnwrap(directories[entry.directory]).path + "/" + entry.file.name
            try bytes.write(to: URL(fileURLWithPath: path))
            guard chown(path, getuid(), getgid()) == 0, chmod(path, entry.file.mode) == 0 else { throw JournalLeaseError.system(errno) }
        }
        func snapshot(_ plan: RuntimeAuditUpgradeArtifactPlan, verify: () throws -> Void = {}) throws -> RuntimeAuditUpgradeArtifactSnapshot {
            try .capture(plan, directories: directories, owner: getuid(), ownership: .ordinaryOwnerFixture, verifyCurrent: verify)
        }
        func entry(_ name: String, _ plan: RuntimeAuditUpgradeArtifactPlan) throws -> RuntimeAuditUpgradeArtifactPlan.Entry {
            try XCTUnwrap(plan.entries.first { $0.file.name == name })
        }
        func gateway(activated: Bool = true, initialized: Bool = true) throws -> RuntimeAuditUpgradeArtifactPlan.GatewayInputs {
            let helper = RuntimeAuditUpgradeDependenciesTests(), material = try helper.gateway(preparation)
            let ready = try helper.journal(material, preparation, inventory)
            let journal = GatewayJournalPreparationState(intent: ready.intent, initialized: initialized)
            let activation = try activated ? GatewayRuntimeActivationPlan(journal: journal, foreground: preparation.source,
                inventory: inventory, wakePollMilliseconds: 777, wakeTimeoutMilliseconds: 8888) : nil
            let service = try GatewayJournalSetupServiceConfiguration(intent: XCTUnwrap(journal.intent),
                bundlePath: inventory.bundlePath, codePolicy: preparation.source.host.codePolicy, maximumLifetimeMilliseconds: 45678)
            return try .init(material: material, reference: material.reference, journal: journal,
                activation: .init(plan: activation, filesPublished: activated, jobRegistered: activated), settings: .empty, service: service, fence: nil)
        }
    }
    func testAuditMaterialBindingUsesTheExactIntentAndPrivateMetadata() throws {
        let id = Data(repeating: 0xab, count: 16)
        let file = AdministrativeSetupPublication.File.auditUpgradeMaterial(intentID: id)
        try file.validate()
        XCTAssertEqual(file.name, "runtime-audit-upgrade-" + String(repeating: "ab", count: 16) + ".cbor")
        XCTAssertEqual(file.mode, 0o600)
        XCTAssertFalse(file.requiresSharedDirectory)
        XCTAssertNil(file.groupID)
        XCTAssertEqual(file.fileOwner(processOwner: getuid()), getuid())
    }
    func testAuditMaterialBindingRejectsEveryWrongIntentLength() {
        for count in [0, 1, 15, 17, 32] {
            let file = AdministrativeSetupPublication.File.auditUpgradeMaterial(intentID: Data(repeating: 0, count: count))
            XCTAssertThrowsError(try file.validate()) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .invalidArtifact)
            }
        }
    }
    func testAuditMaterialBindingsKeepDistinctIntentsSeparate() throws {
        let first = AdministrativeSetupPublication.File.auditUpgradeMaterial(intentID: Data(repeating: 1, count: 16))
        let second = AdministrativeSetupPublication.File.auditUpgradeMaterial(intentID: Data(repeating: 2, count: 16))
        try first.validate()
        try second.validate()
        XCTAssertNotEqual(first.name, second.name)
        XCTAssertFalse(first.name.contains("/"))
        XCTAssertFalse(second.name.contains("/"))
    }
    func testClosedForegroundSetKeepsKeysClientsJobsAndAbsences() throws {
        let f = try Fixture(), plan = try f.plan(); try f.install(plan, omitOptional: true)
        let snapshot = try f.snapshot(plan)
        XCTAssertEqual(Set(plan.entries.map(\.key)).count, plan.entries.count)
        XCTAssertEqual(Set(plan.entries.map(\.directory)), Set(RuntimeAuditUpgradeArtifactPlan.Directory.allCases))
        XCTAssertGreaterThanOrEqual(plan.entries.count, 34)
        for leaf in snapshot.leaves where leaf.entry.directory == .clients {
            XCTAssertEqual(leaf.source, leaf.target); XCTAssertNotNil(leaf.metadata)
        }
        let identity = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "transport-identity.cbor" })
        XCTAssertEqual(identity.source, f.f.material.transportIdentity); XCTAssertEqual(identity.source, identity.target)
        let runtime = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "runtime-material.cbor" })
        XCTAssertEqual(try RuntimePreparationMaterial.decode(XCTUnwrap(runtime.target)).reference, f.preparation.intent.target)
        XCTAssertNotEqual(runtime.sourceDigest, runtime.targetDigest)
        XCTAssertTrue(snapshot.leaves.filter { $0.entry.directory == .imports }.allSatisfy { $0.source == nil && $0.target == nil })
        XCTAssertNil(plan.gateway.reference); XCTAssertFalse(plan.gateway.journal.initialized)
        XCTAssertEqual(plan.sourceAccount, f.f.account); XCTAssertEqual(plan.sourceInventory, f.inventory)
        XCTAssertEqual(plan.sourceInitialization.accountID, f.f.account.accountID)
        XCTAssertNil(plan.sourceImport)
        XCTAssertEqual(String(reflecting: plan), "RuntimeAuditUpgradeArtifactPlan(redacted)")
        XCTAssertEqual(String(reflecting: snapshot), "RuntimeAuditUpgradeArtifactSnapshot(redacted)")
        XCTAssertEqual(Mirror(reflecting: snapshot).children.count, 0)
    }
    func testPartialGatewaySetupRetainsJournalIdentityLifetimeAndMissingFiles() throws {
        let f = try Fixture(), source = try f.gateway(activated: false, initialized: false), plan = try f.plan(gateway: source)
        try f.install(plan, omitOptional: true)
        let snapshot = try f.snapshot(plan)
        XCTAssertFalse(plan.gateway.journal.initialized); XCTAssertNil(plan.gateway.activation.plan)
        XCTAssertEqual(plan.gateway.journal.intent?.files, source.journal.intent?.files)
        XCTAssertEqual(plan.sourceGateway.journal, source.journal)
        XCTAssertEqual(plan.gateway.journal.intent?.id, source.journal.intent?.id)
        XCTAssertEqual(plan.gateway.service?.maximumLifetimeMilliseconds, 45678)
        XCTAssertEqual(plan.gateway.reference?.runtime, f.preparation.intent.target)
        for leaf in snapshot.leaves where ["gateway-provider.json", "gateway-receipt-key.cbor", "transport-wake-key.cbor"].contains(leaf.entry.file.name) {
            XCTAssertNotNil(leaf.source); XCTAssertEqual(leaf.source, leaf.target)
        }
        let service = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == GatewayJournalSetupServiceConfiguration.fileName })
        let decoded = try GatewayJournalSetupServiceConfiguration.decode(XCTUnwrap(service.target))
        XCTAssertEqual(decoded.maximumLifetimeMilliseconds, 45678); XCTAssertEqual(decoded.intent.files, source.journal.intent?.files)
        XCTAssertTrue(snapshot.leaves.filter { if case .gatewayJournalJob = $0.entry.file { true } else { false } }.allSatisfy { $0.source == nil && $0.target == nil })
    }
    func testPrivateGatewayPublicationBeforeJournalRetentionPreservesMissingLeaves() throws {
        let f = try Fixture(), material = try RuntimeAuditUpgradeDependenciesTests().gateway(f.preparation)
        let input = try RuntimeAuditUpgradeArtifactPlan.GatewayInputs(material: material, reference: material.reference,
            journal: .init(intent: nil, initialized: false), activation: .init(plan: nil, filesPublished: false, jobRegistered: false),
            settings: .empty, service: nil, fence: nil)
        let plan = try f.plan(gateway: input); try f.install(plan, omitOptional: true)
        let snapshot = try f.snapshot(plan)
        XCTAssertNotNil(plan.gateway.reference); XCTAssertNil(plan.gateway.journal.intent)
        let provider = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "gateway-provider.json" })
        XCTAssertNil(provider.source); XCTAssertNil(provider.target)
    }
    func testRetainedJournalCannotTreatMissingPrivateFilesAsPartialPublication() throws {
        let f = try Fixture(), input = try f.gateway(activated: false, initialized: false), plan = try f.plan(gateway: input)
        try f.install(plan)
        let provider = try f.entry("gateway-provider.json", plan)
        let path = try XCTUnwrap(f.directories[provider.directory]).path + "/" + provider.file.name
        XCTAssertEqual(unlink(path), 0)
        XCTAssertThrowsError(try f.snapshot(plan))
    }
    func testUnreferencedGatewayMaterialDoesNotInventPreparationOrInitialization() throws {
        let f = try Fixture(), material = try RuntimeAuditUpgradeDependenciesTests().gateway(f.preparation)
        let input = RuntimeAuditUpgradeArtifactPlan.GatewayInputs(material: material, reference: nil,
            journal: .init(intent: nil, initialized: false), activation: .init(plan: nil, filesPublished: false, jobRegistered: false),
            settings: .empty, service: nil, fence: nil)
        let plan = try f.plan(gateway: input); try f.install(plan, omitOptional: true)
        let value = try f.snapshot(plan)
        XCTAssertNotNil(plan.gateway.material); XCTAssertNil(plan.gateway.reference); XCTAssertNil(plan.gateway.journal.intent)
        let leaf = try XCTUnwrap(value.leaves.first { $0.entry.file.name == "gateway-material.cbor" })
        XCTAssertEqual(try GatewayPreparationMaterial.decode(XCTUnwrap(leaf.target)).runtime, f.preparation.intent.target)
    }
    func testActiveAndPendingFileVariantsMapToTheirCorrespondingTargetAcrossEveryPhase() throws {
        let f = try Fixture(), input = try f.gateway(), activation = try XCTUnwrap(input.activation.plan)
        let activeSelection = try GatewaySetupForm().settingsSelection()
        let active = try GatewayRuntimeSettingsRevision(id: Data(repeating: 1, count: 16), selection: activeSelection,
            activation: activation, previous: nil, journal: input.journal, foreground: f.preparation.source, inventory: f.inventory)
        let pending = try GatewayRuntimeSettingsRevision(id: Data(repeating: 2, count: 16), selection: activeSelection,
            activation: activation, previous: active, journal: input.journal, foreground: f.preparation.source, inventory: f.inventory)
        let publication = try GatewayRuntimeSettingsPublicationPlan(revision: pending, previous: active, activation: activation,
            journal: input.journal, foreground: f.preparation.source, inventory: f.inventory)
        for phase in GatewayRuntimeSettingsPhase.allCases {
            let selected = RuntimeAuditUpgradeArtifactPlan.GatewayInputs(material: input.material, reference: input.reference,
                journal: input.journal, activation: input.activation, settings: .init(active: active, pending: pending, phase: phase),
                service: input.service, fence: try .init(publication))
            let plan = try f.plan(gateway: selected)
            for entry in plan.entries {
                for variant in entry.variants where variant.source != nil {
                    let lone = try XCTUnwrap(variant.source)
                    try f.write(lone, entry)
                }
            }
            let snapshot = try f.snapshot(plan)
            XCTAssertEqual(plan.gateway.settings.phase, phase); XCTAssertEqual(plan.gateway.settings.active?.id, active.id)
            XCTAssertEqual(plan.gateway.settings.pending?.id, pending.id)
            let revision = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "gateway-settings-revision.cbor" })
            XCTAssertEqual(try GatewayRuntimeSettingsRevision.decode(XCTUnwrap(revision.target)).id, pending.id)
            let authority = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "authority-gateway-runtime.cbor" })
            XCTAssertEqual(try GatewayRuntimeExtension.decode(XCTUnwrap(authority.target)).material.runtime, f.preparation.intent.target)
        }
    }
    func testRelayRebindsBothReferencesAndKeepsPrivateTokenAndProviderRecords() throws {
        let imported = try RuntimeAuditUpgradeImportTests.Fixture(), f = try Fixture(imported: imported), capture = try imported.capture()
        let plan = try f.plan(imported: capture, transport: imported.relay.material.reference); try f.install(plan)
        let snapshot = try f.snapshot(plan)
        XCTAssertEqual(plan.sourceImport?.source, capture.source)
        for leaf in snapshot.leaves where leaf.entry.directory == .imports && leaf.entry.file.name != AdministrativeSetupPublication.File.importRelayRunReference(accountID: f.f.account.accountID).name {
            XCTAssertEqual(leaf.source, leaf.target)
        }
        let transport = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "transport-relay-reference.cbor" })
        XCTAssertEqual(try RelayRunCredentialReference.decodeForTransport(XCTUnwrap(transport.target), runtime: f.preparation.intent.target,
            relayPort: 51001), try capture.targetMaterial?.reference)
        let token = try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "transport-tunnel.token" })
        XCTAssertEqual(token.source, token.target); XCTAssertNotNil(token.metadata)
    }
    func testImportSnapshotIdentityCannotBeReboundToAnIdenticalReplacement() throws {
        let imported = try RuntimeAuditUpgradeImportTests.Fixture(), f = try Fixture(imported: imported), capture = try imported.capture()
        let plan = try f.plan(imported: capture); try f.install(plan)
        let file = AdministrativeSetupPublication.File.importRelayPlan(accountID: f.f.account.accountID)
        let entry = try f.entry(file.name, plan), path = imported.directory.path + "/" + file.name
        let original = try Data(contentsOf: URL(fileURLWithPath: path))
        try FileManager.default.moveItem(atPath: path, toPath: path + ".retained")
        try f.write(original, entry)
        XCTAssertThrowsError(try f.snapshot(plan)) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
    }
    func testUnpublishedRelayMaterialKeepsBothReferencesAbsent() throws {
        let imported = try RuntimeAuditUpgradeImportTests.Fixture(published: false), f = try Fixture(imported: imported)
        let plan = try f.plan(imported: imported.capture()); try f.install(plan, omitOptional: true)
        let snapshot = try f.snapshot(plan)
        for leaf in snapshot.leaves where leaf.entry.file.name == "transport-relay-reference.cbor" || leaf.entry.file.name.hasPrefix("import-relay-run-") {
            XCTAssertNil(leaf.source); XCTAssertNil(leaf.target)
        }
        XCTAssertNotNil(try XCTUnwrap(snapshot.leaves.first { $0.entry.file.name == "relay-run-material.cbor" }).target)
    }
    func testMissingRequiredChangedAndIdenticallyReplacedLeavesInvalidateSnapshot() throws {
        for action in 0...2 {
            let f = try Fixture(), plan = try f.plan(); try f.install(plan)
            let snapshot = try f.snapshot(plan), entry = try f.entry("command-runtime.cbor", plan)
            let path = try XCTUnwrap(f.directories[entry.directory]).path + "/" + entry.file.name
            let original = try Data(contentsOf: URL(fileURLWithPath: path))
            if action == 0 { XCTAssertEqual(unlink(path), 0) }
            else if action == 1 { try f.write(Data("changed".utf8), entry) }
            else { try FileManager.default.moveItem(atPath: path, toPath: path + ".retained"); try f.write(original, entry) }
            XCTAssertThrowsError(try snapshot.validate(directories: f.directories, owner: getuid(), ownership: .ordinaryOwnerFixture, verifyCurrent: {}))
        }
    }
    func testVerifiedAbsenceCannotBecomeAFileAndOtherAccountsStayIndependent() throws {
        let f = try Fixture(), plan = try f.plan(); try f.install(plan)
        let other = AdministrativeSetupPublication.File.importRelayPlan(accountID: Data(repeating: 99, count: 16))
        let path = try XCTUnwrap(f.directories[.imports]).path + "/" + other.name
        try Data("other account fixture".utf8).write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o600), 0)
        let snapshot = try f.snapshot(plan)
        XCTAssertFalse(snapshot.leaves.contains { $0.entry.file.name == other.name })
        let absent = try f.entry("gateway-material.cbor", plan); try f.write(Data("unexpected".utf8), absent)
        XCTAssertThrowsError(try snapshot.validate(directories: f.directories, owner: getuid(), ownership: .ordinaryOwnerFixture, verifyCurrent: {}))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("other account fixture".utf8))
    }
    func testSymlinkWrongModeAndScopeChangeRefuseCapture() throws {
        for action in 0...2 {
            let f = try Fixture(), plan = try f.plan(); try f.install(plan)
            let entry = try f.entry("command-runtime.cbor", plan), path = try XCTUnwrap(f.directories[.runtime]).path + "/" + entry.file.name
            if action == 0 { XCTAssertEqual(unlink(path), 0); XCTAssertEqual(symlink("/tmp/absent-remozio-artifact", path), 0) }
            else if action == 1 { XCTAssertEqual(chmod(path, 0o644), 0) }
            if action < 2 { XCTAssertThrowsError(try f.snapshot(plan)) }
            else { XCTAssertThrowsError(try f.snapshot(plan, verify: { throw RuntimePreparationError.changedScope })) }
        }
    }
    func testMissingImportDirectoryIsObservedWithoutCreationAndCannotAppearLater() throws {
        let f = try Fixture(), plan = try f.plan(); try f.install(plan)
        let unused = try XCTUnwrap(f.directories.removeValue(forKey: .imports)); unused.close()
        let machine = try ProtectedSetupDirectory(anchor: f.f.f.root.path, relativePath: "missing-import-parent", owner: getuid())
        defer { machine.close() }
        let missing = try RuntimeAuditUpgradeArtifactSnapshot.MissingImports.observe(machine: machine,
            owner: getuid(), ownership: .ordinaryOwnerFixture, verifyCurrent: {})
        let snapshot = try RuntimeAuditUpgradeArtifactSnapshot.capture(plan, directories: f.directories, owner: getuid(),
            ownership: .ordinaryOwnerFixture, missingImports: missing, verifyCurrent: {})
        XCTAssertTrue(snapshot.leaves.filter { $0.entry.directory == .imports }.allSatisfy { $0.source == nil && $0.target == nil })
        XCTAssertFalse(FileManager.default.fileExists(atPath: machine.path + "/SharedSetupImport"))
        try FileManager.default.createDirectory(atPath: machine.path + "/SharedSetupImport", withIntermediateDirectories: false)
        XCTAssertThrowsError(try snapshot.validate(directories: f.directories, owner: getuid(), ownership: .ordinaryOwnerFixture,
            missingImports: missing, verifyCurrent: {}))
    }
    func testEmptyImportDirectoryCannotBeReplacedByAnotherEmptyDirectory() throws {
        let f = try Fixture(), plan = try f.plan(); try f.install(plan)
        let snapshot = try f.snapshot(plan), first = try XCTUnwrap(f.directories[.imports])
        let other = try ProtectedSetupDirectory(anchor: f.f.f.root.path, relativePath: "other-import-parent", owner: getuid())
        defer { other.close() }
        f.directories[.imports] = other
        XCTAssertThrowsError(try snapshot.validate(directories: f.directories, owner: getuid(), ownership: .ordinaryOwnerFixture, verifyCurrent: {}))
        first.close()
    }
    func testNativeOwnershipRefusesBeforeCallbacksOrDirectoryAccess() throws {
        let f = try Fixture(), plan = try f.plan(); var calls = 0
        XCTAssertThrowsError(try RuntimeAuditUpgradeArtifactSnapshot.capture(plan, directories: [:], owner: 0,
            ownership: .native, verifyCurrent: { calls += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(calls, 0)
        XCTAssertThrowsError(try RuntimeAuditUpgradeArtifactSnapshot.capture(plan, directories: [:], owner: getuid(),
            ownership: .ordinaryOwnerFixture, verifyCurrent: {}))
    }
}
