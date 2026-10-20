import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned files prove validation and recovery mechanics. Production Root and service ownership remain unproven.
private final class ImportedRuntimeFixture {
    let runtime: RuntimeActivationFixture
    let directory: URL
    var published = 0
    var validated = 0
    init() throws {
        runtime = try .init()
        directory = runtime.f.root.appendingPathComponent("ImportedRuntimeArtifacts")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    func proposal() throws -> PortableSetup {
        let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 540_000, observationLifetimeMilliseconds: 7000,
            unavailableGraceMilliseconds: 45_000), gateway: GatewaySetupForm().settingsSelection())
        return .init(defaults: defaults)
    }
    func intent() throws -> SharedSetupImportIntent {
        try .init(scope: .init(account: runtime.account, inventory: XCTUnwrap(runtime.machine.inventory())), proposal: proposal())
    }
    func journal(initialize: Bool = false, hook: (() throws -> Void)? = nil) throws -> SharedSetupImportJournal {
        let f = runtime.f
        if initialize { try f.prepare("machine/SharedSetupImport", .sharedSetupImport) }
        return try .init(lease: .init(anchor: f.root.path, relativeDirectory: "machine/SharedSetupImport", owner: getuid(),
            ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(), macID: runtime.account.macID,
            installationID: runtime.account.installationID, initialize: initialize, didCommit: hook)
    }
    func retain() throws -> SharedSetupImportIntent {
        let value = try intent(), store = try journal(initialize: true); defer { try? store.close() }
        try store.begin(value); return value
    }
    func state() throws -> RuntimePreparationState { try runtime.machine.runtimePreparation(accountID: runtime.account.accountID) }
    func progress() throws -> SharedSetupImportIntent {
        let store = try journal(); defer { try? store.close() }
        return try XCTUnwrap(store.current(scope: intent().scope))
    }
    func bundle(_ intent: SharedSetupImportIntent) throws -> RuntimeConfigurationBundle {
        try .initial(account: runtime.account, initialization: XCTUnwrap(runtime.machine.initialization(accountID: runtime.account.accountID)),
            reference: runtime.material.reference, inventory: XCTUnwrap(runtime.machine.inventory()), importIntent: intent)
    }
    func path(_ artifact: RuntimePublishedArtifactValidation.Artifact) -> URL {
        directory.appendingPathComponent(SHA256.hash(data: Data(artifact.path.utf8)).map { String(format: "%02x", $0) }.joined())
    }
    func write(_ bundle: RuntimeConfigurationBundle) throws {
        published += 1
        for artifact in try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: runtime.material) {
            let target = path(artifact)
            if FileManager.default.fileExists(atPath: target.path) {
                guard try Data(contentsOf: target) == artifact.bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
            } else { try artifact.bytes.write(to: target); XCTAssertEqual(chmod(target.path, 0o600), 0) }
        }
    }
    func read(_ artifact: RuntimePublishedArtifactValidation.Artifact) throws -> Data {
        try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: path(artifact).lastPathComponent, owner: getuid())
    }
    func execute(_ imported: SharedSetupImportIntent?, _ verify: () throws -> Void,
                 expected: RuntimePreparationState, allowPublication: Bool = true,
                 stage: (RuntimePublicationController.Stage) throws -> Void = { _ in }) throws -> RuntimePreparationState {
        try withoutActuallyEscaping(verify) { verify in
            try RuntimePublicationController.prepare(machine: runtime.machine, account: runtime.account, expected: expected,
                importIntent: imported, verifyCurrent: verify, verifyServices: { _ in }, verifyAuthority: { _ in },
                restoreMaterial: { _, retained, verify in
                    try verify(); XCTAssertEqual(retained, try self.runtime.material.reference); return self.runtime.material
                }, publish: { bundle, _, verify in
                    try verify(); guard allowPublication else { return XCTFail("Republished completed runtime") }
                    try self.write(bundle); try verify()
                }, validatePublishedImport: { bundle, material, verify in
                    self.validated += 1
                    try RuntimePublishedArtifactValidation.validate(bundle: bundle, material: material, verifyCurrent: verify, read: self.read)
                }, didStage: stage)
        }
    }
    func run(allowPublication: Bool = true,
             stage: (RuntimePublicationController.Stage) throws -> Void = { _ in }) throws -> RuntimePreparationState {
        let expected = try state()
        return try runtime.machine.withSharedImportJournal { journal in
            try SharedSetupImportRuntimePreparation.prepare(machine: runtime.machine, account: runtime.account,
                expected: expected, journal: journal, verifyCurrent: {}) { imported, verify in
                try self.execute(imported, verify, expected: expected, allowPublication: allowPublication, stage: stage)
            }
        }
    }
}

final class SharedSetupImportRuntimePreparationTests: XCTestCase {
    private struct Interrupted: Error {}
    func testNoImportPreservesLegacyPreparationWithoutCreatingAnImportDirectory() throws {
        let f = try ImportedRuntimeFixture(), before = try f.state()
        XCTAssertEqual(try f.run(allowPublication: false), before)
        XCTAssertEqual(f.published, 0); XCTAssertEqual(f.validated, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.runtime.f.root.path + "/machine/SharedSetupImport"))
    }
    func testNoImportAlsoPreservesInitialPublicationAndDoesNotCreateImportState() throws {
        let f = try ImportedRuntimeFixture()
        _ = try f.runtime.f.sql("UPDATE runtime_preparation_v1 SET complete=0")
        XCTAssertTrue(try f.run().configurationPublished)
        XCTAssertEqual(f.published, 1); XCTAssertEqual(f.validated, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.runtime.f.root.path + "/machine/SharedSetupImport"))
    }
    func testChangedLocalScopeDoesNotFallBackToPublishingDefaults() throws {
        let f = try ImportedRuntimeFixture(), limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        guard case var .map(fields) = try DeterministicCBOR.decode(f.runtime.account.bytes, limits: limits) else { return XCTFail("Missing account") }
        fields[2] = .bytes(Data(repeating: 29, count: 16))
        let changed = try AccountPreparationIntent.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        let intent = try SharedSetupImportIntent(scope: .init(account: changed, inventory: XCTUnwrap(f.runtime.machine.inventory())),
            proposal: f.proposal())
        let journal = try f.journal(initialize: true); try journal.begin(intent); try journal.close()
        _ = try f.runtime.f.sql("UPDATE runtime_preparation_v1 SET complete=0")
        XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        XCTAssertEqual(f.published, 0); XCTAssertEqual(f.validated, 0)
        XCTAssertFalse(try f.state().configurationPublished)
    }
    func testInitialImportPublishesReviewedPolicyAndMarksOnlyVerifiedRuntime() throws {
        let f = try ImportedRuntimeFixture(), intent = try f.retain()
        _ = try f.runtime.f.sql("UPDATE runtime_preparation_v1 SET complete=0")
        let result = try f.run()
        XCTAssertTrue(result.configurationPublished); XCTAssertEqual(result.reference, try f.runtime.material.reference)
        XCTAssertEqual(f.published, 1); XCTAssertEqual(f.validated, 1)
        let retained = try f.progress(); XCTAssertEqual(retained.phase, .runtimePublished)
        XCTAssertEqual(retained.operationID, intent.operationID); XCTAssertEqual(retained.proposalDigest, intent.proposalDigest)
        let bundle = try f.bundle(retained)
        XCTAssertEqual(try AuthorityCommandStartupConfiguration.decode(bundle.command.canonicalBytes).presence.presence.policy.idleMilliseconds, 540_000)
        XCTAssertEqual(bundle.elevationPolicy.canonicalBytes, f.runtime.account.policyBytes)
    }
    func testCompletedPublicationWithLostImportMarkerValidatesAndNeverRepublishes() throws {
        let f = try ImportedRuntimeFixture(), intent = try f.retain()
        try f.write(f.bundle(intent)); let count = f.published
        _ = try f.run(allowPublication: false)
        let completed = try f.progress(); XCTAssertEqual(completed.phase, .runtimePublished)
        _ = try f.run(allowPublication: false)
        XCTAssertEqual(try f.progress(), completed); XCTAssertEqual(f.published, count); XCTAssertEqual(f.validated, 2)
    }
    func testMissingOrChangedPublishedArtifactDoesNotRepairOrAdvanceImport() throws {
        for missing in [false, true] {
            let f = try ImportedRuntimeFixture(), intent = try f.retain(), bundle = try f.bundle(intent)
            try f.write(bundle)
            let command = try XCTUnwrap(RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: f.runtime.material).first { $0.path == bundle.paths.commandConfiguration })
            if missing { try FileManager.default.removeItem(at: f.path(command)) }
            else { try Data([1, 2, 3]).write(to: f.path(command)) }
            let count = f.published
            XCTAssertThrowsError(try f.run(allowPublication: false))
            XCTAssertEqual(f.published, count); XCTAssertEqual(try f.progress(), intent)
            if missing { XCTAssertFalse(FileManager.default.fileExists(atPath: f.path(command).path)) }
            else { XCTAssertEqual(try Data(contentsOf: f.path(command)), Data([1, 2, 3])) }
            XCTAssertTrue(try f.state().configurationPublished)
        }
    }
    func testAdvancedImportCannotRepairAnUnpublishedRuntime() throws {
        let f = try ImportedRuntimeFixture(), intent = try f.retain(), journal = try f.journal()
        _ = try journal.advance(intent, to: .runtimePublished); try journal.close()
        _ = try f.runtime.f.sql("UPDATE runtime_preparation_v1 SET complete=0")
        XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? RuntimePreparationError, .incomplete) }
        XCTAssertEqual(f.published, 0); XCTAssertEqual(f.validated, 0)
        XCTAssertFalse(try f.state().configurationPublished)
    }
    func testInterruptedUnpublishedSetupResumesWithTheSameLocalMaterial() throws {
        let f = try ImportedRuntimeFixture(), intent = try f.retain()
        _ = try f.runtime.f.sql("UPDATE runtime_preparation_v1 SET complete=0")
        XCTAssertThrowsError(try f.run(stage: { if $0 == .filesPublished { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertFalse(try f.state().configurationPublished); XCTAssertEqual(try f.progress(), intent)
        XCTAssertEqual(try f.state().reference, try f.runtime.material.reference)
        XCTAssertTrue(try f.run().configurationPublished); XCTAssertEqual(try f.progress().phase, .runtimePublished)
    }
    func testChangedJournalRevisionDuringPreparationStopsWithoutPublishing() throws {
        let f = try ImportedRuntimeFixture(), intent = try f.retain(), journal = try f.journal()
        defer { try? journal.close() }
        let expected = try f.state()
        XCTAssertThrowsError(try SharedSetupImportRuntimePreparation.prepare(machine: f.runtime.machine, account: f.runtime.account,
            expected: expected, journal: journal, verifyCurrent: {}) { imported, verify in
            XCTAssertEqual(imported, intent)
            _ = try journal.advance(intent, to: .runtimePublished)
            try verify(); return expected
        }) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        XCTAssertEqual(f.published, 0)
    }
    func testUnknownMarkerCommitRecoversWithoutRepeatingPublication() throws {
        let f = try ImportedRuntimeFixture(), intent = try f.intent(); var fail = false
        let journal = try f.journal(initialize: true) { if fail { throw Interrupted() } }
        try journal.begin(intent); fail = true
        try f.write(f.bundle(intent)); let count = f.published, expected = try f.state()
        XCTAssertThrowsError(try SharedSetupImportRuntimePreparation.prepare(machine: f.runtime.machine, account: f.runtime.account,
            expected: expected, journal: journal, verifyCurrent: {}) { imported, verify in
            try f.execute(imported, verify, expected: expected, allowPublication: false)
        }) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertEqual(try f.progress().phase, .runtimePublished)
        _ = try f.run(allowPublication: false); XCTAssertEqual(f.published, count)
    }
    func testArtifactDescriptorsUseLocalPathsAndPreserveRequiredOwnershipRoles() throws {
        let f = try ImportedRuntimeFixture(), bundle = try f.bundle(f.intent())
        let artifacts = try RuntimePublishedArtifactValidation.artifacts(bundle: bundle, material: f.runtime.material)
        XCTAssertEqual(artifacts.count, 7); XCTAssertEqual(Set(artifacts.map(\.path)).count, artifacts.count)
        XCTAssertEqual(artifacts.first { $0.path == bundle.paths.commandConfiguration }?.access, .privateRoot)
        XCTAssertEqual(artifacts.first { $0.path == bundle.paths.transportConfiguration }?.access, .publicRoot)
        XCTAssertEqual(artifacts.first { $0.path == bundle.paths.transportIdentity }?.access, .servicePrivate(20000))
        XCTAssertTrue(artifacts.allSatisfy { $0.description == "RuntimePublishedArtifact(redacted)" })
    }
}
