import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Real owned import files and disposable credentials only. No provider dispatch or installed migration.
final class RuntimeAuditUpgradeImportTests: XCTestCase {
    final class Fixture {
        let runtime: RuntimeActivationFixture
        let preparation: RuntimeAuditUpgradePreparation
        let inventory: InstallationInventory
        let relay: RuntimeAuditUpgradeDependenciesTests.Relay
        let expected: SharedSetupImportIntent
        let directory: ProtectedSetupDirectory
        let source: SharedSetupImportCompatibilitySnapshot.Record
        let providerBytes: [String: Data]
        var materialPresent = true
        var loadCalls = 0
        init(published: Bool = true, port: UInt16 = 51001, unknownDNS: Bool = false) throws {
            guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owned import fixture") }
            let helper = RuntimeAuditUpgradeDependenciesTests()
            (runtime, preparation, inventory) = try helper.fixture(port: port)
            relay = try helper.relay(runtime, preparation, inventory)
            try runtime.f.prepare("machine/SharedSetupImport", .sharedSetupImport)
            directory = try .init(anchor: runtime.f.root.path, relativePath: "machine/SharedSetupImport", owner: getuid())
            let lease = try ProtectedStorageLease(anchor: runtime.f.root.path, relativeDirectory: "machine/SharedSetupImport",
                owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite")
            let journal = try SharedSetupImportJournal(lease: lease, owner: getuid(), macID: runtime.account.macID,
                installationID: runtime.account.installationID, initialize: true)
            try journal.begin(relay.imported)
            expected = try journal.advance(relay.imported, to: .runtimePublished)
            try journal.close()
            let access = try SharedSetupAccessApplicationRecord(expected: expected, plan: relay.plan, createdTunnel: relay.created)
                .transition(to: .dispatched).transition(to: .created,
                    applicationID: "22222222-2222-4222-8222-222222222222", audience: "synthetic-audience")
            let dns = try SharedSetupDNSRecord(expected: expected, plan: relay.plan, createdTunnel: relay.created, application: access)
                .transition(to: .dispatched)
            let selectedDNS = try unknownDNS ? dns.transition(to: .unknown) : dns.transition(to: .created,
                dnsRecordID: String(repeating: "c", count: 32))
            let id = runtime.account.accountID
            let files: [(AdministrativeSetupPublication.File, Data)] = [
                (.importRelayPlan(accountID: id), relay.plan.bytes), (.importRelayProvisioning(accountID: id), relay.created.bytes),
                (.importAccessApplication(accountID: id), access.bytes), (.importDNSRecord(accountID: id), selectedDNS.bytes)]
            var bytes: [String: Data] = [:]
            for (file, data) in files {
                _ = try AdministrativeSetupPublication.publish(data, file: file, directory: directory, owner: getuid())
                bytes[file.name] = data
            }
            providerBytes = bytes
            if published {
                _ = try SharedSetupRelayRunReferenceStorage.retain(relay.material.reference, expected: expected,
                    plan: relay.plan, created: relay.created, runtime: preparation.intent.source,
                    directory: directory, owner: getuid(), verifyCurrent: {})
            }
            let snapshot = try XCTUnwrap(SharedSetupImportCompatibilitySnapshot.capture(anchor: runtime.f.root.path,
                relativeMachineDirectory: "machine", owner: getuid(), macID: runtime.account.macID,
                installationID: runtime.account.installationID))
            source = try XCTUnwrap(snapshot.records.first { $0.accountID == id })
        }
        deinit { directory.close() }
        var runPath: String {
            directory.path + "/" + AdministrativeSetupPublication.File.importRelayRunReference(accountID: runtime.account.accountID).name
        }
        func files() throws -> [String: Data] {
            try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: directory.path).map {
                ($0, try Data(contentsOf: URL(fileURLWithPath: directory.path + "/" + $0)))
            })
        }
        func capture(expected supplied: SharedSetupImportIntent? = nil,
                     source record: SharedSetupImportCompatibilitySnapshot.Record? = nil,
                     verify: () throws -> Void = {}, onLoad: () throws -> Void = {}) throws -> RuntimeAuditUpgradeImportPreparation {
            try RuntimeAuditUpgradeImportPreparation.captureOwned(preparation, expected: supplied ?? expected, source: record ?? source,
                account: runtime.account, inventory: inventory, directory: directory, owner: getuid(), verifyCurrent: verify,
                loadMaterial: { plan, created in
                    self.loadCalls += 1; try onLoad()
                    if self.materialPresent { XCTAssertEqual(plan, self.relay.plan); XCTAssertEqual(created, self.relay.created) }
                    return self.materialPresent ? self.relay.material : nil
                })
        }
    }
    func testPublishedRelayReferenceRebindsWithoutChangingImportOrProviderRecords() throws {
        let f = try Fixture(), before = try f.files(), value = try f.capture()
        XCTAssertEqual(value.intent, f.expected); XCTAssertEqual(value.source, f.source)
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: value.preservedFiles.map { ($0.file.name, $0.bytes) }), f.providerBytes)
        let material = try XCTUnwrap(value.targetMaterial), reference = try XCTUnwrap(value.targetReference)
        XCTAssertEqual(try material.reference, reference); XCTAssertEqual(reference.runtime, f.preparation.intent.target)
        XCTAssertEqual(reference.materialID, try f.relay.material.reference.materialID)
        XCTAssertEqual(reference.credentialDigest, try f.relay.material.reference.credentialDigest)
        XCTAssertNotEqual(reference.materialDigest, try f.relay.material.reference.materialDigest)
        XCTAssertEqual(try value.sourceMaterial?.encoded, try f.relay.material.encoded)
        XCTAssertEqual(try RelayRunCredentialReference.decode(reference.encoded, expected: f.expected, plan: f.relay.plan,
            created: f.relay.created, runtime: f.preparation.intent.target, account: f.runtime.account, inventory: f.inventory), reference)
        XCTAssertEqual(try f.files(), before); XCTAssertEqual(f.loadCalls, 2)
        XCTAssertEqual(try f.capture().targetReference, reference)
        XCTAssertEqual(String(reflecting: value), "RuntimeAuditUpgradeImportPreparation(redacted)")
    }
    func testUnreferencedPrivateMaterialIsPreservedWithoutInventingAPublishedReference() throws {
        let f = try Fixture(published: false), before = try f.files(), value = try f.capture()
        XCTAssertNil(value.source.runCredential); XCTAssertNil(value.targetReference)
        XCTAssertNotNil(value.sourceMaterial); XCTAssertNotNil(value.targetMaterial)
        XCTAssertEqual(try value.targetMaterial?.reference.runtime, f.preparation.intent.target)
        f.relay.material.withCredentialBytes { original in value.targetMaterial?.withCredentialBytes { XCTAssertEqual($0, original) } }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.runPath)); XCTAssertEqual(try f.files(), before)
    }
    func testPrivateMaterialDisappearanceDuringCaptureCannotReturnAStaleCandidate() throws {
        let f = try Fixture(published: false), before = try f.files()
        var reads = 0
        XCTAssertThrowsError(try RuntimeAuditUpgradeImportPreparation.captureOwned(f.preparation, expected: f.expected,
            source: f.source, account: f.runtime.account, inventory: f.inventory, directory: f.directory, owner: getuid(),
            verifyCurrent: {}, loadMaterial: { _, _ in
                reads += 1
                return reads == 1 ? f.relay.material : nil
            })) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
        XCTAssertEqual(reads, 2); XCTAssertEqual(try f.files(), before)
    }
    func testAbsentUnpublishedMaterialStaysAbsentAndAcceptedMissingMaterialCannotBeRecreated() throws {
        let pending = try Fixture(published: false); pending.materialPresent = false
        let empty = try pending.capture()
        XCTAssertNil(empty.sourceMaterial); XCTAssertNil(empty.targetMaterial); XCTAssertNil(empty.targetReference)
        let accepted = try Fixture(); accepted.materialPresent = false
        let before = try accepted.files()
        XCTAssertThrowsError(try accepted.capture()) { XCTAssertEqual($0 as? RuntimePreparationError, .missingMaterial) }
        XCTAssertEqual(try accepted.files(), before)
    }
    func testUnknownProviderOutcomeKeepsItsAttemptAndDoesNotDispatchOrRetry() throws {
        let f = try Fixture(published: false, unknownDNS: true); f.materialPresent = false
        let before = try f.files(), value = try f.capture()
        let bytes = try XCTUnwrap(value.preservedFiles.first { if case .importDNSRecord = $0.file { true } else { false } }).bytes
        let access = try SharedSetupAccessApplicationRecord.decode(XCTUnwrap(f.providerBytes[AdministrativeSetupPublication.File.importAccessApplication(accountID: f.runtime.account.accountID).name]),
            expected: f.expected, plan: f.relay.plan, createdTunnel: f.relay.created)
        let record = try SharedSetupDNSRecord.decode(bytes, expected: f.expected, plan: f.relay.plan,
            createdTunnel: f.relay.created, application: access)
        XCTAssertEqual(record.phase, .unknown); XCTAssertEqual(record.attemptNumber, 1)
        XCTAssertEqual(try f.files(), before)
    }
    func testChangedProviderOrIdenticalReplacementCannotMatchTheCapturedSource() throws {
        for identical in [false, true] {
            let f = try Fixture(), name = AdministrativeSetupPublication.File.importRelayPlan(accountID: f.runtime.account.accountID).name
            let path = f.directory.path + "/" + name
            XCTAssertThrowsError(try f.capture(onLoad: {
                let bytes = identical ? try XCTUnwrap(f.providerBytes[name]) : Data("changed provider projection".utf8)
                try FileManager.default.moveItem(atPath: path, toPath: path + ".retained")
                try bytes.write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o600), 0)
            }))
            XCTAssertEqual(f.loadCalls, 1)
            XCTAssertNotNil(try SharedSetupRelayRunReferenceStorage.read(expected: f.expected, plan: f.relay.plan,
                created: f.relay.created, directory: f.directory, owner: getuid()))
        }
    }
    func testUnsafeOrMissingReferencedLeafRefusesBeforeLoadingPrivateMaterial() throws {
        for link in [false, true] {
            let f = try Fixture(), before = try Data(contentsOf: URL(fileURLWithPath: f.runPath))
            if link {
                try FileManager.default.moveItem(atPath: f.runPath, toPath: f.runPath + ".retained")
                try FileManager.default.createSymbolicLink(atPath: f.runPath, withDestinationPath: f.runPath + ".retained")
            } else { try FileManager.default.removeItem(atPath: f.runPath) }
            XCTAssertThrowsError(try f.capture()); XCTAssertEqual(f.loadCalls, 0)
            if link { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.runPath + ".retained")), before) }
        }
    }
    func testForeignIntentChangedProgressAndWrongRelayPortRefuseBeforePrivateLoad() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try f.capture(expected: other.expected)); XCTAssertEqual(f.loadCalls, 0)
        XCTAssertThrowsError(try f.capture(expected: f.expected.advanced(to: .gatewayPrepared))); XCTAssertEqual(f.loadCalls, 0)
        let wrongPort = try Fixture(port: 51002)
        XCTAssertThrowsError(try wrongPort.capture()); XCTAssertEqual(wrongPort.loadCalls, 0)
    }
    func testMissingConfiguredRelayPlanCannotBeRebuiltOrSkipped() throws {
        let f = try Fixture(published: false)
        for name in f.providerBytes.keys { try FileManager.default.removeItem(atPath: f.directory.path + "/" + name) }
        let source = f.source
        let absent = SharedSetupImportCompatibilitySnapshot.Record(accountID: source.accountID, operationID: source.operationID,
            revision: source.revision, phase: source.phase, digest: source.digest,
            portableVersion: source.portableVersion, settingsVersion: source.settingsVersion,
            relay: nil, relayProvisioning: nil, accessApplication: nil, dnsRecord: nil)
        XCTAssertThrowsError(try f.capture(source: absent)); XCTAssertEqual(f.loadCalls, 0)
    }
    func testImportWithoutCloudConfigurationKeepsAnEmptyLeafProjection() throws {
        let helper = RuntimeAuditUpgradeDependenciesTests(), (runtime, preparation, inventory) = try helper.fixture()
        let proposal = try PortableSetup(defaults: .init(presence: preparation.source.host.command.presence.presence.policy,
            gateway: GatewaySetupForm().settingsSelection()))
        let expected = try SharedSetupImportIntent(scope: .init(account: runtime.account, inventory: inventory), proposal: proposal)
        let source = try SharedSetupImportCompatibilitySnapshot.Record(accountID: expected.scope.accountID,
            operationID: expected.operationID, revision: expected.revision, phase: expected.phase.rawValue,
            digest: Data(SHA256.hash(data: expected.bytes)), portableVersion: expected.originalPortableVersion,
            settingsVersion: expected.recipe.settingsVersion, relay: nil, relayProvisioning: nil, accessApplication: nil, dnsRecord: nil)
        let directory = try ProtectedSetupDirectory(anchor: runtime.f.root.path, relativePath: "empty-imports", owner: getuid())
        defer { directory.close() }
        // This leaf-only fixture supplies scope metadata; it claims no native journal membership.
        let result = try RuntimeAuditUpgradeImportPreparation.captureOwned(preparation, expected: expected, source: source,
            account: runtime.account, inventory: inventory, directory: directory, owner: getuid(), verifyCurrent: {},
            loadMaterial: { plan, created in XCTAssertNil(plan); XCTAssertNil(created); return nil })
        XCTAssertEqual(result.intent, expected); XCTAssertTrue(result.preservedFiles.isEmpty)
        XCTAssertNil(result.sourceMaterial); XCTAssertNil(result.targetMaterial); XCTAssertNil(result.targetReference)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), [])
    }
    func testScopeLossAndNativeEntryRefuseBeforeProtectedWork() throws {
        let f = try Fixture(); var checks = 0
        XCTAssertThrowsError(try f.capture(verify: {
            checks += 1
            if checks == 3 { throw RuntimePreparationError.changedScope }
        }))
        XCTAssertEqual(f.loadCalls, 1)
        XCTAssertThrowsError(try RuntimeAuditUpgradeImportPreparation.capture(f.preparation, expected: f.expected, source: f.source,
            account: f.runtime.account, inventory: f.inventory, verifyCurrent: { XCTFail("The Root guard must precede scope work") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
