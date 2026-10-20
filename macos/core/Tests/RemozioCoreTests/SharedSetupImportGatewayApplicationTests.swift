import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Owned files exercise custody, validation and progress. Native Root admission and service identities remain unproven.
final class SharedSetupImportGatewayApplicationTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    final class Fixture {
        let core: GatewayJournalSetupStoreTests.Fixture
        let privateState: ProtectedSetupDirectory
        let selection: GatewayRuntimeSettingsSelection
        let choices: GatewaySetupPreparationChoices
        init(prepared: Bool = true) throws {
            core = try .init(retainMaterial: false)
            privateState = try .init(anchor: core.runtime.f.root.path, relativePath: "ImportGatewayPrivate", owner: getuid())
            selection = try .init(service: core.bundle.gateway.settings, activation: .init())
            choices = try .init(provider: core.provider, senderID: "123", packageName: "dev.remozio.android",
                settings: selection.service, fileWakeCustodyAccepted: true)
            if prepared { try prepare(on: core.machine) }
        }
        deinit { privateState.close() }
        var materialPath: String { privateState.path + "/" + AdministrativeSetupPublication.File.gatewayMaterial.name }
        func load() throws -> GatewayPreparationMaterial {
            try .decode(ProtectedServiceConfiguration.read(anchor: privateState.path,
                relativePath: AdministrativeSetupPublication.File.gatewayMaterial.name, owner: getuid()))
        }
        func publishPrivate(_ mode: GatewayPrivateArtifactPublication.Mode, verify: () throws -> Void = {}) throws {
            _ = try GatewayPrivateArtifactPublication.publish(material: load(), expected: core.material.reference,
                directory: core.parent, owner: getuid(), gatewayUID: getuid(), gatewayGID: getgid(),
                transportUID: getuid(), transportGID: getgid(), mode: mode, verifyCurrent: verify)
        }
        func prepare(on machine: PreparationIntentStore) throws {
            let retained = try machine.gatewayPreparation(accountID: core.runtime.account.accountID).reference
            if let retained {
                XCTAssertEqual(retained, try core.material.reference)
                XCTAssertEqual(try load().reference, retained)
            } else {
                _ = try AdministrativeSetupPublication.publish(core.material.encoded, file: .gatewayMaterial,
                    directory: privateState, owner: getuid(), verify: {})
                try machine.retainGatewayMaterial(core.material.reference)
            }
            let intent = try machine.gatewayJournalPreparation(accountID: core.runtime.account.accountID).intent
            try publishPrivate(intent == nil ? .prepareUnactivated : .validateRetained)
            try machine.retainGatewayJournalIntent(core.intent)
        }
        func validate(on machine: PreparationIntentStore? = nil, choices: GatewaySetupPreparationChoices? = nil,
                      selection: GatewayRuntimeSettingsSelection? = nil, verify: () throws -> Void = {}) throws {
            try SharedSetupImportGatewayPreparedValidation.validate(machine: machine ?? core.machine, account: core.runtime.account,
                choices: choices ?? self.choices, selection: selection ?? self.selection, verifyCurrent: verify,
                readMaterial: load, validatePrivate: { reference, current in
                    XCTAssertEqual(reference, try self.core.material.reference); try self.publishPrivate(.validateRetained, verify: current)
                }, validateJournal: { intent, current in
                    _ = try GatewayJournalFileProvisioning.prepare(parent: self.core.parent, processOwner: getuid(),
                        serviceUID: getuid(), serviceGID: getgid(), mode: .requireExisting, expected: intent.files, verifyCurrent: current)
                })
        }
        func proposal() -> PortableSetup {
            .init(defaults: .init(presence: core.runtime.plan.host.command.presence.presence.policy, gateway: selection),
                fcm: core.provider, pushClient: try! .init(projectID: core.provider.project, senderID: "123", packageName: "dev.remozio.android"))
        }
        func owner(proposal selected: PortableSetup? = nil, importedRuntime: GatewaySetupImportedRuntimeOperations? = nil) throws -> SetupAccountOwner {
            let account = core.runtime.account, f = core.runtime.f
            let initial = try SharedSetupImportIntent(scope: .init(account: account, inventory: XCTUnwrap(core.machine.inventory())), proposal: selected ?? proposal())
            try f.prepare("machine/SharedSetupImport", .sharedSetupImport)
            let journal = try SharedSetupImportJournal(lease: .init(anchor: f.root.path, relativeDirectory: "machine/SharedSetupImport",
                owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                macID: account.macID, installationID: account.installationID, initialize: true)
            try journal.begin(initial); _ = try journal.advance(initial, to: .runtimePublished); try journal.close()
            try core.machine.close()
            return try .init(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy,
                lookupAccount: { uid in guard uid == f.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return f.identity }, importedGatewayOperation: importedRuntime)
        }
    }
    private func read(_ owner: SetupAccountOwner) throws -> SetupPortableImportProgress {
        guard let value = try owner.portableImportProgress(callerUID: getuid()) else { throw Interrupted() }; return value
    }
    func testPreparedValidationRetainsActualOwnedFilesAndTheirIdentities() throws {
        let f = try Fixture(), before = try Data(contentsOf: URL(fileURLWithPath: f.materialPath))
        let state = try f.core.machine.gatewayJournalPreparation(accountID: f.core.runtime.account.accountID)
        try f.validate(); try f.validate()
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.materialPath)), before)
        XCTAssertEqual(try f.core.machine.gatewayJournalPreparation(accountID: f.core.runtime.account.accountID), state)
    }
    func testMissingPrivateArtifactsAreNotRepaired() throws {
        for file in ["gateway-provider.json", "gateway-receipt-key.cbor", "transport-wake-key.cbor"] {
            let f = try Fixture(), path = f.core.parent.path + "/" + file
            XCTAssertEqual(unlink(path), 0); XCTAssertThrowsError(try f.validate())
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
        let f = try Fixture(); XCTAssertEqual(unlink(f.materialPath), 0)
        XCTAssertThrowsError(try f.validate()); XCTAssertFalse(FileManager.default.fileExists(atPath: f.materialPath))
    }
    func testMissingJournalFilesAndChangedConnectionLimitsRefuseValidation() throws {
        let f = try Fixture(); XCTAssertEqual(unlink(f.core.path), 0)
        XCTAssertThrowsError(try f.validate()); XCTAssertFalse(FileManager.default.fileExists(atPath: f.core.path))
        let g = try Fixture(), altered = try GatewayRuntimeSettingsSelection(service: g.selection.service,
            activation: g.selection.activation, maximumWakeConnections: g.selection.maximumWakeConnections + 1)
        XCTAssertThrowsError(try g.validate(selection: altered)) { XCTAssertEqual($0 as? GatewayPreparationError, .changedScope) }
    }
    func testDifferentCredentialBytesWithTheSameProjectCannotValidateRetainedOutputs() throws {
        let f = try Fixture(), fields = try XCTUnwrap(JSONSerialization.jsonObject(with: f.core.material.providerJSON) as? [String: String])
        let provider = try SetupFCMConfiguration(project: f.core.provider.project, clientEmail: fields["client_email"]!,
            privateKeyID: "different-fixture-key", privateKeyPEM: fields["private_key"]!)
        let altered = try GatewaySetupPreparationChoices(provider: provider, senderID: "123", packageName: "dev.remozio.android",
            settings: f.selection.service, fileWakeCustodyAccepted: true)
        XCTAssertThrowsError(try f.validate(choices: altered)) { XCTAssertEqual($0 as? GatewayPreparationError, .conflictingMaterial) }
    }
    func testNativeValidationRefusesOrdinaryUIDBeforeOpeningProductionPaths() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary-account refusal") }
        let f = try Fixture()
        XCTAssertThrowsError(try SharedSetupImportGatewayPreparedValidation.validateNative(machine: f.core.machine,
            account: f.core.runtime.account, choices: f.choices, selection: f.selection, verifyCurrent: {})) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testAbsentGatewayCannotSilentlySkipExistingGatewayMaterial() throws {
        let empty = try RuntimeActivationFixture()
        XCTAssertNoThrow(try SharedSetupImportGatewayPreparedValidation.validateAbsent(machine: empty.machine, account: empty.account, verifyCurrent: {}))
        let f = try Fixture()
        XCTAssertThrowsError(try SharedSetupImportGatewayPreparedValidation.validateAbsent(machine: f.core.machine, account: f.core.runtime.account, verifyCurrent: {}))
    }
    func testOwnerAdvancesOnlyAfterPreparedOutputsValidateAndRetryDoesNotPrepareAgain() throws {
        let f = try Fixture(prepared: false), owner = try f.owner(); defer { try? owner.close() }
        let before = try read(owner); var preparations = 0, validations = 0
        let result = try owner.prepareImportedGateway(callerUID: getuid(), expected: before, proposal: f.proposal(), fileWakeCustodyAccepted: true,
            prepare: { machine, _, choices, selection, verify in
                try verify(); XCTAssertTrue(choices.fileWakeCustodyAccepted)
                XCTAssertEqual(try selection.bytes, try f.selection.bytes); preparations += 1; try f.prepare(on: machine); try verify()
            }, validate: { machine, _, choices, selection, verify in
                validations += 1; try f.validate(on: machine, choices: choices, selection: selection, verify: verify)
            })
        XCTAssertEqual(result.phase, .gatewayPrepared); XCTAssertEqual(result.operationID, before.operationID)
        XCTAssertNotEqual(result.revision, before.revision); XCTAssertEqual(preparations, 1); XCTAssertEqual(validations, 1)
        XCTAssertEqual(try read(owner), result)
        let retry = try owner.prepareImportedGateway(callerUID: getuid(), expected: result, proposal: f.proposal(), fileWakeCustodyAccepted: false,
            prepare: { _, _, _, _, _ in XCTFail("Repeated preparation after the verified marker") },
            validate: { machine, _, choices, selection, verify in try f.validate(on: machine, choices: choices, selection: selection, verify: verify) })
        XCTAssertEqual(retry, result)
    }
    func testOwnerRefusesMissingCustodyAndChangedProposalBeforePreparingAnyCredential() throws {
        let f = try Fixture(prepared: false), owner = try f.owner(); defer { try? owner.close() }
        let before = try read(owner); var preparations = 0
        XCTAssertThrowsError(try owner.prepareImportedGateway(callerUID: getuid(), expected: before, proposal: f.proposal(), fileWakeCustodyAccepted: false,
            prepare: { _, _, _, _, _ in preparations += 1 }, validate: { _, _, _, _, _ in XCTFail() })) {
            XCTAssertEqual($0 as? GatewayPreparationError, .custodyNotAccepted)
        }
        let different = PortableSetup(defaults: f.proposal().defaults)
        XCTAssertThrowsError(try owner.prepareImportedGateway(callerUID: getuid(), expected: before, proposal: different, fileWakeCustodyAccepted: true,
            prepare: { _, _, _, _, _ in preparations += 1 }, validate: { _, _, _, _, _ in XCTFail() })) {
            XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
        }
        XCTAssertEqual(preparations, 0); XCTAssertFalse(FileManager.default.fileExists(atPath: f.materialPath))
        XCTAssertEqual(try read(owner), before)
    }
    func testOwnerAdvancesAProviderFreeImportWithoutCreatingGatewayCustody() throws {
        let f = try Fixture(prepared: false), proposal = PortableSetup(defaults: f.proposal().defaults)
        let owner = try f.owner(proposal: proposal); defer { try? owner.close() }
        let before = try read(owner)
        let result = try owner.prepareImportedGateway(callerUID: getuid(), expected: before, proposal: proposal,
            fileWakeCustodyAccepted: false, prepare: { _, _, _, _, _ in XCTFail("Invented provider preparation") },
            validate: { _, _, _, _, _ in XCTFail("Invented provider validation") })
        XCTAssertEqual(result.phase, .gatewayPrepared); XCTAssertEqual(result.operationID, before.operationID)
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.materialPath))
    }
    func testInvalidPreparedOutputsKeepTheMarkerPendingAndNeverRepairARetry() throws {
        let f = try Fixture(prepared: false), owner = try f.owner(); defer { try? owner.close() }
        let before = try read(owner), missing = f.core.parent.path + "/gateway-provider.json"
        XCTAssertThrowsError(try owner.prepareImportedGateway(callerUID: getuid(), expected: before, proposal: f.proposal(), fileWakeCustodyAccepted: true,
            prepare: { machine, _, _, _, verify in try verify(); try f.prepare(on: machine); XCTAssertEqual(unlink(missing), 0) },
            validate: { machine, _, choices, selection, verify in try f.validate(on: machine, choices: choices, selection: selection, verify: verify) }))
        XCTAssertEqual(try read(owner), before); XCTAssertFalse(FileManager.default.fileExists(atPath: missing))
        XCTAssertThrowsError(try owner.prepareImportedGateway(callerUID: getuid(), expected: before, proposal: f.proposal(), fileWakeCustodyAccepted: true,
            prepare: { machine, _, _, _, verify in try verify(); try f.prepare(on: machine) },
            validate: { machine, _, choices, selection, verify in try f.validate(on: machine, choices: choices, selection: selection, verify: verify) }))
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing)); XCTAssertEqual(try read(owner), before)
    }
}
