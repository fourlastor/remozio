import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned fixture records and synthetic policy receipts. It proves no protected commit or native health.
final class RetainedSetupCompletionArchiveTests: XCTestCase {
    final class Fixture {
        let activationFixture: RetainedSetupActivationArchiveTests.Fixture
        let activationBytes: Data
        let startupFields: [String: Any]
        let intentFields: [String: Any]
        let bindingFields: [String: Any]
        let inventory: InstallationInventory
        let startupPolicy: AuthorityCodePolicySnapshot
        let completionPolicy: AuthorityCodePolicySnapshot
        let checkpoint: ContinuityCheckpoint
        let fields: [UInt64: CBORValue]
        let limits = try! CBORLimits(maxBytes: 2_097_152, maxDepth: 4, maxItems: 4096)

        init(changedPolicy: Bool = false) throws {
            let f = try RetainedSetupActivationArchiveTests.Fixture()
            let services = f.source.reference.services
            let originalPolicy = f.host.codePolicy
            let startup = try originalPolicy.retainingFormat(with: originalPolicy.entries.map { entry in
                try AuthorityCodeEntry(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                    installedGeneration: changedPolicy && entry.role == .authority ? 2 : entry.installedGeneration,
                    minimumGeneration: entry.minimumGeneration, codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
            })
            let completion = try startup.retainingFormat(with: startup.entries.map { entry in
                try AuthorityCodeEntry(role: entry.role, teamID: entry.teamID, identifier: entry.identifier,
                    installedGeneration: entry.installedGeneration,
                    minimumGeneration: changedPolicy && entry.role == .authority ? entry.installedGeneration : entry.minimumGeneration,
                    codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
            })
            let source = AuthorityCodePolicySnapshot(revision: UUID(), policy: startup,
                roleRevisions: Dictionary(uniqueKeysWithValues: startup.entries.map { ($0.role, UUID()) }))
            var roleRevisions = source.roleRevisions
            if changedPolicy { roleRevisions[.authority] = UUID() }
            let completed = changedPolicy ? AuthorityCodePolicySnapshot(revision: UUID(), policy: completion,
                roleRevisions: roleRevisions) : source
            let initialCheckpoint = try ContinuityCheckpoint(generation: 3,
                authorityDigest: MachineUpdateActivationRecord.digest(Data("startup authority".utf8)),
                ledgerDigest: MachineUpdateActivationRecord.digest(Data("retained ledger".utf8)),
                journalEpoch: Data(repeating: 7, count: 16), journalHead: 5, authorityGeneration: 2)
            let checkpoint: ContinuityCheckpoint
            if changedPolicy {
                checkpoint = try initialCheckpoint.successor(
                    authorityDigest: MachineUpdateActivationRecord.digest(Data("completion authority".utf8)),
                    ledgerDigest: initialCheckpoint.ledgerDigest, journalEpoch: initialCheckpoint.journalEpoch,
                    journalHead: initialCheckpoint.journalHead)
            } else { checkpoint = initialCheckpoint }
            func stored(_ policy: AuthorityCodePolicySnapshot) throws -> [String: Any] {
                ["revision": policy.revision.uuidString, "bytes": try policy.storedBytes.base64EncodedString()]
            }
            let startupIntent: [String: Any] = [
                "formatVersion": 2, "id": UUID().uuidString, "revision": UUID().uuidString,
                "macID": services.macID.base64EncodedString(), "installationID": services.installationID.base64EncodedString(),
                "accountID": services.accountID.base64EncodedString(), "ownerUID": services.ownerUID,
                "sourceDigest": f.binding.retainedSourceDigest.base64EncodedString(),
                "initializationDigest": f.binding.initializationDigest.base64EncodedString(),
                "installedReleaseDigest": f.binding.installedReleaseDigest.base64EncodedString(),
                "sourcePolicy": try stored(source), "sourceCheckpoint": try initialCheckpoint.bytes.base64EncodedString(),
                "startupPolicy": try startup.bytes.base64EncodedString(), "completionPolicy": try completion.bytes.base64EncodedString(),
                "phase": 3, "committedPolicy": try stored(source),
                "committedCheckpoint": try initialCheckpoint.bytes.base64EncodedString(),
            ]
            let startupRecord = try MachineUpdateRetainedSetupPolicyIntentRecord.decode(f.source.json(startupIntent))
            var startupFields = f.source.startup
            startupFields["policyIntentDigest"] = try Self.digest(startupRecord.encoded)
            startupFields["sourcePolicyDigest"] = try Self.digest(source.storedBytes)
            startupFields["sourceCheckpointDigest"] = try Self.digest(initialCheckpoint.bytes)
            startupFields["startupPolicyDigest"] = try Self.digest(startup.bytes)
            startupFields["startupPolicySnapshotDigest"] = try Self.digest(source.storedBytes)
            startupFields["startupCheckpointDigest"] = try Self.digest(initialCheckpoint.bytes)
            startupFields["completionPolicyDigest"] = try Self.digest(completion.bytes)
            func host(_ role: GatewaySettingsConsumerRole) throws -> GatewaySettingsConsumerHostConfiguration {
                var fields = try f.source.map(f.source.bytes(stage: 3, role: role, startup: startupFields))
                fields[5] = .bytes(try startup.bytes)
                return try .decodeForReleaseArchive(f.source.encode(fields))
            }
            let gateway = try host(.gateway), transportHost = try host(.transport)
            let authority = try InstalledAuthorityCommandConfiguration(machineDirectory: f.host.machineDirectory,
                installationID: f.host.installationID, releaseDigest: f.host.releaseDigest, codePolicy: startup,
                command: f.host.command, label: f.host.label, plistName: f.host.plistName,
                jobPlacement: f.host.jobPlacement, gatewaySettingsControlEnabled: true)
            let transport = try TransportPairingStartupConfiguration(transport: f.transport.transport, control: f.transport.control,
                wake: f.transport.wake, relayPort: f.transport.relayPort, settingsHost: transportHost)
            var activationFields = f.fields
            activationFields[3] = .bytes(authority.canonicalBytes); activationFields[4] = .bytes(transport.canonicalBytes)
            activationFields[5] = .bytes(try gateway.encoded); activationFields[9] = .bytes(try f.source.json(startupFields))
            let activationBytes = try f.bytes(activationFields)
            _ = try RuntimeRetainedSetupActivationArchive.decode(activationBytes)
            let account = try InstallationAccount(accountID: services.accountID, ownerUID: services.ownerUID)
            let service = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                label: "dev.sebastiano.remozio.macos.archive-completion.authority",
                plistName: "dev.sebastiano.remozio.macos.archive-completion.authority.plist", accountID: account.accountID)
            let inventory = try InstallationInventory(macID: f.inventory.macID, installationID: f.inventory.installationID,
                revision: f.inventory.revision, bundlePath: f.inventory.bundlePath, releaseDigest: f.inventory.releaseDigest,
                accounts: [account], services: f.inventory.services + [service], formatVersion: 2)
            let intentFields: [String: Any] = [
                "formatVersion": 1, "id": UUID().uuidString, "revision": UUID().uuidString,
                "startupIntent": startupIntent, "binding": startupFields, "phase": 3,
                "activationPlanDigest": Self.digest(activationBytes), "inventoryDigest": Self.digest(inventory.canonicalBytes),
                "committedPolicy": try stored(completed), "committedCheckpoint": try checkpoint.bytes.base64EncodedString(),
            ]
            let intent = try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.source.json(intentFields))
            let bindingFields: [String: Any] = [
                "formatVersion": 1, "startupBinding": startupFields, "recordedCompletionDigest": try Self.digest(intent.encoded),
                "activationPlanDigest": Self.digest(activationBytes), "recordedInventoryDigest": Self.digest(inventory.canonicalBytes),
                "completionPolicyRevision": completed.revision.uuidString,
                "completionPolicySnapshotDigest": try Self.digest(completed.storedBytes),
                "completionCheckpointDigest": try Self.digest(checkpoint.bytes),
            ]
            let bindingBytes = try f.source.json(bindingFields)
            _ = try RuntimeRetainedSetupCompletionBinding.decode(bindingBytes)
            self.activationFixture = f; self.activationBytes = activationBytes; self.startupFields = startupFields
            self.intentFields = intentFields; self.bindingFields = bindingFields; self.inventory = inventory
            self.startupPolicy = source; self.completionPolicy = completed; self.checkpoint = checkpoint
            // Frozen from the donor's archive map. No bytes come from executing the donor.
            fields = [0: .unsigned(1), 1: .text("retained-setup-completion-archive"), 2: .bytes(bindingBytes),
                3: .bytes(activationBytes), 4: .bytes(try intent.encoded), 5: .bytes(inventory.canonicalBytes)]
        }
        static func digest(_ bytes: Data) -> String { MachineUpdateActivationRecord.digest(bytes).base64EncodedString() }
        func json(_ fields: [String: Any]) throws -> Data { try activationFixture.source.json(fields) }
        func bytes(_ fields: [UInt64: CBORValue]? = nil) throws -> Data {
            try DeterministicCBOR.encode(.map(fields ?? self.fields), limits: limits)
        }
        func replacing(activation: Data? = nil, intent: [String: Any]? = nil, inventory: Data? = nil,
                       binding: [String: Any]? = nil) throws -> Data {
            var fields = self.fields, binding = binding ?? bindingFields
            if let activation { fields[3] = .bytes(activation); binding["activationPlanDigest"] = Self.digest(activation) }
            if let intent {
                let bytes = try json(intent); fields[4] = .bytes(bytes); binding["recordedCompletionDigest"] = Self.digest(bytes)
            }
            if let inventory { fields[5] = .bytes(inventory); binding["recordedInventoryDigest"] = Self.digest(inventory) }
            fields[2] = .bytes(try json(binding))
            return try bytes(fields)
        }
        func inventoryBytes(macID: Data? = nil, installationID: Data? = nil, releaseDigest: Data? = nil,
                       path: String? = nil, account: InstallationAccount? = nil, enrolled: Bool = true) throws -> Data {
            let original = inventory
            let account = try account ?? XCTUnwrap(original.accounts.first)
            if !enrolled {
                return try InstallationInventory.machineBootstrap(macID: macID ?? original.macID,
                    installationID: installationID ?? original.installationID, revision: original.revision,
                    bundlePath: path ?? original.bundlePath, releaseDigest: releaseDigest ?? original.releaseDigest).canonicalBytes
            }
            let service = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                label: "dev.sebastiano.remozio.macos.archive-completion.authority",
                plistName: "dev.sebastiano.remozio.macos.archive-completion.authority.plist", accountID: account.accountID)
            return try InstallationInventory(macID: macID ?? original.macID, installationID: installationID ?? original.installationID,
                revision: original.revision, bundlePath: path ?? original.bundlePath, releaseDigest: releaseDigest ?? original.releaseDigest,
                accounts: [account], services: [service], formatVersion: 2).canonicalBytes
        }
    }

    func testReadsChangedAndNoOpRecordedReceiptsFromTheSourceDerivedWireMap() throws {
        for changed in [false, true] {
            let f = try Fixture(changedPolicy: changed), bytes = try f.bytes()
            let archive = try RuntimeRetainedSetupCompletionArchive.decode(bytes)
            XCTAssertEqual(try archive.encoded, bytes)
            XCTAssertEqual(try RuntimeRetainedSetupCompletionArchive.decode(archive.encoded), archive)
            XCTAssertEqual(try archive.originalActivation().binding, archive.binding.startupBinding)
            XCTAssertEqual(try archive.recordedInventory(), f.inventory)
            let record = try archive.completionIntent()
            XCTAssertEqual(record.phase, .recorded)
            XCTAssertEqual(try record.committedPolicy?.snapshot(), f.completionPolicy)
            XCTAssertEqual(record.committedCheckpoint, try f.checkpoint.bytes)
            XCTAssertEqual(f.startupPolicy == f.completionPolicy, !changed)
            XCTAssertEqual(archive.description, "RuntimeRetainedSetupCompletionArchive(redacted)")
            XCTAssertEqual(archive.debugDescription, archive.description)
            XCTAssertThrowsError(try RuntimeActivationPlan.decode(archive.originalActivationBytes))
            XCTAssertThrowsError(try RuntimeActivationState.Plan(encoded: archive.originalActivationBytes))
        }
    }

    func testRejectsEachPayloadDigestMismatchAndMalformedNestedRecord() throws {
        let f = try Fixture()
        for name in ["activationPlanDigest", "recordedCompletionDigest", "recordedInventoryDigest"] {
            var binding = f.bindingFields; binding[name] = Fixture.digest(Data(name.utf8))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(binding: binding)))
        }
        for key in UInt64(2)...5 {
            var fields = f.fields; fields[key] = .bytes(Data())
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.bytes(fields)))
        }
        for key in [UInt64(3), 4, 5] {
            var fields = f.fields; fields[key] = .bytes(Data([0]))
            var binding = f.bindingFields
            binding[key == 3 ? "activationPlanDigest" : key == 4 ? "recordedCompletionDigest" : "recordedInventoryDigest"] = Fixture.digest(Data([0]))
            fields[2] = .bytes(try f.json(binding))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.bytes(fields)))
        }
        for (key, maximum): (UInt64, Int) in [
            (3, RuntimeRetainedSetupActivationArchive.maximumBytes),
            (4, MachineUpdateRetainedSetupCompletionIntentRecord.maximumBytes),
            (5, try InstallationInventory.limits.maxBytes),
        ] {
            let oversized = Data(repeating: 0, count: maximum + 1)
            var fields = f.fields; fields[key] = .bytes(oversized)
            var binding = f.bindingFields
            binding[key == 3 ? "activationPlanDigest" : key == 4 ? "recordedCompletionDigest" : "recordedInventoryDigest"] = Fixture.digest(oversized)
            fields[2] = .bytes(try f.json(binding))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.bytes(fields)))
        }
    }

    func testRejectsUnrecordedIntentsAndCrossBoundActivationOrInventoryDigests() throws {
        let f = try Fixture()
        for phase in [1, 2] {
            var record = f.intentFields; record["phase"] = phase
            record.removeValue(forKey: "committedPolicy"); record.removeValue(forKey: "committedCheckpoint")
            XCTAssertNoThrow(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.json(record)))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(intent: record)))
        }
        for name in ["activationPlanDigest", "inventoryDigest"] {
            var record = f.intentFields; record[name] = Fixture.digest(Data(name.utf8))
            XCTAssertNoThrow(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.json(record)))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(intent: record)))
        }
        var startup = f.startupFields; startup["activationAttempt"] = UUID().uuidString
        var record = f.intentFields; record["binding"] = startup
        XCTAssertNoThrow(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.json(record)))
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(intent: record)))
    }

    func testRequiresTheExactRecordedPolicyRevisionSnapshotAndCheckpoint() throws {
        let f = try Fixture(changedPolicy: true)
        for name in ["completionPolicySnapshotDigest", "completionCheckpointDigest"] {
            var binding = f.bindingFields; binding[name] = Fixture.digest(Data(name.utf8))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(binding: binding)))
        }
        var binding = f.bindingFields; binding["completionPolicyRevision"] = UUID().uuidString
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(binding: binding)))
        var record = f.intentFields
        record["committedPolicy"] = ["revision": f.startupPolicy.revision.uuidString,
            "bytes": try f.startupPolicy.storedBytes.base64EncodedString()]
        record["committedCheckpoint"] = try f.checkpoint.bytes.base64EncodedString()
        XCTAssertThrowsError(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.json(record)))
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(intent: record)))
    }

    func testRejectsResealedInventoryOutsideTheRecordedAccountAndInstalledScope() throws {
        let f = try Fixture()
        func changed(_ bytes: Data) -> Data { var copy = bytes; copy[copy.startIndex] ^= 64; return copy }
        let account = try XCTUnwrap(f.inventory.accounts.first)
        let replacements = [
            try f.inventoryBytes(macID: changed(f.inventory.macID)),
            try f.inventoryBytes(installationID: changed(f.inventory.installationID)),
            try f.inventoryBytes(releaseDigest: f.activationFixture.binding.provisioningReleaseDigest),
            try f.inventoryBytes(path: "/Applications/Other.app"),
            try f.inventoryBytes(account: .init(accountID: changed(account.accountID), ownerUID: account.ownerUID)),
            try f.inventoryBytes(account: .init(accountID: account.accountID, ownerUID: account.ownerUID + 1)),
            try f.inventoryBytes(enrolled: false),
        ]
        for inventory in replacements {
            var record = f.intentFields; record["inventoryDigest"] = Fixture.digest(inventory)
            XCTAssertNoThrow(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.json(record)))
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(intent: record, inventory: inventory)))
        }
    }

    func testRequiresTheRetainedV6ActivationAndItsExactStartupBinding() throws {
        let f = try Fixture()
        let ordinary = try f.activationFixture.source.f.f.plan.encoded
        var record = f.intentFields; record["activationPlanDigest"] = Fixture.digest(ordinary)
        XCTAssertNoThrow(try MachineUpdateRetainedSetupCompletionIntentRecord.decode(f.json(record)))
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(activation: ordinary, intent: record)))
        var binding = f.bindingFields, startup = f.startupFields
        startup["activationAttempt"] = UUID().uuidString; binding["startupBinding"] = startup
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.replacing(binding: binding)))
    }

    func testRejectsWrongPurposeVersionKeysNoncanonicalAndOversizedArchives() throws {
        let f = try Fixture()
        for key in f.fields.keys {
            var fields = f.fields; fields[key] = nil
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.bytes(fields)))
        }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(0)), (0, .unsigned(2)), (1, .text("wrong-purpose")), (2, .null),
            (3, .null), (4, .null), (5, .null), (6, .null),
        ] {
            var fields = f.fields; fields[key] = value
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(f.bytes(fields)))
        }
        for bytes in [Data(), try f.bytes() + Data([0]),
                      Data(repeating: 0, count: RuntimeRetainedSetupCompletionArchive.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(bytes)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
            }
        }
    }
}
