import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned fixture records and synthetic archive facts. It does not register jobs or prove native startup.
final class RetainedSetupConsumerHostArchiveTests: XCTestCase {
    final class Fixture {
        let f: ConsumerHostMetadataFixture
        let reference: RuntimeMaterialReference
        let startup: [String: Any]
        let completed: [String: Any]
        let limits = try! CBORLimits(maxBytes: 65536, maxDepth: 2, maxItems: 128)

        init() throws {
            f = try ConsumerHostMetadataFixture()
            reference = try f.reference()
            let services = reference.services
            let digest = MachineUpdateActivationRecord.digest(Data("archive fixture".utf8)).base64EncodedString()
            var installed = services.releaseDigest
            installed[installed.startIndex] ^= 128
            var startup: [String: Any] = [
                "formatVersion": 1, "macID": services.macID.base64EncodedString(),
                "installationID": services.installationID.base64EncodedString(),
                "accountID": services.accountID.base64EncodedString(), "ownerUID": services.ownerUID,
                "activationAttempt": UUID().uuidString,
                "provisioningReleaseDigest": services.releaseDigest.base64EncodedString(),
                "installedReleaseDigest": installed.base64EncodedString(),
                "runtimeReferenceDigest": MachineUpdateActivationRecord.digest(try reference.encoded).base64EncodedString(),
                "startupPolicyDigest": MachineUpdateActivationRecord.digest(try f.f.plan.host.codePolicy.bytes).base64EncodedString(),
                "completionPolicyDigest": MachineUpdateActivationRecord.digest(try f.f.plan.host.codePolicy.bytes).base64EncodedString(),
            ]
            for name in ["candidateDigest", "admissionDigest", "updateID", "stableSealDigest", "installedEpochDigest",
                         "sealedInventoryDigest", "sourceAccountDigest", "preparationDigest", "initializationDigest",
                         "provisioningInventoryDigest", "previousInstalledReleaseDigest", "retainedSourceDigest", "policyIntentDigest",
                         "sourcePolicyDigest", "sourceCheckpointDigest", "startupPolicySnapshotDigest", "startupCheckpointDigest"] {
                startup[name] = digest
            }
            self.startup = startup
            completed = ["formatVersion": 1, "startupBinding": startup,
                "recordedCompletionDigest": digest, "activationPlanDigest": digest, "recordedInventoryDigest": digest,
                "completionPolicyRevision": UUID().uuidString, "completionPolicySnapshotDigest": digest,
                "completionCheckpointDigest": digest]
        }
        func json(_ fields: [String: Any]) throws -> Data {
            try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        }
        func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
            guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else {
                throw GatewayPreparationError.invalidRecord
            }
            return fields
        }
        func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
            try DeterministicCBOR.encode(.map(fields), limits: limits)
        }
        func bytes(stage: UInt64, role: GatewaySettingsConsumerRole = .transport,
                   startup: [String: Any]? = nil) throws -> Data {
            let host = try f.host(role, runtime: reference)
            var fields = try map(host.encoded)
            fields[0] = .unsigned(stage)
            var binding = completed
            binding["startupBinding"] = startup ?? self.startup
            fields[6] = .bytes(try json(stage == 3 ? startup ?? self.startup : binding))
            fields[7] = .unsigned(stage == 3 ? RuntimeReleasePolicyStage.startup.rawValue : RuntimeReleasePolicyStage.completion.rawValue)
            return try encode(fields)
        }
    }

    func testArchiveReadsBothRetainedStagesForBothRolesAndStartupStillRejectsThem() throws {
        let f = try Fixture()
        for role in GatewaySettingsConsumerRole.allCases {
            for stage in [UInt64(3), UInt64(4)] {
                let bytes = try f.bytes(stage: stage, role: role)
                let host = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(bytes)
                XCTAssertEqual(try host.encoded, bytes)
                XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(host.encoded), host)
                XCTAssertEqual(host.formatVersion, stage)
                XCTAssertEqual(host.role, role)
                XCTAssertEqual(host.runtime, f.reference)
                XCTAssertEqual(host.policyStage, stage == 3 ? .startup : .completion)
                XCTAssertNil(host.releaseBinding)
                XCTAssertEqual(host.retainedSetupBinding != nil, stage == 3)
                XCTAssertEqual(host.retainedSetupCompletionBinding != nil, stage == 4)
                let startup = try RuntimeRetainedSetupReleaseBinding.decode(f.json(f.startup))
                XCTAssertEqual(host.installedReleaseDigest, startup.installedReleaseDigest)
                XCTAssertNotEqual(host.installedReleaseDigest, host.runtime.services.releaseDigest)
                XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decode(bytes))
                XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForUpdateHealthStartup(bytes)) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
                XCTAssertEqual(host.description, "GatewaySettingsConsumerHostConfiguration(redacted)")
            }
        }
    }
    func testTransportArchiveReadsRetainedHostsWithoutEnablingItsStartupDecoder() throws {
        let f = try Fixture(), original = f.f.f.plan.transport
        for stage in [UInt64(3), UInt64(4)] {
            let host = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(f.bytes(stage: stage))
            let transport = try TransportPairingStartupConfiguration(transport: original.transport,
                control: original.control, wake: original.wake, relayPort: original.relayPort, settingsHost: host)
            let archived = try TransportPairingStartupConfiguration.decodeForReleaseArchive(transport.canonicalBytes)
            XCTAssertEqual(archived.settingsHost, host)
            XCTAssertEqual(archived.canonicalBytes, transport.canonicalBytes)
            XCTAssertThrowsError(try TransportSettingsConsumerBootstrap.decodeForUpdateHealthStartup(transport.canonicalBytes)) {
                XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
            }
            XCTAssertThrowsError(try TransportPairingStartupConfiguration.decode(transport.canonicalBytes))
            XCTAssertThrowsError(try archived.requireLegacyStartup()) {
                XCTAssertEqual($0 as? TransportPairingControlError, .unsupportedVersion)
            }
        }
    }
    func testArchiveRejectsEachHistoricalScopeAndStagePolicyDigestMismatch() throws {
        let f = try Fixture()
        for stage in [UInt64(3), UInt64(4)] {
            for name in ["macID", "installationID", "accountID", "provisioningReleaseDigest", "runtimeReferenceDigest",
                         stage == 3 ? "startupPolicyDigest" : "completionPolicyDigest"] {
                var binding = f.startup
                var bytes = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(binding[name] as? String)))
                bytes[bytes.index(before: bytes.endIndex)] ^= 64
                binding[name] = bytes.base64EncodedString()
                XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(
                    f.bytes(stage: stage, startup: binding)), name) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .changedScope, name)
                }
            }
            var binding = f.startup
            binding["ownerUID"] = f.reference.services.ownerUID + 1
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(
                f.bytes(stage: stage, startup: binding))) {
                XCTAssertEqual($0 as? RuntimeActivationError, .changedScope)
            }
        }
    }
    func testArchiveRejectsWrongPurposeStageUnknownFieldsAndNoncanonicalBytes() throws {
        let f = try Fixture()
        for stage in [UInt64(3), UInt64(4)] {
            let bytes = try f.bytes(stage: stage)
            let fields = try f.map(bytes)
            for (key, value): (UInt64, CBORValue) in [
                (0, .unsigned(5)), (1, .text("wrong-purpose")), (2, .unsigned(3)), (3, .bytes(Data())),
                (4, .text("relative.app")), (5, .bytes(Data())), (6, .bytes(Data())),
                (7, .unsigned(stage == 3 ? 2 : 1)), (8, .null),
            ] {
                var changed = fields; changed[key] = value
                XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(f.encode(changed)))
            }
            for key in fields.keys {
                var changed = fields; changed[key] = nil
                XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(f.encode(changed)))
            }
            var startup = f.startup; startup["unknown"] = true
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(
                f.bytes(stage: stage, startup: startup)))
            XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(bytes + Data([0])))
        }
        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(Data(repeating: 0, count: 32769)))
    }
    func testArchiveCannotPassTheOrdinaryAccountScopeCheckWithTheSameLegacyInputs() throws {
        let f = try Fixture(), account = f.f.f.account
        let inventory = try XCTUnwrap(f.f.f.machine.inventory())
        for role in GatewaySettingsConsumerRole.allCases {
            let legacy = try f.f.host(role, runtime: f.reference)
            XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decode(legacy.encoded), legacy)
            XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(legacy.encoded), legacy)
            XCTAssertNoThrow(try legacy.validate(account: account, inventory: inventory))
            for stage in [UInt64(3), UInt64(4)] {
                let archive = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(f.bytes(stage: stage, role: role))
                XCTAssertEqual(archive.role, legacy.role)
                XCTAssertEqual(archive.runtime, legacy.runtime)
                XCTAssertEqual(archive.bundlePath, legacy.bundlePath)
                XCTAssertEqual(archive.codePolicy, legacy.codePolicy)
                XCTAssertThrowsError(try archive.validate(account: account, inventory: inventory)) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
            }
        }
    }
}
