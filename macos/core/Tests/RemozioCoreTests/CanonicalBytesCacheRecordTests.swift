import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Second set of canonical-bytes cache checks: the retained bytes stay a pure function of each value's fields, equality
/// and coding ignore them, and decoding still rejects non-canonical input. Uses the existing owned fixtures only.
final class CanonicalBytesCacheRecordTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 4_194_304, maxDepth: 1, maxItems: 64)
    private let options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]

    private func jsonEncoder() -> JSONEncoder {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; return encoder
    }

    private func object(_ bytes: Data) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    }

    /// Re-encodes the leading `0: n` entry of a canonical CBOR map with a non-minimal one-byte argument.
    private func nonMinimalFirstEntry(_ bytes: Data) throws -> Data {
        let raw = [UInt8](bytes)
        XCTAssertGreaterThanOrEqual(raw.count, 3)
        XCTAssertEqual(raw[0] & 0xE0, 0xA0, "expected a short CBOR map header")
        XCTAssertEqual(raw[1], 0x00, "expected key 0 first")
        XCTAssertLessThan(raw[2], 24, "expected a small unsigned value")
        return Data([raw[0], raw[1], 0x18, raw[2]] + raw[3...])
    }

    func testRuntimeReleaseBindingCachesTheFreshJSONEncodingAndKeepsEqualityAndCoding() throws {
        let fixtureValue = try MachineUpdateRoleChallengeTests.Fixture().requirement().binding
        let fields = try object(jsonEncoder().encode(fixtureValue))
        let input = try JSONSerialization.data(withJSONObject: fields, options: options)
        let value = try RuntimeReleaseBinding.decode(input)
        XCTAssertEqual(value, fixtureValue)
        let fresh = try jsonEncoder().encode(value)
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)
        XCTAssertEqual(Set(try object(fresh).keys), [
            "formatVersion", "activationAttempt", "macID", "installationID", "accountID", "candidateDigest",
            "sourceInventoryDigest", "admissionDigest", "sourceAccountDigest", "runtimeReferenceDigest", "sourcePolicyRevision",
            "sourcePolicyDigest", "previousInstalledReleaseDigest", "installedReleaseDigest", "updateID", "startupPolicyDigest",
            "completionPolicyDigest"])

        var changed = fields
        changed["completionPolicyDigest"] = MachineUpdateActivationRecord.digest(Data("changed".utf8)).base64EncodedString()
        let other = try RuntimeReleaseBinding.decode(JSONSerialization.data(withJSONObject: changed, options: options))
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other, value)

        let text = try XCTUnwrap(String(data: input, encoding: .utf8))
        for noncanonical in [Data((" " + text).utf8), Data(text.replacingOccurrences(of: ",", with: ", ").utf8),
                             try JSONSerialization.data(withJSONObject: fields, options: [.prettyPrinted, .sortedKeys])] {
            XCTAssertThrowsError(try RuntimeReleaseBinding.decode(noncanonical)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .invalidRecord)
            }
        }
    }

    func testRuntimeMaterialReferenceCachesTheFreshCBOREncodingAndKeepsEquality() throws {
        let f = try RetainedSetupConsumerHostArchiveTests.Fixture()
        let input = try f.reference.encoded, value = try RuntimeMaterialReference.decode(input)
        XCTAssertEqual(value, f.reference)
        var fields: [UInt64: CBORValue] = [0: .unsigned(value.formatVersion), 1: .bytes(value.materialID),
            2: .bytes(try value.services.encoded), 3: .bytes(value.materialDigest), 4: .bytes(value.transportPublicKeyInfo),
            5: .bytes(try value.gateway.encode())]
        if let activity = value.serviceActivity { fields[6] = .bytes(try activity.encoded) }
        if let audit = value.auditDeliveryVersion { fields[7] = .unsigned(audit) }
        let fresh = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)

        let other = try RuntimeMaterialReference(materialID: value.materialID, services: value.services,
            materialDigest: value.materialDigest, transportPublicKeyInfo: value.transportPublicKeyInfo, gateway: value.gateway)
        XCTAssertNotNil(value.serviceActivity)
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other, value)

        XCTAssertThrowsError(try RuntimeMaterialReference.decode(nonMinimalFirstEntry(input)))
    }

    func testGatewaySettingsHostCachesTheFreshCBOREncodingAndKeepsEquality() throws {
        let f = try RetainedSetupConsumerHostArchiveTests.Fixture()
        let input = try f.bytes(stage: 3, role: .gateway)
        let value = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(input)
        let binding = try XCTUnwrap(value.retainedSetupBinding)
        let fresh = try DeterministicCBOR.encode(.map([0: .unsigned(value.formatVersion),
            1: .text("remozio-gateway-settings-consumer-host"), 2: .unsigned(value.role.rawValue),
            3: .bytes(try value.runtime.encoded), 4: .text(value.bundlePath), 5: .bytes(try value.codePolicy.bytes),
            6: .bytes(try binding.encoded), 7: .unsigned(RuntimeReleasePolicyStage.startup.rawValue)]), limits: limits)
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)
        XCTAssertEqual(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(input), value)

        let other = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(f.bytes(stage: 3, role: .transport))
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other, value)

        XCTAssertThrowsError(try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(nonMinimalFirstEntry(input)))
    }

    func testInstalledReleaseRecordCachesTheFreshJSONEncodingAndKeepsEqualityAndCoding() throws {
        try MachineUpdateReplacementTests.withRetainedRuntimeCompatibilityFixture { f in
            try f.inject()
            let input = try f.capture().runtime.setup.source.actual.installed.record.encoded
            let value = try MachineUpdateInstalledReleaseRecord.decode(input)
            let fresh = try jsonEncoder().encode(value)
            XCTAssertEqual(try value.encoded, fresh)
            XCTAssertEqual(try value.encoded, input)
            XCTAssertEqual(try value.encoded, try value.encoded)
            let fields = try object(fresh)
            XCTAssertEqual(Set(fields.keys), ["formatVersion", "id", "revision", "sourceSchemaVersion", "activationAttempt",
                "macID", "installationID", "inventoryRevision", "releaseDigest", "operands"])
            XCTAssertEqual(try MachineUpdateInstalledReleaseRecord.decode(input), value)

            var changed = fields
            changed["revision"] = UUID().uuidString
            let other = try MachineUpdateInstalledReleaseRecord.decode(JSONSerialization.data(withJSONObject: changed, options: options))
            XCTAssertNotEqual(try other.encoded, try value.encoded)
            XCTAssertNotEqual(other, value)

            let text = try XCTUnwrap(String(data: input, encoding: .utf8))
            for noncanonical in [Data((" " + text).utf8), Data(text.replacingOccurrences(of: ",", with: ", ").utf8)] {
                XCTAssertThrowsError(try MachineUpdateInstalledReleaseRecord.decode(noncanonical)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
        }
    }
}
