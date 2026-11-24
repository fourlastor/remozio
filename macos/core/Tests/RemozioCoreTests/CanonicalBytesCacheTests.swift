import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Checks that retained canonical bytes stay a pure function of each value's fields, that equality and coding ignore the
/// retained bytes, and that decoding still rejects non-canonical input. Uses the existing owned fixtures only.
final class CanonicalBytesCacheTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 4_194_304, maxDepth: 1, maxItems: 64)

    /// Re-encodes the leading `0: n` entry of a canonical CBOR map with a non-minimal one-byte argument.
    private func nonMinimalFirstEntry(_ bytes: Data) throws -> Data {
        let raw = [UInt8](bytes)
        XCTAssertGreaterThanOrEqual(raw.count, 3)
        XCTAssertEqual(raw[0] & 0xE0, 0xA0, "expected a short CBOR map header")
        XCTAssertEqual(raw[1], 0x00, "expected key 0 first")
        XCTAssertLessThan(raw[2], 24, "expected a small unsigned value")
        return Data([raw[0], raw[1], 0x18, raw[2]] + raw[3...])
    }

    private func cbor(_ fields: [UInt64: CBORValue]) throws -> Data {
        try DeterministicCBOR.encode(.map(fields), limits: limits)
    }

    func testReleaseBindingCachesTheFreshJSONEncodingAndKeepsEqualityAndCoding() throws {
        let f = try RetainedSetupActivationArchiveTests.Fixture()
        let input = try f.source.json(f.source.startup)
        let value = try RuntimeRetainedSetupReleaseBinding.decode(input)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let fresh = try encoder.encode(value)
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: fresh) as? [String: Any])
        XCTAssertEqual(Set(object.keys), Set(f.source.startup.keys))
        XCTAssertEqual(object.count, 28)
        XCTAssertEqual(try RuntimeRetainedSetupReleaseBinding.decode(input), value)

        var changed = f.source.startup
        changed["completionPolicyDigest"] = MachineUpdateActivationRecord.digest(Data("changed".utf8)).base64EncodedString()
        let other = try RuntimeRetainedSetupReleaseBinding.decode(f.source.json(changed))
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other, value)

        let text = try XCTUnwrap(String(data: input, encoding: .utf8))
        for noncanonical in [" " + text, text.replacingOccurrences(of: ",", with: ", ")] {
            XCTAssertThrowsError(try RuntimeRetainedSetupReleaseBinding.decode(Data(noncanonical.utf8))) {
                XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
            }
        }
        let pretty = try JSONSerialization.data(withJSONObject: f.source.startup, options: [.prettyPrinted, .withoutEscapingSlashes])
        XCTAssertThrowsError(try RuntimeRetainedSetupReleaseBinding.decode(pretty)) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
        }
    }

    func testActivationArchiveCachesTheFreshCBOREncoding() throws {
        let f = try RetainedSetupActivationArchiveTests.Fixture()
        let input = try f.bytes(), value = try RuntimeRetainedSetupActivationArchive.decode(input)
        let fresh = try cbor([0: .unsigned(RuntimeRetainedSetupActivationArchive.formatVersion),
            1: .bytes(value.reference.encoded), 2: .text(value.bundlePath), 3: .bytes(value.host.canonicalBytes),
            4: .bytes(value.transport.canonicalBytes), 5: .bytes(value.gatewaySettingsHost.encoded),
            6: value.phoneRoutingVersion.map(CBORValue.unsigned) ?? .null,
            7: value.phoneAuditVersion.map(CBORValue.unsigned) ?? .null,
            8: value.phoneUpdateSchedulingVersion.map(CBORValue.unsigned) ?? .null,
            9: .bytes(value.binding.encoded), 10: .bytes(value.inventory.canonicalBytes)])
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)

        var fields = f.fields; fields[6] = .unsigned(1)
        let other = try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields))
        XCTAssertNotEqual(try other.encoded, try value.encoded)

        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(nonMinimalFirstEntry(input)))
    }

    func testCompletionArchiveCachesTheFreshCBOREncodingAndKeepsEquality() throws {
        let f = try RetainedSetupCompletionArchiveTests.Fixture()
        let input = try f.bytes(), value = try RuntimeRetainedSetupCompletionArchive.decode(input)
        let fresh = try cbor([0: .unsigned(1), 1: .text("retained-setup-completion-archive"),
            2: .bytes(value.binding.encoded), 3: .bytes(value.originalActivationBytes),
            4: .bytes(value.completionIntentBytes), 5: .bytes(value.recordedInventoryBytes)])
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)
        XCTAssertEqual(try RuntimeRetainedSetupCompletionArchive.decode(input), value)

        let changed = try RetainedSetupCompletionArchiveTests.Fixture(changedPolicy: true)
        let other = try RuntimeRetainedSetupCompletionArchive.decode(changed.bytes())
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other, value)

        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionArchive.decode(nonMinimalFirstEntry(input))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
        }
    }

    func testCompletionConfigurationCachesTheFreshCBOREncoding() throws {
        let f = try RetainedSetupCompletionConfigurationTests.Fixture()
        let input = try f.bytes(), value = try RuntimeRetainedSetupCompletionConfiguration.decode(input)
        let fresh = try cbor([0: .unsigned(1), 1: .text(RuntimeRetainedSetupCompletionConfiguration.formatName),
            2: .bytes(value.archive.encoded), 3: .bytes(value.sourceDigest), 4: .bytes(value.host.canonicalBytes),
            5: .bytes(value.transport.canonicalBytes), 6: .bytes(value.gateway.encoded),
            7: .bytes(value.clients.presence.canonicalBytes), 8: .bytes(value.clients.pairing.canonicalBytes),
            9: .bytes(value.clients.frontend.canonicalBytes)])
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)

        var fields = f.fields
        fields[3] = .bytes(MachineUpdateActivationRecord.digest(Data("different recorded source".utf8)))
        let other = try RuntimeRetainedSetupCompletionConfiguration.decode(f.bytes(fields))
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other.sourceDigest, value.sourceDigest)

        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionConfiguration.decode(nonMinimalFirstEntry(input))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
        }
    }

    func testCompletionPublicationCachesTheFreshCBOREncoding() throws {
        let f = try RetainedSetupPromotionArchiveTests.Fixture()
        let input = try f.envelope(), value = try RuntimeRetainedSetupCompletionPublication.decode(input)
        let fresh = try cbor([0: .unsigned(1), 1: .text(RuntimeRetainedSetupCompletionPublication.formatName),
            2: .bytes(value.configuration.encoded), 3: .bytes(value.sourceClients.presence.canonicalBytes),
            4: .bytes(value.sourceClients.pairing.canonicalBytes), 5: .bytes(value.sourceClients.frontend.canonicalBytes)])
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)

        let other = try RuntimeRetainedSetupCompletionPublication.decode(
            RetainedSetupPromotionArchiveTests.Fixture(changedPolicy: true).envelope())
        XCTAssertNotEqual(try other.encoded, try value.encoded)

        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(nonMinimalFirstEntry(input))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
        }
    }

    func testPromotionIntentRecordCachesTheFreshCBOREncodingAndKeepsEquality() throws {
        let f = try RetainedSetupPromotionArchiveTests.Fixture()
        let input = try f.record(), value = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(input)
        let fresh = try cbor([0: .unsigned(MachineUpdateRetainedSetupPromotionIntentRecord.currentFormatVersion),
            1: .text(MachineUpdateRetainedSetupPromotionIntentRecord.formatName),
            2: .bytes(RetainedSetupPromotionArchiveTests.Fixture.bytes(value.id)),
            3: .bytes(RetainedSetupPromotionArchiveTests.Fixture.bytes(value.revision)),
            4: .unsigned(value.phase.rawValue), 5: .bytes(value.publicationBytes)])
        XCTAssertEqual(try value.encoded, fresh)
        XCTAssertEqual(try value.encoded, input)
        XCTAssertEqual(try value.encoded, try value.encoded)
        XCTAssertEqual(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(input), value)

        var fields = f.recordFields; fields[3] = .bytes(RetainedSetupPromotionArchiveTests.Fixture.bytes(UUID()))
        let other = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(fields))
        XCTAssertNotEqual(try other.encoded, try value.encoded)
        XCTAssertNotEqual(other, value)

        XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(nonMinimalFirstEntry(input))) {
            XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
        }
    }

    func testCacheRetainsOnlyTheFirstSuccessfulResult() throws {
        struct Refused: Error {}
        let cache = CanonicalBytesCache()
        var calls = 0
        XCTAssertThrowsError(try cache.bytes { calls += 1; throw Refused() })
        XCTAssertEqual(try cache.bytes { calls += 1; return Data([1]) }, Data([1]))
        XCTAssertEqual(try cache.bytes { calls += 1; return Data([2]) }, Data([1]))
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(CanonicalBytesCache(), cache)
    }
}
