import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

/// Uses owned fixture metadata and an in-memory table. It proves no actual publication, migration, or native health.
final class RetainedSetupPromotionArchiveTests: XCTestCase {
    final class Fixture {
        let configuration: RetainedSetupCompletionConfigurationTests.Fixture
        let envelopeFields: [UInt64: CBORValue]
        let recordFields: [UInt64: CBORValue]
        let id: UUID
        let revision: UUID
        let limits = try! CBORLimits(maxBytes: 4_194_304, maxDepth: 1, maxItems: 64)

        init(changedPolicy: Bool = false) throws {
            let limits = try CBORLimits(maxBytes: 4_194_304, maxDepth: 1, maxItems: 64)
            let configuration = try RetainedSetupCompletionConfigurationTests.Fixture(changedPolicy: changedPolicy)
            let envelopeFields: [UInt64: CBORValue] = [
                0: .unsigned(1), 1: .text("runtime.retained-setup-completion-publication"),
                2: .bytes(try configuration.bytes()), 3: .bytes(configuration.clients.presence.canonicalBytes),
                4: .bytes(configuration.clients.pairing.canonicalBytes), 5: .bytes(configuration.clients.frontend.canonicalBytes),
            ]
            let envelope = try DeterministicCBOR.encode(.map(envelopeFields), limits: limits)
            _ = try RuntimeRetainedSetupCompletionPublication.decode(envelope)
            let id = UUID(), revision = UUID()
            self.configuration = configuration; self.envelopeFields = envelopeFields; self.id = id; self.revision = revision
            // These two wire maps come from donor source. No bytes were produced by executing the donor.
            recordFields = [0: .unsigned(1), 1: .text("authority.retained-setup-promotion-intent"),
                2: .bytes(Self.bytes(id)), 3: .bytes(Self.bytes(revision)), 4: .unsigned(1), 5: .bytes(envelope)]
        }
        static func bytes(_ uuid: UUID) -> Data {
            var value = uuid.uuid; return withUnsafeBytes(of: &value) { Data($0) }
        }
        func encode(_ fields: [UInt64: CBORValue]) throws -> Data {
            try DeterministicCBOR.encode(.map(fields), limits: limits)
        }
        func envelope(_ fields: [UInt64: CBORValue]? = nil) throws -> Data { try encode(fields ?? envelopeFields) }
        func record(_ fields: [UInt64: CBORValue]? = nil) throws -> Data { try encode(fields ?? recordFields) }
    }

    func testPublicationMapPreservesAllSixPreviousAndSelectedArtifacts() throws {
        for changed in [false, true] {
            let f = try Fixture(changedPolicy: changed), bytes = try f.envelope()
            let value = try RuntimeRetainedSetupCompletionPublication.decode(bytes)
            XCTAssertEqual(try value.encoded, bytes)
            XCTAssertEqual(try value.configuration.encoded, try f.configuration.bytes())
            let original = try value.configuration.archive.originalActivation()
            let previous = [original.host.canonicalBytes, original.transport.canonicalBytes,
                try original.gatewaySettingsHost.encoded, f.configuration.clients.presence.canonicalBytes,
                f.configuration.clients.pairing.canonicalBytes, f.configuration.clients.frontend.canonicalBytes]
            let selected = [value.configuration.host.canonicalBytes, value.configuration.transport.canonicalBytes,
                try value.configuration.gateway.encoded, value.configuration.clients.presence.canonicalBytes,
                value.configuration.clients.pairing.canonicalBytes, value.configuration.clients.frontend.canonicalBytes]
            XCTAssertEqual(value.artifacts.map(\.kind), RuntimeRetainedSetupCompletionPublication.File.allCases)
            XCTAssertEqual(value.artifacts.map(\.previous), previous)
            XCTAssertEqual(value.artifacts.map(\.selected), selected)
            for artifact in value.artifacts { XCTAssertNoThrow(try artifact.file.validate()) }
            XCTAssertEqual(value.description, "RuntimeRetainedSetupCompletionPublication(redacted)")
            XCTAssertEqual(value.debugDescription, value.description)
        }
    }

    func testPublicationRequiresTheExactRecordedSourceDigestAndClientBytes() throws {
        let f = try Fixture(), other = try Fixture()
        var configuration = f.configuration.fields
        configuration[3] = .bytes(MachineUpdateActivationRecord.digest(Data("different recorded source".utf8)))
        let configurationBytes = try f.configuration.bytes(configuration)
        XCTAssertNoThrow(try RuntimeRetainedSetupCompletionConfiguration.decode(configurationBytes))
        var fields = f.envelopeFields; fields[2] = .bytes(configurationBytes)
        XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(f.envelope(fields)))
        for key in UInt64(3)...5 {
            fields = f.envelopeFields; fields[key] = other.envelopeFields[key]
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(f.envelope(fields)))
        }
    }

    func testPublicationRejectsMissingUnknownMalformedNoncanonicalAndOversizedRecords() throws {
        let f = try Fixture()
        for key in f.envelopeFields.keys {
            var fields = f.envelopeFields; fields[key] = nil
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(f.envelope(fields)))
        }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(0)), (0, .unsigned(2)), (1, .text("wrong-purpose")), (6, .null),
        ] {
            var fields = f.envelopeFields; fields[key] = value
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(f.envelope(fields)))
        }
        for key in UInt64(2)...5 {
            for value in [CBORValue.null, .bytes(Data([0]))] {
                var fields = f.envelopeFields; fields[key] = value
                XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(f.envelope(fields)))
            }
        }
        for bytes in [Data(), try f.envelope() + Data([0]),
                      Data(repeating: 0, count: RuntimeRetainedSetupCompletionPublication.maximumBytes + 1)] {
            XCTAssertThrowsError(try RuntimeRetainedSetupCompletionPublication.decode(bytes)) {
                XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
            }
        }
    }

    func testPromotionMapReadsAllThreeHistoricalPhasesAndExactIdentities() throws {
        let f = try Fixture()
        for phase in [UInt64(1), 2, 3] {
            var fields = f.recordFields; fields[4] = .unsigned(phase)
            let bytes = try f.record(fields), value = try MachineUpdateRetainedSetupPromotionIntentRecord.decode(bytes)
            XCTAssertEqual(value.id, f.id)
            XCTAssertEqual(value.revision, f.revision)
            XCTAssertEqual(value.phase.rawValue, phase)
            XCTAssertEqual(value.publicationBytes, try f.envelope())
            XCTAssertEqual(try value.publication().encoded, try f.envelope())
            XCTAssertEqual(try value.encoded, bytes)
            XCTAssertEqual(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(value.encoded), value)
            XCTAssertEqual(value.description, "MachineUpdateRetainedSetupPromotionIntentRecord(redacted)")
            XCTAssertEqual(value.debugDescription, value.description)
        }
    }

    func testPromotionRejectsInvalidIdentityLengthsAndUnknownPhases() throws {
        let f = try Fixture()
        for key in [UInt64(2), 3] {
            for count in [0, 15, 17] {
                var fields = f.recordFields; fields[key] = .bytes(Data(repeating: 1, count: count))
                XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(fields)))
            }
        }
        for phase in [UInt64(0), 4, .max] {
            var fields = f.recordFields; fields[4] = .unsigned(phase)
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(fields)))
        }
    }

    func testPromotionRejectsMissingUnknownMalformedNoncanonicalAndOversizedRecords() throws {
        let f = try Fixture()
        for key in f.recordFields.keys {
            var fields = f.recordFields; fields[key] = nil
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(fields)))
        }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(0)), (0, .unsigned(2)), (1, .text("wrong-purpose")), (2, .null),
            (3, .null), (4, .text("prepared")), (5, .null), (5, .bytes(Data())), (5, .bytes(Data([0]))), (6, .null),
            (5, .bytes(Data(repeating: 0, count: RuntimeRetainedSetupCompletionPublication.maximumBytes + 1))),
        ] {
            var fields = f.recordFields; fields[key] = value
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(f.record(fields)))
        }
        for bytes in [Data(), try f.record() + Data([0]),
                      Data(repeating: 0, count: MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes + 1)] {
            XCTAssertThrowsError(try MachineUpdateRetainedSetupPromotionIntentRecord.decode(bytes)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
        }
    }

    func testPromotionTableChecksBlobTypesIdentityLengthsAndRecordBounds() throws {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(":memory:", &db), SQLITE_OK)
        let opened = try XCTUnwrap(db)
        defer { sqlite3_close(opened) }
        XCTAssertEqual(sqlite3_exec(opened, MachineUpdateRetainedSetupPromotionStorage.createSQL, nil, nil, nil), SQLITE_OK)
        func insert(account: String = "zeroblob(16)", id: String = "zeroblob(16)",
                    revision: String = "zeroblob(16)", record: String = "zeroblob(1)") -> Int32 {
            XCTAssertEqual(sqlite3_exec(opened, "DELETE FROM retained_setup_promotion_intents_v1", nil, nil, nil), SQLITE_OK)
            let sql = "INSERT INTO retained_setup_promotion_intents_v1(account,id,revision,record) VALUES(\(account),\(id),\(revision),\(record))"
            return sqlite3_exec(opened, sql, nil, nil, nil)
        }
        XCTAssertEqual(insert(), SQLITE_OK)
        XCTAssertEqual(insert(record: "zeroblob(\(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes))"), SQLITE_OK)
        for count in [15, 17] {
            XCTAssertNotEqual(insert(account: "zeroblob(\(count))"), SQLITE_OK)
            XCTAssertNotEqual(insert(id: "zeroblob(\(count))"), SQLITE_OK)
            XCTAssertNotEqual(insert(revision: "zeroblob(\(count))"), SQLITE_OK)
        }
        XCTAssertNotEqual(insert(record: "zeroblob(0)"), SQLITE_OK)
        XCTAssertNotEqual(insert(record: "zeroblob(\(MachineUpdateRetainedSetupPromotionIntentRecord.maximumBytes + 1))"), SQLITE_OK)
        XCTAssertNotEqual(insert(account: "'abcdefghijklmnop'"), SQLITE_OK)
        XCTAssertNotEqual(insert(record: "'x'"), SQLITE_OK)
    }

    func testPromotionReaderRequirementsGrantNoWriteDirection() throws {
        let requirements = try MachineUpdateRetainedSetupPromotionStorage.readerRequirements
        XCTAssertTrue(requirements.allSatisfy { $0.writeVersions.isEmpty })
        XCTAssertEqual(Set(requirements.map(\.role)), [.authority, .setupController])
        XCTAssertTrue(requirements.contains { $0.name == MachineUpdateRetainedSetupPromotionIntentRecord.formatName && $0.readVersions == [1] })
    }
}
