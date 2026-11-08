import Foundation
import XCTest
@testable import RemozioCore

final class MachineUpdateConfigurationEpochRecordTests: XCTestCase {
    private let accountID = Data(repeating: 7, count: 16)

    func testCanonicalRecordPreservesThePendingPublicationPlan() throws {
        let bytes = try encode(fields())
        let record = try MachineUpdateConfigurationEpochRecord.decode(bytes)
        XCTAssertEqual(try record.encoded, bytes)
        XCTAssertNil(record.publication)

        let publishing = try record.applying(.begin)
        let progress = try XCTUnwrap(publishing.publication)
        XCTAssertEqual(publishing.id, record.id)
        XCTAssertEqual(publishing.formatVersion, 2)
        XCTAssertEqual(progress.entries.map(\.accountID), Array(repeating: accountID, count: 6))
        XCTAssertEqual(try progress.state(accountID: accountID, file: .host), .pending)
        XCTAssertThrowsError(try publishing.applying(.complete(accountID, .host)))

        let writing = try publishing.applying(.prepare(accountID, .host))
        let published = try writing.applying(.complete(accountID, .host))
        XCTAssertEqual(try published.publication?.state(accountID: accountID, file: .host), .published)
        XCTAssertEqual(try MachineUpdateConfigurationEpochRecord.decode(published.encoded), published)
    }

    func testRecordRejectsMissingOrForeignOperands() throws {
        let original = fields()
        let operands = try XCTUnwrap(original["operands"] as? [[String: Any]])
        var missing = original
        missing["operands"] = Array(operands.dropLast())
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochRecord.decode(encode(missing)))

        var foreign = original
        var changed = operands
        changed[0]["account"] = Data(repeating: 8, count: 16).base64EncodedString()
        foreign["operands"] = changed
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochRecord.decode(encode(foreign)))
    }

    func testProvenanceRequiresTheCorrespondingFormat() throws {
        var value = fields()
        var accounts = try XCTUnwrap(value["accounts"] as? [[String: Any]])
        accounts[0]["provisioningDigest"] = digest
        value["accounts"] = accounts
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochRecord.decode(encode(value)))
        value["formatVersion"] = 3
        let record = try MachineUpdateConfigurationEpochRecord.decode(encode(value))
        XCTAssertTrue(record.carriesProvenance)
        XCTAssertEqual(try record.applying(.begin).formatVersion, 4)
    }

    func testRetainedRequirementsFollowTheRecordFormat() throws {
        typealias Record = MachineUpdateConfigurationEpochRecord
        func names(_ formats: [RetainedReleaseFormat]) -> Set<String> { Set(formats.map(\.name)) }
        let plain = try encode(fields())
        XCTAssertTrue(try Record.retainedRequirements(plain).isEmpty)
        let publishing = try Record.decode(plain).applying(.begin)
        XCTAssertEqual(publishing.formatVersion, 2)
        XCTAssertEqual(try Record.retainedRequirements(publishing.encoded).map(\.readVersions), try Record.publicationRequirements.map(\.readVersions))

        var value = fields()
        var accounts = try XCTUnwrap(value["accounts"] as? [[String: Any]])
        accounts[0]["provisioningDigest"] = digest
        value["accounts"] = accounts
        value["formatVersion"] = 3
        let provenance = try Record.decode(encode(value))
        for record in [provenance, try provenance.applying(.begin)] {
            let required = try Record.retainedRequirements(record.encoded)
            XCTAssertTrue(names(required).contains(MachineUpdateProvisioningHistory.formatName), "\(record.formatVersion)")
            XCTAssertTrue(required.contains { $0.name == Record.formatName && $0.readVersions.contains(record.formatVersion) }, "\(record.formatVersion)")
        }
    }

    func testStorageRowsBindEveryPayloadToTheExactEpoch() throws {
        let payload = Data([1, 2, 3])
        let record = try MachineUpdateConfigurationEpochRecord.decode(encode(fields(
            operandDigest: MachineUpdateActivationRecord.digest(payload).base64EncodedString())))
        let epoch = withUnsafeBytes(of: record.id.uuid) { Data($0) }
        let revision = withUnsafeBytes(of: record.revision.uuid) { Data($0) }
        typealias Row = MachineUpdateConfigurationEpochRows.Row
        let header = Row(kind: 0, account: MachineUpdateConfigurationEpochRecord.globalAccount,
            epoch: epoch, revision: revision, payload: try record.encoded)
        let rows = [header] + record.operands.map {
            Row(kind: $0.kind, account: $0.account, epoch: epoch, revision: revision, payload: payload)
        }
        XCTAssertNil(try MachineUpdateConfigurationEpochRows.decodeRecord([], macID: record.macID))
        XCTAssertEqual(try MachineUpdateConfigurationEpochRows.decodeRecord(rows, macID: record.macID), record)
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochRows.decodeRecord(rows, macID: Data()))
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochRows.decodeRecord(Array(rows.dropLast()), macID: record.macID))

        var reordered = rows
        reordered.swapAt(1, 2)
        XCTAssertThrowsError(try MachineUpdateConfigurationEpochRows.decodeRecord(reordered, macID: record.macID))
        let first = rows[1]
        for changed in [
            Row(kind: first.kind, account: first.account, epoch: epoch, revision: Data(repeating: 0, count: 16), payload: payload),
            Row(kind: first.kind, account: first.account, epoch: epoch, revision: revision, payload: Data([0])),
        ] {
            var invalid = rows
            invalid[1] = changed
            XCTAssertThrowsError(try MachineUpdateConfigurationEpochRows.decodeRecord(invalid, macID: record.macID))
        }
    }

    private var digest: String { Data(repeating: 3, count: 32).base64EncodedString() }

    private func fields(operandDigest: String? = nil) -> [String: Any] {
        let identifier = "12345678-1234-1234-1234-123456789ABC"
        let account = accountID.base64EncodedString()
        let global = Data([0]).base64EncodedString()
        let operands = (1...9).map { kind in
            ["kind": kind, "account": kind < 5 ? account : global, "digest": operandDigest ?? digest] as [String: Any]
        }
        return [
            "formatVersion": 1, "id": identifier, "revision": identifier, "activationAttempt": identifier,
            "macID": account, "installationID": account, "updateID": digest, "candidateDigest": digest,
            "inventoryDigest": digest, "admissionDigest": digest, "installedReleaseDigest": digest,
            "sourceMachineDigest": digest,
            "accounts": [["accountID": account, "ownerUID": 501, "sourceDigest": digest, "runtimeDigest": digest,
                          "configurationPublished": true, "policyRevision": identifier]],
            "operands": operands,
        ]
    }

    private func encode(_ fields: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}
