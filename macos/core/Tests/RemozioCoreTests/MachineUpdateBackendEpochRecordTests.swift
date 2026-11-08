import Foundation
import XCTest
@testable import RemozioCore

final class MachineUpdateBackendEpochRecordTests: XCTestCase {
    private let account = Data(repeating: 7, count: 16)
    private let inactiveAccount = Data(repeating: 8, count: 16)
    private let digest = Data(repeating: 3, count: 32).base64EncodedString()

    func testHeaderCannotBeginPublicationBeforeCapturesAreRetained() throws {
        var header = fields()
        header.removeValue(forKey: "accounts")
        header["operands"] = []
        let bytes = try encode(header)
        let value = try MachineUpdateBackendEpochRecord.decode(bytes)
        XCTAssertEqual(try value.encoded, bytes)
        XCTAssertNil(value.accounts)
        XCTAssertThrowsError(try value.applying(.begin)) {
            XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
        }
    }

    func testBackendCommitRequiresEveryOtherFileToBePublished() throws {
        let retained = try MachineUpdateBackendEpochRecord.decode(encode(fields()))
        var value = try retained.applying(.begin)
        XCTAssertEqual(value.id, retained.id)
        XCTAssertNotEqual(value.revision, retained.revision)
        XCTAssertEqual(value.formatVersion, 2)
        XCTAssertEqual(value.publication?.entries.map(\.accountID), Array(repeating: account, count: 4))
        XCTAssertThrowsError(try value.applying(.prepare(inactiveAccount, .authority)))
        for file in [MachineUpdateBackendPublicationProgress.File.authority, .transport, .gateway] {
            XCTAssertThrowsError(try value.applying(.prepare(account, .commit))) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            value = try value.applying(.prepare(account, file)).applying(.complete(account, file))
        }
        value = try value.applying(.prepare(account, .commit)).applying(.complete(account, .commit))
        XCTAssertEqual(value.publication?.complete, true)
        XCTAssertEqual(try MachineUpdateBackendEpochRecord.decode(value.encoded), value)
    }

    func testDecoderRejectsAnEarlyCommitAndForeignPublicationEntry() throws {
        let retained = try MachineUpdateBackendEpochRecord.decode(encode(fields()))
        let publishing = try retained.applying(.begin)
        let bytes = try publishing.encoded
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let publication = try XCTUnwrap(original["publication"] as? [String: Any])
        let entries = try XCTUnwrap(publication["entries"] as? [[String: Any]])

        var earlyCommit = entries
        earlyCommit[3]["state"] = MachineUpdateBackendPublicationProgress.State.writing.rawValue
        var foreignAccount = entries
        foreignAccount[0]["accountID"] = inactiveAccount.base64EncodedString()
        for changed in [earlyCommit, foreignAccount] {
            var value = original
            value["publication"] = ["entries": changed]
            XCTAssertThrowsError(try MachineUpdateBackendEpochRecord.decode(encode(value)))
        }
    }

    func testDecoderRejectsMissingUnsortedAndDuplicateOperands() throws {
        let original = fields()
        let operands = try XCTUnwrap(original["operands"] as? [[String: Any]])
        for changed in [Array(operands.dropLast()), Array(operands.reversed()), [operands[0], operands[0], operands[2]]] {
            var value = original
            value["operands"] = changed
            XCTAssertThrowsError(try MachineUpdateBackendEpochRecord.decode(encode(value)))
        }
    }

    private func fields() -> [String: Any] {
        let id = "12345678-1234-1234-1234-123456789ABC"
        let accountID = account.base64EncodedString()
        let operands = (1...3).map { ["kind": $0, "accountID": accountID, "digest": digest] as [String: Any] }
        return [
            "formatVersion": 1, "id": id, "revision": id, "configurationEpochID": id,
            "configurationEpochDigest": digest, "macID": accountID, "installationID": accountID,
            "updateID": digest, "originalSourceDigest": digest, "currentSourceDigest": digest,
            "accounts": [["accountID": accountID, "sourceDigest": digest], ["accountID": inactiveAccount.base64EncodedString()]],
            "operands": operands,
        ]
    }

    private func encode(_ fields: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}
