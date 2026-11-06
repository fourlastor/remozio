import Foundation
import XCTest
@testable import RemozioCore

final class MachineUpdatePublicationProgressTests: XCTestCase {
    private let one = Data(repeating: 1, count: 16)
    private let two = Data(repeating: 2, count: 16)
    private func encoded(_ value: MachineUpdatePublicationProgress) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private func edit(_ value: MachineUpdatePublicationProgress,
        _ change: (inout [[String: Any]]) throws -> Void) throws -> MachineUpdatePublicationProgress {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded(value)) as? [String: Any])
        var entries = try XCTUnwrap(object["entries"] as? [[String: Any]])
        try change(&entries)
        object["entries"] = entries
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        return try JSONDecoder().decode(MachineUpdatePublicationProgress.self, from: bytes)
    }
    func testEachAccountStartsWithAllSixFilesInTheExactOrder() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [one, two])
        try value.validate(accountIDs: [one, two])
        XCTAssertEqual(value.entries.count, 12)
        XCTAssertEqual(value.entries.map(\.accountID), Array(repeating: one, count: 6) + Array(repeating: two, count: 6))
        XCTAssertEqual(value.entries.map(\.file), MachineUpdatePublicationProgress.File.allCases + MachineUpdatePublicationProgress.File.allCases)
        XCTAssertTrue(value.entries.allSatisfy { $0.state == .pending })
        XCTAssertFalse(value.complete)
    }
    func testAnEmptyFileIntentHasNoAccountOrHealthEvidence() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [])
        try value.validate(accountIDs: [])
        XCTAssertTrue(value.entries.isEmpty)
        XCTAssertTrue(value.complete)
        XCTAssertThrowsError(try value.state(accountID: one, file: .host)) { XCTAssertEqual($0 as? PreparationStoreError, .notFound) }
    }
    func testEveryFileRequiresWritingBeforePublished() throws {
        for file in MachineUpdatePublicationProgress.File.allCases {
            let value = MachineUpdatePublicationProgress(accountIDs: [one])
            let writing = try value.advancing(accountID: one, file: file, to: .writing)
            XCTAssertEqual(try writing.state(accountID: one, file: file), .writing)
            let published = try writing.advancing(accountID: one, file: file, to: .published)
            XCTAssertEqual(try published.state(accountID: one, file: file), .published)
            try published.validate(accountIDs: [one])
        }
    }
    func testAFileCannotSkipTheWritingIntent() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [one])
        for file in MachineUpdatePublicationProgress.File.allCases {
            XCTAssertThrowsError(try value.advancing(accountID: one, file: file, to: .published)) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
        }
    }
    func testAFileCannotRepeatOrReverseAnAcknowledgedTransition() throws {
        let start = MachineUpdatePublicationProgress(accountIDs: [one])
        let writing = try start.advancing(accountID: one, file: .host, to: .writing)
        for state in [MachineUpdatePublicationProgress.State.pending, .writing] {
            XCTAssertThrowsError(try writing.advancing(accountID: one, file: .host, to: state))
        }
        let published = try writing.advancing(accountID: one, file: .host, to: .published)
        for state in [MachineUpdatePublicationProgress.State.pending, .writing, .published] {
            XCTAssertThrowsError(try published.advancing(accountID: one, file: .host, to: state))
        }
    }
    func testPublishingOneFileDoesNotAdvanceAnotherFileOrAccount() throws {
        let start = MachineUpdatePublicationProgress(accountIDs: [one, two])
        let next = try start.advancing(accountID: one, file: .gateway, to: .writing)
            .advancing(accountID: one, file: .gateway, to: .published)
        for entry in next.entries {
            XCTAssertEqual(entry.state, entry.accountID == one && entry.file == .gateway ? .published : .pending)
        }
        XCTAssertFalse(next.complete)
    }
    func testCompletionRequiresEveryFileForEverySelectedAccount() throws {
        var value = MachineUpdatePublicationProgress(accountIDs: [one, two])
        for account in [one, two] {
            for file in MachineUpdatePublicationProgress.File.allCases {
                XCTAssertFalse(value.complete)
                value = try value.advancing(accountID: account, file: file, to: .writing)
                XCTAssertFalse(value.complete)
                value = try value.advancing(accountID: account, file: file, to: .published)
            }
        }
        XCTAssertTrue(value.complete)
        try value.validate(accountIDs: [one, two])
    }
    func testAnUnknownAccountCannotCreateOrAdvanceAFileEntry() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [one])
        XCTAssertThrowsError(try value.advancing(accountID: two, file: .host, to: .writing)) { XCTAssertEqual($0 as? PreparationStoreError, .notFound) }
        XCTAssertThrowsError(try value.state(accountID: two, file: .host)) { XCTAssertEqual($0 as? PreparationStoreError, .notFound) }
    }
    func testTheExpectedAccountSetMustBeUniqueAndCanonical() throws {
        for accounts in [[one, one], [two, one]] {
            let value = MachineUpdatePublicationProgress(accountIDs: accounts)
            XCTAssertThrowsError(try value.validate(accountIDs: accounts)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        }
    }
    func testTheExpectedAccountIDsMustHaveTheExactLength() throws {
        for count in [0, 15, 17] {
            let accounts = [Data(repeating: 1, count: count)]
            XCTAssertThrowsError(try MachineUpdatePublicationProgress(accountIDs: accounts).validate(accountIDs: accounts))
        }
    }
    func testAllOneHundredTwentyEightAccountsFitButTheNextAccountIsRefused() throws {
        let accounts = (1...128).map { Data(repeating: UInt8($0), count: 16) }
        let value = MachineUpdatePublicationProgress(accountIDs: accounts)
        XCTAssertEqual(value.entries.count, 768)
        try value.validate(accountIDs: accounts)
        let tooMany = accounts + [Data(repeating: 129, count: 16)]
        XCTAssertThrowsError(try MachineUpdatePublicationProgress(accountIDs: tooMany).validate(accountIDs: tooMany))
    }
    func testDecodedEntriesCannotBeMissingDuplicatedOrReordered() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [one, two])
        let missing = try edit(value) { $0.removeLast() }
        let duplicate = try edit(value) { $0.append($0[0]) }
        let reordered = try edit(value) { $0.swapAt(0, 1) }
        for changed in [missing, duplicate, reordered] {
            XCTAssertThrowsError(try changed.validate(accountIDs: [one, two])) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        }
    }
    func testDecodedEntriesCannotSubstituteAnAccountAtTheSameIndex() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [one, two])
        let changed = try edit(value) { $0[0]["accountID"] = two.base64EncodedString() }
        XCTAssertThrowsError(try changed.validate(accountIDs: [one, two]))
        XCTAssertThrowsError(try value.validate(accountIDs: [one]))
    }
    func testPartialProgressRoundTripsWithoutAcknowledgingAnUnfinishedFile() throws {
        let value = try MachineUpdatePublicationProgress(accountIDs: [one])
            .advancing(accountID: one, file: .host, to: .writing)
        let decoded = try JSONDecoder().decode(MachineUpdatePublicationProgress.self, from: encoded(value))
        XCTAssertEqual(decoded, value)
        try decoded.validate(accountIDs: [one])
        XCTAssertEqual(try decoded.state(accountID: one, file: .host), .writing)
        XCTAssertFalse(decoded.complete)
    }
    func testAnUnknownEncodedStateIsRejected() throws {
        let value = MachineUpdatePublicationProgress(accountIDs: [one])
        XCTAssertThrowsError(try edit(value) { $0[0]["state"] = 3 })
    }
    func testReadingAndAdvancingACopyDoNotMutateTheRetainedValue() throws {
        let original = MachineUpdatePublicationProgress(accountIDs: [one])
        let before = try encoded(original)
        XCTAssertEqual(try original.state(accountID: one, file: .host), .pending)
        let changed = try original.advancing(accountID: one, file: .host, to: .writing)
        XCTAssertEqual(try encoded(original), before)
        XCTAssertEqual(try original.state(accountID: one, file: .host), .pending)
        XCTAssertNotEqual(changed, original)
    }
}
