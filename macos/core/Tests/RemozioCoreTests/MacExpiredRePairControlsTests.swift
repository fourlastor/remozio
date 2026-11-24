import Foundation
import XCTest
@testable import RemozioCore

final class MacExpiredRePairControlsTests: XCTestCase {
    @MainActor
    func testEmptyListIsAvailable() async {
        let controls = MacExpiredRePairControls(load: { [] }, discard: { _ in XCTFail("Unexpected discard") })
        await controls.refresh()
        XCTAssertEqual(controls.records, [])
        XCTAssertFalse(controls.unavailable)
        XCTAssertNil(controls.notice)
    }

    @MainActor
    func testUnsupportedOperationLeavesExpiredAttemptsUnavailable() async {
        let controls = MacExpiredRePairControls(load: { throw AuthorityPairingChannelError.unsupportedVersion },
            discard: { _ in XCTFail("Unexpected discard") })
        await controls.refresh()
        XCTAssertNil(controls.records)
        XCTAssertTrue(controls.unavailable)
        XCTAssertNil(controls.notice)
    }

    @MainActor
    func testCancelledAuthorizationKeepsTheSelectedAttempt() async {
        let record = Self.record(1)
        var reads = 0
        let controls = MacExpiredRePairControls(load: { reads += 1; return [record] },
            discard: { _ in throw SetupAdministratorAuthorizationError.cancelled })
        await controls.refresh()
        await controls.discardConfirmed(record)
        XCTAssertEqual(controls.records, [record])
        XCTAssertEqual(controls.notice, .authorizationCancelled)
        XCTAssertEqual(reads, 1)
    }

    @MainActor
    func testLostReplyChecksTheExactAttemptWithoutRepeatingTheDiscard() async {
        let record = Self.record(1), replacement = Self.record(1, attempt: 2)
        var discards = 0
        let controls = MacExpiredRePairControls(load: { discards == 0 ? [record] : [replacement] },
            discard: { selected in
                XCTAssertEqual(selected, record)
                discards += 1
                throw AuthorityPairingChannelError.closed
            })
        await controls.refresh()
        await controls.discardConfirmed(record)
        await controls.discardConfirmed(record)
        XCTAssertEqual(discards, 1)
        XCTAssertEqual(controls.records, [replacement])
        XCTAssertEqual(controls.notice, .noLongerListed)
    }

    @MainActor
    func testLostReplyWithAttemptStillListedOrListUnavailableStaysUnconfirmed() async {
        let record = Self.record(1)
        for loseList in [false, true] {
            var discards = 0
            let controls = MacExpiredRePairControls(load: {
                if loseList && discards > 0 { throw AuthorityPairingChannelError.closed }
                return [record]
            }, discard: { _ in
                discards += 1
                throw AuthorityPairingChannelError.closed
            })
            await controls.refresh()
            await controls.discardConfirmed(record)
            XCTAssertEqual(discards, 1)
            XCTAssertEqual(controls.records, loseList ? nil : [record])
            XCTAssertEqual(controls.unavailable, loseList)
            XCTAssertEqual(controls.notice, .unconfirmed)
        }
    }

    @MainActor
    func testConfirmedDiscardUpdatesOnlyTheSelectedRecord() async {
        let record = Self.record(1), other = Self.record(2)
        var current = [record, other]
        let controls = MacExpiredRePairControls(load: { current }, discard: { selected in
            XCTAssertEqual(selected, record)
            current.removeAll { $0 == selected }
        })
        await controls.refresh()
        await controls.discardConfirmed(record)
        XCTAssertEqual(controls.records, [other])
        XCTAssertEqual(controls.notice, .discarded)
    }

    func testSnapshotAcceptsTheFullStageCapAndRejectsChangesToScopeOrIdentity() throws {
        let records = (1...32).map { Self.record(UInt8($0)) }
        let first = try XCTUnwrap(records.first)
        func encode(_ values: [ExpiredRePairRecord]) throws -> Data {
            try ExpiredRePairSnapshot(macID: first.macID, accountID: first.accountID, records: values).encode()
        }
        func decode(_ bytes: Data) throws -> [ExpiredRePairRecord] {
            try ExpiredRePairSnapshot.decode(bytes, macID: first.macID, accountID: first.accountID).records
        }
        let bytes = try encode(records)
        XCTAssertEqual(try decode(bytes), records)
        XCTAssertThrowsError(try decode(encode(records + [Self.record(33)])))
        XCTAssertThrowsError(try decode(encode([first, Self.record(1, attempt: 2)])))
        XCTAssertThrowsError(try decode(encode([first, Self.record(2, attempt: 1)])))
        XCTAssertThrowsError(try ExpiredRePairSnapshot.decode(bytes, macID: first.accountID, accountID: first.accountID))
        XCTAssertThrowsError(try ExpiredRePairSnapshot.decode(bytes, macID: first.macID, accountID: first.macID))
        XCTAssertEqual(Array(Mirror(reflecting: first).children).count, 0)
    }

    private static func record(_ phone: UInt8, attempt: UInt8? = nil) -> ExpiredRePairRecord {
        ExpiredRePairRecord(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: phone, count: 16), originalExpiryUnixMilliseconds: 1_000,
            reason: .deadlineElapsed, setupID: Data(repeating: attempt ?? phone, count: 16),
            transcriptDigest: Data(repeating: 3, count: 32))
    }
}
