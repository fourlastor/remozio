import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class PairingRecoveryLookupTests: XCTestCase {
    func testOneChallengeAndOneConsumption() throws {
        let query = try makeQuery()
        let exporter = Data(repeating: 7, count: 32)
        let now: UInt64 = 1_000_000_000
        let deadline = now + 1_000_000_000
        var lookup = PairingRecoveryLookup()
        let nonce = try lookup.begin(query: query, exporter: exporter, deadline: deadline, now: now)
        XCTAssertEqual(nonce.count, 32)
        XCTAssertThrowsError(try lookup.begin(query: query, exporter: exporter, deadline: deadline, now: now))
        let attempt = try XCTUnwrap(lookup.consume(now: now))
        XCTAssertEqual(attempt.query, query)
        XCTAssertEqual(attempt.exporter, exporter)
        XCTAssertEqual(attempt.challenge, nonce)
        XCTAssertEqual(attempt.deadline, deadline)
        XCTAssertNil(lookup.consume(now: now))
    }

    func testDeadlineConsumesChallengeAtBoundary() throws {
        let query = try makeQuery()
        let exporter = Data(repeating: 7, count: 32)
        let now: UInt64 = 1_000_000_000
        let deadline = now + 1_000_000_000
        var lookup = PairingRecoveryLookup()
        _ = try lookup.begin(query: query, exporter: exporter, deadline: deadline, now: now)
        XCTAssertNil(lookup.consume(now: deadline))
        XCTAssertNil(lookup.consume(now: now))
    }

    private func makeQuery() throws -> PairingRecoveryQuery {
        let scope = try ChannelScope(macID: Data(repeating: 3, count: 16), accountID: Data(repeating: 4, count: 16),
            phoneID: Data(repeating: 5, count: 16), enrollmentEpoch: Data(repeating: 6, count: 16))
        return try PairingRecoveryQuery(setupID: Data(repeating: 1, count: 16),
            transcriptDigest: Data(repeating: 2, count: 32), scope: scope)
    }
}
