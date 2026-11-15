import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceGateMessageTests: XCTestCase {
    private typealias Request = AuthorityMaintenanceGateRequest
    private typealias Response = AuthorityMaintenanceGateResponse
    private func data(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private let wide = try! CBORLimits(maxBytes: 4096, maxDepth: 4, maxItems: 128)
    private func request(challenge: Data? = nil, revision: Data? = nil, inode: UInt64 = 99) throws -> Request {
        let target = try AuthorityMaintenanceBinding(accountID: data(1), attemptID: data(2), revision: data(3),
            incarnation: data(4), connectionID: data(5))
        return try .init(accountID: data(1), attemptID: data(2), revision: revision ?? data(6), installationID: data(7),
            gate: .init(device: 8, inode: inode), target: target, challenge: challenge ?? data(9))
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: wide) else { throw RuntimePreparationError.invalidRecord }
        return f
    }
    private func encode(_ f: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(f), limits: wide) }
    private func response(_ q: Request) throws -> Response {
        try .init(request: q, authorityIncarnation: data(10), hold: .released, admission: .available)
    }
    func testDedicatedChallengeHasSixteenBytesAndDoesNotTruncateTheOtherChannelNonce() throws {
        for count in [0, 15, 17, 31, 32, 33] { XCTAssertThrowsError(try request(challenge: data(9, count))) }
        XCTAssertEqual(try Request.decode(request().encoded).challenge, data(9))
    }
    func testSavedTargetRetainsItsOldRevisionWhileTheRequestBindsPendingRevision() throws {
        let q = try request(), decoded = try Request.decode(q.encoded)
        XCTAssertEqual(decoded, q); XCTAssertNotEqual(decoded.revision, decoded.target.revision)
        XCTAssertEqual(decoded.target.incarnation, data(4)); XCTAssertEqual(decoded.target.connectionID, data(5))
        let foreign = try AuthorityMaintenanceBinding(accountID: data(90), attemptID: q.attemptID, revision: q.target.revision,
            incarnation: q.target.incarnation, connectionID: q.target.connectionID)
        XCTAssertThrowsError(try Request(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision,
            installationID: q.installationID, gate: q.gate, target: foreign, challenge: q.challenge))
    }
    func testReplyCannotBeReusedForAnotherNonceRevisionOrGate() throws {
        let q = try request(), bytes = try response(q).encoded
        for other in [try request(challenge: data(91)), try request(revision: data(92)), try request(inode: 100)] {
            XCTAssertThrowsError(try Response.decode(bytes, expected: other))
        }
    }
    func testReadbackUsesTheExactNativeEpochAndExactCanonicalResponseDigest() throws {
        let q = try request(), bytes = try response(q).encoded
        let readback = try Response.decode(bytes, expected: q).readback(expectedIncarnation: data(10))
        XCTAssertEqual(readback.authorityIncarnation, data(10)); XCTAssertEqual(readback.challenge, q.challenge)
        XCTAssertEqual(readback.attemptID, q.attemptID); XCTAssertEqual(readback.requestRevision, q.revision)
        XCTAssertEqual(readback.identity, q.gate); XCTAssertEqual(readback.responseDigest, Data(SHA256.hash(data: bytes)))
        XCTAssertThrowsError(try response(q).readback(expectedIncarnation: q.target.incarnation))
    }
    func testHeldBusyAndUnavailableObservationsNeverDecodeAsReleasedAvailable() throws {
        let q = try request()
        for hold in Response.Readback.Hold.allCases {
            for admission in Response.Readback.Admission.allCases {
                let value = try Response(request: q, authorityIncarnation: data(10), hold: hold, admission: admission)
                let actual = try Response.decode(value.encoded, expected: q).readback(expectedIncarnation: data(10))
                XCTAssertEqual(actual.hold, hold); XCTAssertEqual(actual.admission, admission)
            }
        }
    }
    func testRequestRejectsMissingUnknownTagsVersionsAndInvalidGateWidths() throws {
        let original = try fields(request().encoded)
        var mutations: [[UInt64: CBORValue]] = []
        for key in original.keys { var f = original; f.removeValue(forKey: key); mutations.append(f) }
        var extra = original; extra[10] = .null; mutations.append(extra)
        for version: UInt64 in [0, 2, .max] { var f = original; f[0] = .unsigned(version); mutations.append(f) }
        var overflow = original; overflow[6] = .unsigned(UInt64(UInt32.max) + 1); mutations.append(overflow)
        var zero = original; zero[7] = .unsigned(0); mutations.append(zero)
        for f in mutations { XCTAssertThrowsError(try Request.decode(encode(f))) }
    }
    func testResponseRejectsUnknownEnumsMissingTagsAndWrongTypes() throws {
        let q = try request(), original = try fields(response(q).encoded)
        for key in original.keys {
            var f = original; f.removeValue(forKey: key); XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        }
        for key: UInt64 in [4, 5] {
            for value: CBORValue in [.unsigned(0), .unsigned(4), .unsigned(.max), .text("available"), .null] {
                var f = original; f[key] = value; XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
            }
        }
        var f = original; f[6] = .null; XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
    }
    func testTruncatedTrailingAndOversizedFramesAreRejected() throws {
        let q = try request(), a = try q.encoded, b = try response(q).encoded
        for bytes in [Data(a.dropLast()), a + data(0, 1), data(0, 513)] { XCTAssertThrowsError(try Request.decode(bytes)) }
        for bytes in [Data(b.dropLast()), b + data(0, 1), data(0, 1025)] { XCTAssertThrowsError(try Response.decode(bytes, expected: q)) }
    }
}
