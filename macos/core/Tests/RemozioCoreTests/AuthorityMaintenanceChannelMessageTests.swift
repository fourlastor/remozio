import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceChannelMessageTests: XCTestCase {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private typealias Work = AuthorityMaintenanceChannelWork
    private let wide = try! CBORLimits(maxBytes: 8192, maxDepth: 8, maxItems: 256)
    private func bytes(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func binding(_ field: Int? = nil) throws -> AuthorityMaintenanceBinding {
        var a = (1...5).map { bytes(UInt8($0)) }; if let field { a[field] = bytes(99) }
        return try .init(accountID: a[0], attemptID: a[1], revision: a[2], incarnation: a[3], connectionID: a[4])
    }
    private func request(_ action: Request.Action = .observe, challenge: UInt8 = 6) throws -> Request {
        try .init(action: action, accountID: bytes(1), attemptID: bytes(2), revision: bytes(3), installationID: bytes(7),
            gate: .init(device: 8, inode: 9), binding: action == .open ? nil : binding(), challenge: bytes(challenge, 32))
    }
    private func work(_ n: [Int] = Array(1...10), _ b: [Bool] = [true, false, true, false, true, false]) throws -> Work {
        try .init(journal: .init(requests: .init(liveRequests: n[0], commandCaptures: n[1], activityOwners: n[2]),
            exchanges: .init(active: n[3], stopped: b[0]), nativeExecutions: n[4], executionActivityOwners: n[5]),
            execution: .init(started: b[1], stopping: b[2], failed: b[3], queuedTurns: n[6], rejectedTurns: n[7]),
            pairing: .init(ready: b[4], stagedAttempts: n[8], activityOwners: n[9], operationActive: b[5]))
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: wide) else { throw RuntimePreparationError.invalidRecord }; return f
    }
    private func encode(_ f: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(f), limits: wide) }
    private func response(_ q: Request) throws -> Response {
        try .init(request: q, binding: binding(), work: [Request.Action.cancel, .reopen].contains(q.action) ? nil : work(), outcome: .applied)
    }
    func testAllActionsHaveExactRequestAndResponseRoundTrips() throws {
        for action in Request.Action.allCases {
            let q = try request(action), r = try response(q)
            XCTAssertEqual(try Request.decode(q.encoded), q)
            XCTAssertEqual(try Response.decode(r.encoded, expected: q), r)
            XCTAssertLessThan(try q.encoded.count, 512); XCTAssertLessThan(try r.encoded.count, 1024)
        }
    }
    func testRequestIdentifierAndChallengeLengthsAreExact() throws {
        let original = try fields(request(.open).encoded)
        for key in [UInt64(3), 4, 5, 7, 8] {
            let exact = key == 7 ? 32 : 16
            for count in [0, exact - 1, exact + 1, 513] {
                var f = original; f[key] = .bytes(bytes(9, count)); XCTAssertThrowsError(try Request.decode(encode(f)))
            }
        }
    }
    func testOnlyOpenOmitsBindingAndLaterRequestsRequireAllThreeScopeValues() throws {
        var f = try fields(request(.open).encoded); f[6] = .bytes(try binding().encoded)
        XCTAssertThrowsError(try Request.decode(encode(f)))
        f = try fields(request().encoded); f[6] = .null; XCTAssertThrowsError(try Request.decode(encode(f)))
        for field in 0..<3 {
            f = try fields(request().encoded); f[6] = .bytes(try binding(field).encoded)
            XCTAssertThrowsError(try Request.decode(encode(f)))
        }
    }
    func testRequestRejectsUnknownMissingTagsVersionsEnumsAndWrongTypes() throws {
        let original = try fields(request().encoded)
        for key in original.keys { var f = original; f.removeValue(forKey: key); XCTAssertThrowsError(try Request.decode(encode(f))) }
        var f = original; f[11] = .null; XCTAssertThrowsError(try Request.decode(encode(f)))
        for value: CBORValue in [.unsigned(0), .unsigned(2), .text("1")] {
            f = original; f[0] = value; XCTAssertThrowsError(try Request.decode(encode(f)))
        }
        f = original; f[1] = .text("authority.maintenance-response"); XCTAssertThrowsError(try Request.decode(encode(f)))
        for value: CBORValue in [.unsigned(0), .unsigned(6), .unsigned(.max), .text("observe")] {
            f = original; f[2] = value; XCTAssertThrowsError(try Request.decode(encode(f)))
        }
        for key in [UInt64(3), 4, 5, 6, 7, 8, 9, 10] {
            f = original; f[key] = .boolean(false); XCTAssertThrowsError(try Request.decode(encode(f)))
        }
    }
    func testGateDeviceAndInodeAreBoundedWithoutLosingTheirExactIdentity() throws {
        var f = try fields(request().encoded); f[9] = .unsigned(UInt64(UInt32.max)); f[10] = .unsigned(.max)
        let q = try Request.decode(encode(f)); XCTAssertEqual(q.gate, .init(device: UInt32.max, inode: UInt64.max))
        f[9] = .unsigned(UInt64(UInt32.max) + 1); XCTAssertThrowsError(try Request.decode(encode(f)))
        f[9] = .unsigned(8); f[10] = .unsigned(0); XCTAssertThrowsError(try Request.decode(encode(f)))
    }
    func testEveryWorkCountAndFlagSurvivesTransportWithoutAnIdleInference() throws {
        let q = try request(.arm)
        for flag in 0..<6 {
            var b = Array(repeating: false, count: 6); b[flag] = true
            let observed = try work(Array(1...10), b), r = try Response(request: q, binding: binding(), work: observed, outcome: .applied)
            XCTAssertEqual(try Response.decode(r.encoded, expected: q).work, observed)
        }
        XCTAssertNotNil(try response(q).work)
    }
    func testAllWorkCountsRejectNegativeAndOverflowAndAcceptMaximum() throws {
        for index in 0..<10 {
            for value in [-1, Int(UInt32.max) + 1] {
                var n = Array(1...10); n[index] = value; XCTAssertThrowsError(try work(n))
            }
            var n = Array(1...10); n[index] = Int(UInt32.max)
            let q = try request(), r = try Response(request: q, binding: binding(), work: work(n), outcome: .applied)
            XCTAssertEqual(try Response.decode(r.encoded, expected: q), r)
        }
    }
    func testWireWorkRequiresExactCountTypesAndBooleanFlags() throws {
        let q = try request(), original = try fields(response(q).encoded)
        guard case .array(let originalWork) = original[4] else { return XCTFail() }
        for index in 0..<16 {
            var a = originalWork; a[index] = [4, 7, 8, 9, 12, 15].contains(index) ? .unsigned(0) : .boolean(false)
            var f = original; f[4] = .array(a); XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        }
        for index in [0, 1, 2, 3, 5, 6, 10, 11, 13, 14] {
            var a = originalWork; a[index] = .unsigned(UInt64(UInt32.max) + 1)
            var f = original; f[4] = .array(a); XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        }
        for a in [Array(originalWork.dropLast()), originalWork + [.null]] {
            var f = original; f[4] = .array(a); XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        }
    }
    func testReplyCorrelationIncludesInstallationGateActionAndChallenge() throws {
        let q = try request(), r = try response(q), original = try fields(q.encoded)
        for key in [UInt64(2), 3, 4, 5, 7, 8, 9, 10] {
            var f = original
            switch key {
            case 2: f[key] = .unsigned(Request.Action.arm.rawValue)
            case 9, 10: f[key] = .unsigned(99)
            default: f[key] = .bytes(bytes(99, key == 7 ? 32 : 16))
            }
            if [3, 4, 5].contains(key) { f[6] = .bytes(try binding(Int(key) - 3).encoded) }
            let other = try Request.decode(encode(f))
            XCTAssertThrowsError(try Response.decode(r.encoded, expected: other))
        }
    }
    func testFirstReplyNeedsWorkAndLaterRepliesCannotReplaceAnyBindingField() throws {
        let open = try request(.open), q = try request()
        XCTAssertThrowsError(try Response(request: open, binding: binding(), work: nil, outcome: .applied))
        for field in 0..<5 { XCTAssertThrowsError(try Response(request: q, binding: binding(field), work: work(), outcome: .applied)) }
        for action in [Request.Action.cancel, .reopen] {
            XCTAssertThrowsError(try Response(request: request(action), binding: binding(), work: work(), outcome: .applied))
            XCTAssertNil(try response(request(action)).work)
        }
    }
    func testResponseRejectsUnknownMissingTagsVersionsAndUnexpectedWork() throws {
        let q = try request(), original = try fields(response(q).encoded)
        for key in original.keys { var f = original; f.removeValue(forKey: key); XCTAssertThrowsError(try Response.decode(encode(f), expected: q)) }
        var f = original; f[6] = .null; XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        f = original; f[0] = .unsigned(2); XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        f = original; f[1] = .text("authority.maintenance-request"); XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        for key in [UInt64(2), 3, 4] { f = original; f[key] = .boolean(false); XCTAssertThrowsError(try Response.decode(encode(f), expected: q)) }
        var deep: CBORValue = .null; for _ in 0..<5 { deep = .array([deep]) }
        f = original; f[4] = deep; XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
    }
    func testCanonicalTruncationTrailingDuplicatesAndByteLimitsRefuse() throws {
        let q = try request(), qb = try q.encoded, rb = try response(q).encoded
        for end in 0..<qb.count { XCTAssertThrowsError(try Request.decode(qb.prefix(end))) }
        for end in 0..<rb.count { XCTAssertThrowsError(try Response.decode(rb.prefix(end), expected: q)) }
        for b in [qb + Data([0]), Data(repeating: 0, count: 513), Data([0xab, 0, 0x18, 1]) + qb.dropFirst(3), Data([0xac, 0, 1]) + qb.dropFirst()] {
            XCTAssertThrowsError(try Request.decode(b))
        }
        for b in [rb + Data([0]), Data(repeating: 0, count: 1025), Data([0xa6, 0, 0x18, 1]) + rb.dropFirst(3), Data([0xa7, 0, 1]) + rb.dropFirst()] {
            XCTAssertThrowsError(try Response.decode(b, expected: q))
        }
    }
}

extension AuthorityMaintenanceChannelMessageTests {
    func testEveryActionOutcomeAndWorkCombinationIsValidatedAndRoundTrips() throws {
        for action in Request.Action.allCases {
            let q = try request(action)
            for outcome in Response.Outcome.allCases {
                for hasWork in [false, true] {
                    let w = hasWork ? try work() : nil
                    let observes = [Request.Action.open, .observe, .arm].contains(action)
                    let valid: Bool
                    switch outcome {
                    case .applied: valid = observes == hasWork
                    case .stagesPending: valid = action == .arm && hasWork
                    case .refused: valid = !hasWork
                    }
                    if valid {
                        let r = try Response(request: q, binding: binding(), work: w, outcome: outcome)
                        XCTAssertEqual(try Response.decode(r.encoded, expected: q), r)
                    } else {
                        XCTAssertThrowsError(try Response(request: q, binding: binding(), work: w, outcome: outcome))
                        var f = try fields(response(q).encoded); f[5] = .unsigned(outcome.rawValue)
                        if hasWork { f[4] = try fields(response(request(.arm)).encoded)[4] } else { f[4] = .null }
                        XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
                    }
                }
            }
        }
    }
    func testUnknownMissingAndWrongTypeOutcomesCannotBecomeApplied() throws {
        let q = try request(.arm), original = try fields(response(q).encoded)
        for value: CBORValue in [.unsigned(0), .unsigned(4), .unsigned(.max), .text("applied"), .boolean(true), .null] {
            var f = original; f[5] = value; XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
        }
        var f = original; f.removeValue(forKey: 5)
        XCTAssertThrowsError(try Response.decode(encode(f), expected: q))
    }
    func testPendingAndRefusedRemainDistinctAndKeepExactRequestCorrelation() throws {
        let q = try request(.arm)
        let pending = try Response(request: q, binding: binding(), work: work(), outcome: .stagesPending)
        let refused = try Response(request: q, binding: binding(), work: nil, outcome: .refused)
        let applied = try Response(request: q, binding: binding(), work: work(), outcome: .applied)
        XCTAssertEqual(try Response.decode(pending.encoded, expected: q).outcome, .stagesPending)
        XCTAssertEqual(try Response.decode(refused.encoded, expected: q).outcome, .refused)
        XCTAssertNil(try Response.decode(refused.encoded, expected: q).work)
        XCTAssertNotEqual(try pending.encoded, try applied.encoded)
        for r in [pending, refused, applied] {
            XCTAssertThrowsError(try Response.decode(r.encoded, expected: request(.arm, challenge: 99)))
            XCTAssertThrowsError(try Response.decode(r.encoded, expected: request(.observe)))
        }
    }
}
