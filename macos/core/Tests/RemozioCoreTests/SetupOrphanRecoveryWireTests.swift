import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupOrphanRecoveryWireTests: XCTestCase {
    private typealias W = SetupOrphanRecoveryWire
    private let id = Data(repeating: 1, count: 16)
    private var limits: CBORLimits { get throws { try .init(maxBytes: 2048, maxDepth: 4, maxItems: 32) } }
    func testEveryActionRoundTripsWithTheExactIdentityPair() throws {
        let pair = SetupRetainedInvocationStatus.Identity(reservationID: UUID(), incarnation: UUID())
        for action in W.Action.allCases {
            let value = try W.Request(requestID: id, action: action, identity: pair)
            XCTAssertEqual(try W.Request.decode(value.bytes), value)
        }
    }
    func testOmittedIdentityRoundTripsWithoutInventingAnIdentifier() throws {
        let value = try W.Request(requestID: id, action: .releaseWindowFree)
        XCTAssertNil(try W.Request.decode(value.bytes).identity)
    }
    func testEveryClosedResultCodeRoundTripsWithinTheBound() throws {
        for code in W.Code.allCases {
            let value = try W.Reply(requestID: id, code: code)
            XCTAssertLessThanOrEqual(try value.bytes.count, W.maximumBytes)
            XCTAssertEqual(try W.Reply.decode(value.bytes), value)
        }
    }
    func testProgressHasAnIndependentNamespaceAndTheSameCorrelation() throws {
        let value = try W.Progress(requestID: id)
        XCTAssertEqual(try W.Progress.decode(value.bytes), value)
        XCTAssertThrowsError(try W.Request.decode(value.bytes))
        XCTAssertThrowsError(try W.Reply.decode(value.bytes))
    }
    func testCorrelationMustHaveSixteenBytes() throws {
        for count in [0, 15, 17, 1025] {
            let bad = Data(repeating: 0, count: count)
            XCTAssertThrowsError(try W.Request(requestID: bad, action: .restore))
            XCTAssertThrowsError(try W.Progress(requestID: bad))
            XCTAssertThrowsError(try W.Reply(requestID: bad, code: .pending))
        }
    }
    func testOversizedMessagesRefuseBeforeDecoding() {
        let bad = Data(repeating: 0, count: W.maximumBytes + 1)
        XCTAssertThrowsError(try W.Request.decode(bad))
        XCTAssertThrowsError(try W.Progress.decode(bad))
        XCTAssertThrowsError(try W.Reply.decode(bad))
    }
    func testWindowAndRevisionFieldsAreNotAccepted() throws {
        let value = try W.Request(requestID: id, action: .restore)
        guard case .map(var fields) = try DeterministicCBOR.decode(value.bytes, limits: limits) else { return XCTFail("Expected a map") }
        fields[5] = .bytes(id); fields[6] = .bytes(id)
        XCTAssertThrowsError(try W.Request.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testUnknownActionsAndVersionsAreNotNegotiated() throws {
        let value = try W.Request(requestID: id, action: .restore)
        guard case .map(let fields) = try DeterministicCBOR.decode(value.bytes, limits: limits) else { return XCTFail("Expected a map") }
        for key in [UInt64(0), UInt64(3)] {
            var changed = fields; changed[key] = .unsigned(99)
            XCTAssertThrowsError(try W.Request.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
    }
    func testStartAndProgressRepliesRemainDeterministic() throws {
        let value = try W.Reply(requestID: id, code: .requestRecorded)
        XCTAssertEqual(try value.bytes, try value.bytes)
        XCTAssertNotEqual(try value.bytes, try W.Reply(requestID: id, code: .restored).bytes)
    }
    func testInvalidIdentityTupleIsRefused() throws {
        let value = try W.Request(requestID: id, action: .restore)
        guard case .map(var fields) = try DeterministicCBOR.decode(value.bytes, limits: limits) else { return XCTFail("Expected a map") }
        fields[4] = .array([.bytes(id)])
        XCTAssertThrowsError(try W.Request.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        fields[4] = .array([.bytes(Data()), .bytes(id)])
        XCTAssertThrowsError(try W.Request.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
}
