import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupRetainedStatusV3WireTests: XCTestCase {
    private typealias Wire = SetupRetainedStatusV3Wire

    private func request(_ byte: UInt8 = 3) throws -> Wire.Request {
        try .init(legacy: .init(requestID: Data(repeating: byte, count: 16)))
    }

    func testVersionThreeRequestIsCanonicalAndDoesNotDecodeAsVersionOne() throws {
        let request = try request()
        let bytes = try request.bytes
        XCTAssertEqual(try Wire.Request.decode(bytes).legacy, request.legacy)
        XCTAssertThrowsError(try SetupRetainedStatusWire.Request.decode(bytes))
        var noncanonical = bytes
        XCTAssertEqual(Array(bytes.prefix(3)), [0xa3, 0, 3])
        noncanonical.replaceSubrange(2..<3, with: [0x18, 3])
        XCTAssertThrowsError(try Wire.Request.decode(noncanonical))
    }

    func testUnknownAndObservedNoActionStayDistinct() throws {
        let request = try request()
        let unavailable = try Wire.reply(request, .unavailable)
        XCTAssertNil(try Wire.decodeReply(unavailable, matching: request).applicability)
        let noAction = try Wire.reply(request, .init(retained: .unavailable, restart: nil, applicability: .noAction))
        XCTAssertEqual(try Wire.decodeReply(noAction, matching: request).applicability, .noAction)
        XCTAssertThrowsError(try Wire.decodeReply(unavailable, matching: self.request(4)))
    }

    func testActionEvidenceCannotBeDecodedWithoutAnExactIdentity() throws {
        let request = try request()
        for action: Wire.Applicability in [.restore, .adoptRecordedCompletion, .releaseWindowFree] {
            let reply = try Wire.reply(request, .init(retained: .unavailable, restart: nil, applicability: action))
            XCTAssertThrowsError(try Wire.decodeReply(reply, matching: request))
        }
    }

    func testUnknownApplicabilityCodeAndNoncanonicalReplyAreRefused() throws {
        let request = try request()
        let reply = try Wire.reply(request, .unavailable)
        let limits = try CBORLimits(maxBytes: SetupRetainedStatusWire.maximumReplyBytes, maxDepth: 4, maxItems: 64)
        guard case .map(var fields) = try DeterministicCBOR.decode(reply, limits: limits) else {
            return XCTFail("Expected a version 3 map")
        }
        fields[11] = .unsigned(99)
        let unknown = try DeterministicCBOR.encode(.map(fields), limits: limits)
        XCTAssertThrowsError(try Wire.decodeReply(unknown, matching: request))
        var noncanonical = reply
        XCTAssertEqual(Array(reply.prefix(3)), [0xac, 0, 3])
        noncanonical.replaceSubrange(2..<3, with: [0x18, 3])
        XCTAssertThrowsError(try Wire.decodeReply(noncanonical, matching: request))
    }
}
