import Foundation
import XCTest
@testable import RemozioProtocol

private struct SchedulingV2Row: Decodable {
    let name: String; let requestV1: String; let requestV2: String; let replyV2: String
    let payload: String; let signature: String
}
private struct SchedulingV2Vectors: Decodable { let publicKey: String; let rows: [SchedulingV2Row] }
private func schedulingV2Hex(_ text: String) -> Data {
    Data(stride(from: 0, to: text.count, by: 2).map {
        let start = text.index(text.startIndex, offsetBy: $0)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
    })
}
final class PhoneUpdateSchedulingFrameV2Tests: XCTestCase {
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 4, maxItems: 64) } }
    private func vectors() throws -> SchedulingV2Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(SchedulingV2Vectors.self, from: Data(contentsOf:
            root.appendingPathComponent("vectors/phone-update-scheduling-v2.json")))
    }
    func testSharedRequestsAndRepliesHaveExactCanonicalVersion2Bytes() throws {
        let data = try vectors(); XCTAssertEqual(data.rows.count, 8)
        for row in data.rows {
            let request = try PhoneUpdateSchedulingFrame.decode(schedulingV2Hex(row.requestV1))
            XCTAssertEqual(try PhoneUpdateSchedulingFrameV2.message(request).encode(), schedulingV2Hex(row.requestV2))
            let reply = try PhoneUpdateSchedulingFrameV2.decode(schedulingV2Hex(row.replyV2))
            guard case let .tooLate(nonce, payload, signature) = reply else { return XCTFail("Missing TooLate") }
            XCTAssertEqual(try reply.encode(), schedulingV2Hex(row.replyV2)); XCTAssertEqual(nonce, request.queryNonce)
            XCTAssertEqual(payload, schedulingV2Hex(row.payload)); XCTAssertEqual(signature, schedulingV2Hex(row.signature))
        }
    }
    func testVersion1AndVersion2CannotBeSubstitutedInEitherDirection() throws {
        for row in try vectors().rows {
            XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.decode(schedulingV2Hex(row.requestV2)))
            XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.decode(schedulingV2Hex(row.replyV2)))
            XCTAssertThrowsError(try PhoneUpdateSchedulingFrameV2.decode(schedulingV2Hex(row.requestV1)))
        }
        XCTAssertEqual(PhoneUpdateSchedulingFrameV2.applicationProtocol, "remozio-update-scheduling/2")
        XCTAssertNotEqual(PhoneUpdateSchedulingFrameV2.applicationProtocol, PhoneUpdateSchedulingFrame.applicationProtocol)
    }
    func testAllExistingRolesRetainTheirOriginalCanonicalMeaningAndBounds() throws {
        let rows = try vectors().rows, row = rows[0]
        let request = try PhoneUpdateSchedulingFrame.decode(schedulingV2Hex(row.requestV1))
        let late = try UpdateSchedulingTooLateResponse.decode(schedulingV2Hex(row.payload)), nonce = request.queryNonce
        let applied = try PhoneUpdateSchedulingFrame.decode(schedulingV2Hex(rows.first { $0.name.hasSuffix("apply") }!.requestV1))
        guard case let .apply(_, control, _) = applied else { return XCTFail("Missing apply") }
        let bounds = try CBORLimits(maxBytes: 2048, maxDepth: 2, maxItems: 32)
        let challenge = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: control, limits: bounds).encode(limits: bounds)
        let frames: [PhoneUpdateSchedulingFrame] = [.status(queryNonce: nonce), request, applied,
            .challengeResponse(queryNonce: nonce, canonicalPayload: challenge, signature: Data(count: 64)),
            .stateResponse(queryNonce: nonce, canonicalPayload: try late.progress.status.encode(), signature: Data(count: 64)),
            .failure(queryNonce: nonce, reason: .unavailable)]
        for frame in frames {
            guard case let .message(decoded) = try PhoneUpdateSchedulingFrameV2.decode(PhoneUpdateSchedulingFrameV2.message(frame).encode()) else {
                return XCTFail("Missing original message")
            }
            XCTAssertEqual(try decoded.encode(), try frame.encode())
        }
    }
    func testEveryRootSignatureAndRequestDigestRemainBoundToTheOriginalRequest() throws {
        let data = try vectors(), key = schedulingV2Hex(data.publicKey)
        for row in data.rows {
            guard case let .message(request) = try PhoneUpdateSchedulingFrameV2.decode(schedulingV2Hex(row.requestV2)),
                  case let .tooLate(_, body, signature) = try PhoneUpdateSchedulingFrameV2.decode(schedulingV2Hex(row.replyV2)) else {
                return XCTFail("Missing exchange")
            }
            let response = try UpdateSchedulingTooLateResponse.decode(body)
            XCTAssertTrue(try response.matches(request: request, expectedScope: response.progress.status.scope))
            XCTAssertTrue(try UpdateSchedulingTooLateSignature.verify(signature: signature, authorityPublicKey: key,
                wireVersion: 1, canonicalPayload: body, inputLimits: CBORLimits(maxBytes: 8192, maxDepth: 2, maxItems: 32)))
        }
    }
    func testUnknownVersionsKindsFieldsMalformedPairsAndOversizedMessagesAreRejected() throws {
        let row = try vectors().rows[0]
        guard case let .map(source) = try DeterministicCBOR.decode(schedulingV2Hex(row.replyV2), limits: limits) else {
            return XCTFail("Missing fields")
        }
        var changed: [[UInt64: CBORValue]] = []
        for (key, value): (UInt64, CBORValue) in [(1, .unsigned(3)), (2, .unsigned(7)), (5, .null),
            (4, .array([])), (3, .bytes(Data(repeating: 99, count: 32))),
            (4, .array([.bytes(Data(count: 8193)), .bytes(Data(count: 64))]))] {
            var fields = source; fields[key] = value; changed.append(fields)
        }
        var missing = source; missing.removeValue(forKey: 3); changed.append(missing)
        var short = source; short[4] = .array([.bytes(schedulingV2Hex(row.payload)), .bytes(Data(count: 63))]); changed.append(short)
        for fields in changed {
            XCTAssertThrowsError(try PhoneUpdateSchedulingFrameV2.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrameV2.decode(Data(count: PhoneUpdateSchedulingFrameV2.maximumBytes + 1)))
    }
    func testValueCopiesAndDescriptionsDoNotExposeOrReplaceThePayload() throws {
        let row = try vectors().rows[0]
        let nonce = try PhoneUpdateSchedulingFrame.decode(schedulingV2Hex(row.requestV1)).queryNonce
        var body = schedulingV2Hex(row.payload), signature = schedulingV2Hex(row.signature)
        let frame = PhoneUpdateSchedulingFrameV2.tooLate(queryNonce: nonce, canonicalPayload: body, signature: signature)
        let original = try frame.encode(); body.resetBytes(in: 0..<body.count); signature.resetBytes(in: 0..<signature.count)
        XCTAssertEqual(try frame.encode(), original); XCTAssertEqual(frame.description, "PhoneUpdateSchedulingFrameV2(redacted)")
    }
}
