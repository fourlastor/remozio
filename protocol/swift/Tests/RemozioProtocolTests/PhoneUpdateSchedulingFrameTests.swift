import Foundation
import XCTest
@testable import RemozioProtocol

private struct UpdateChannelRow: Decodable {
    let name: String; let hex: String; let signature: String?; let signingInput: String?
    let generation: String?; let revision: String?; let action: UInt64?; let kind: Int?
    let wrongVersionSignature: String?; let wrongTypeSignature: String?
    let wrongPurposeSignature: String?; let phoneControlDomainSignature: String?
}
private struct UpdateChannelVectors: Decodable {
    let publicKey: String?; let otherPublicKey: String?; let valid: [UpdateChannelRow]; let invalid: [UpdateChannelRow]
}
private func channelVectors(_ name: String) throws -> UpdateChannelVectors {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    return try JSONDecoder().decode(UpdateChannelVectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/" + name)))
}
private func channelHex(_ text: String) -> Data {
    Data(stride(from: 0, to: text.count, by: 2).map { offset in
        let start = text.index(text.startIndex, offsetBy: offset)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
    })
}

final class PhoneUpdateSchedulingFrameTests: XCTestCase {
    private func vectors() throws -> UpdateChannelVectors { try channelVectors("phone-update-scheduling-v1.json") }
    func testSharedFramesPreserveCanonicalBytesAndQueryNonces() throws {
        let v = try vectors(); XCTAssertEqual(v.valid.count, 8)
        for row in v.valid {
            let bytes = channelHex(row.hex), value = try PhoneUpdateSchedulingFrame.decode(bytes)
            XCTAssertEqual(try value.encode(), bytes); XCTAssertEqual(value.queryNonce, Data(repeating: 9, count: 32))
            XCTAssertEqual(value.description, "PhoneUpdateSchedulingFrame(redacted)")
        }
    }
    func testMalformedFramesAndNestedClaimsFailStrictly() throws {
        let v = try vectors(); XCTAssertEqual(v.invalid.count, 109)
        for row in v.invalid { XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.decode(channelHex(row.hex)), row.name) }
    }
    func testEveryRoleHasItsOwnTypedPayloadAndUnsignedBoundaries() throws {
        let rows = try vectors().valid
        if case .status = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[0].hex)) {} else { XCTFail() }
        if case let .challenge(_, update, generation, revision, action) = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[2].hex)) {
            XCTAssertEqual(update.count, 32); XCTAssertEqual(generation, .max); XCTAssertEqual(revision, .max); XCTAssertEqual(action, .cancelDrain)
        } else { XCTFail() }
        if case .apply = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[3].hex)) {} else { XCTFail() }
        if case .challengeResponse = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[4].hex)) {} else { XCTFail() }
        if case .stateResponse = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[5].hex)) {} else { XCTFail() }
        if case .failure(_, .unavailable) = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[6].hex)) {} else { XCTFail() }
        if case .failure(_, .incompatible) = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[7].hex)) {} else { XCTFail() }
    }
    func testDirectConstructionCannotBypassNestedNonceOrSignatureBounds() throws {
        let rows = try vectors().valid
        guard case let .stateResponse(nonce, payload, signature) = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[5].hex)) else { return XCTFail() }
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.stateResponse(queryNonce: Data(repeating: 8, count: 32),
            canonicalPayload: payload, signature: signature).encode())
        for size in [63, 65] {
            XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.stateResponse(queryNonce: nonce,
                canonicalPayload: payload, signature: Data(repeating: 1, count: size)).encode())
        }
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.challenge(queryNonce: nonce, updateID: Data(repeating: 1, count: 32),
            generation: 0, revision: 0, action: .deferUpdate).encode())
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.status(queryNonce: Data(repeating: 1, count: 31)).encode())
    }
    func testResponseCodecsCannotAcceptAnotherRoleAsTheirNestedBody() throws {
        let rows = try vectors().valid
        guard case let .stateResponse(nonce, status, signature) = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[5].hex)),
              case let .challengeResponse(_, challenge, _) = try PhoneUpdateSchedulingFrame.decode(channelHex(rows[4].hex)) else { return XCTFail() }
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.challengeResponse(queryNonce: nonce, canonicalPayload: status, signature: signature).encode())
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.stateResponse(queryNonce: nonce, canonicalPayload: challenge, signature: signature).encode())
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.apply(queryNonce: nonce, canonicalControl: challenge, signature: signature).encode())
        XCTAssertNotEqual(PhoneUpdateSchedulingFrame.applicationProtocol, PhoneRoutingFrame.applicationProtocol)
    }
}
