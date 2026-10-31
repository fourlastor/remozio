import Foundation
import XCTest
@testable import RemozioProtocol

private struct ProgressFrameRow: Decodable { let name: String; let hex: String }
private struct ProgressFrameVectors: Decodable { let publicKey: String; let valid: [ProgressFrameRow]; let invalid: [ProgressFrameRow] }
private func frameHex(_ text: String) -> Data {
    Data(stride(from: 0, to: text.count, by: 2).map {
        let start = text.index(text.startIndex, offsetBy: $0)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
    })
}

final class PhoneUpdateProgressFrameTests: XCTestCase {
    private var signingLimits: CBORLimits { get throws { try .init(maxBytes: 8192, maxDepth: 2, maxItems: 32) } }
    private func vectors() throws -> ProgressFrameVectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(ProgressFrameVectors.self, from: Data(contentsOf:
            root.appendingPathComponent("vectors/phone-update-progress-v1.json")))
    }
    func testSharedFramesPreserveCanonicalBytesAndSignedNestedProgress() throws {
        let data = try vectors(); XCTAssertEqual(data.valid.count, 13); var responses = 0
        for row in data.valid {
            let bytes = frameHex(row.hex), frame = try PhoneUpdateProgressFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes, row.name); XCTAssertEqual(frame.queryNonce, Data(repeating: 9, count: 32))
            XCTAssertEqual(frame.description, "PhoneUpdateProgressFrame(redacted)")
            XCTAssertEqual(frame.debugDescription, frame.description)
            if case let .response(nonce, payload, signature) = frame {
                responses += 1
                XCTAssertEqual(try UpdateSchedulingProgressResponse.decode(payload).status.queryNonce, nonce)
                XCTAssertTrue(try UpdateSchedulingProgressSignature.verify(signature: signature,
                    authorityPublicKey: frameHex(data.publicKey), wireVersion: 1, canonicalPayload: payload, inputLimits: signingLimits))
            }
        }
        XCTAssertEqual(responses, 10)
    }
    func testMalformedFramesAndSignedMalformedNestedBodiesFailStrictly() throws {
        let rows = try vectors().invalid; XCTAssertEqual(rows.count, 287)
        for row in rows { XCTAssertThrowsError(try PhoneUpdateProgressFrame.decode(frameHex(row.hex)), row.name) }
    }
    func testParsingDoesNotAuthenticateAWellFormedSignature() throws {
        let (nonce, body, _) = try response()
        let parsed = try PhoneUpdateProgressFrame.decode(PhoneUpdateProgressFrame.response(queryNonce: nonce,
            canonicalPayload: body, signature: Data(repeating: 0, count: 64)).encode())
        guard case let .response(_, payload, signature) = parsed else { return XCTFail() }
        XCTAssertFalse(try UpdateSchedulingProgressSignature.verify(signature: signature,
            authorityPublicKey: frameHex(vectors().publicKey), wireVersion: 1, canonicalPayload: payload, inputLimits: signingLimits))
    }
    func testDirectConstructionCannotBypassNonceBoundsAndCopies() throws {
        let (nonce, body, signature) = try response()
        var copiedNonce = nonce, copiedBody = body, copiedSignature = signature
        let retained = PhoneUpdateProgressFrame.response(queryNonce: copiedNonce, canonicalPayload: copiedBody, signature: copiedSignature)
        copiedNonce[0] ^= 1; copiedBody[0] ^= 1; copiedSignature[0] ^= 1
        XCTAssertEqual(try retained.encode(), try PhoneUpdateProgressFrame.response(queryNonce: nonce, canonicalPayload: body, signature: signature).encode())
        for size in [0, 31, 33] {
            XCTAssertThrowsError(try PhoneUpdateProgressFrame.status(queryNonce: Data(repeating: 0, count: size)).encode())
        }
        for size in [0, 63, 65] {
            XCTAssertThrowsError(try PhoneUpdateProgressFrame.response(queryNonce: nonce, canonicalPayload: body,
                signature: Data(repeating: 0, count: size)).encode())
        }
        XCTAssertThrowsError(try PhoneUpdateProgressFrame.response(queryNonce: Data(repeating: 8, count: 32),
            canonicalPayload: body, signature: signature).encode())
    }
    func testSchedulingMessagesAndUnsignedLateClaimsCannotBecomeProgress() throws {
        let nonce = Data(repeating: 9, count: 32)
        XCTAssertThrowsError(try PhoneUpdateProgressFrame.decode(PhoneUpdateSchedulingFrame.status(queryNonce: nonce).encode()))
        XCTAssertThrowsError(try PhoneUpdateSchedulingFrame.decode(PhoneUpdateProgressFrame.status(queryNonce: nonce).encode()))
        XCTAssertNotEqual(PhoneUpdateProgressFrame.applicationProtocol, PhoneUpdateSchedulingFrame.applicationProtocol)
        let rows = try vectors().valid
        guard case .failure(_, .unavailable) = try PhoneUpdateProgressFrame.decode(frameHex(rows.first { $0.name == "unavailable" }!.hex)),
              case .failure(_, .incompatible) = try PhoneUpdateProgressFrame.decode(frameHex(rows.first { $0.name == "incompatible" }!.hex)) else {
            return XCTFail()
        }
    }
    func testMaximumFrameBytesRemainBounded() throws {
        XCTAssertEqual(PhoneUpdateProgressFrame.maximumBytes, 8192)
        XCTAssertThrowsError(try PhoneUpdateProgressFrame.decode(Data(repeating: 0, count: PhoneUpdateProgressFrame.maximumBytes + 1)))
    }
    private func response() throws -> (Data, Data, Data) {
        guard case let .response(nonce, body, signature) = try PhoneUpdateProgressFrame.decode(frameHex(vectors().valid[1].hex)) else {
            throw PhoneUpdateProgressFrameError.invalidMessage
        }
        return (nonce, body, signature)
    }
}
