import Foundation
import XCTest
@testable import RemozioProtocol

final class RootUpdateSchedulingChallengeTests: XCTestCase {
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 2048, maxDepth: 8, maxItems: 64) } }
    private struct Row: Decodable {
        let name: String; let hex: String; let queryNonce: String?; let controlHex: String?
        let signature: String?; let signingInput: String?
        let wrongVersionSignature: String?; let wrongTypeSignature: String?
        let wrongPurposeSignature: String?; let phoneControlDomainSignature: String?
    }
    private struct Vectors: Decodable { let publicKey: String; let otherPublicKey: String; let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self,
            from: Data(contentsOf: root.appendingPathComponent("vectors/root-update-scheduling-challenge-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func verify(_ signature: Data, _ key: Data, _ payload: Data) throws -> Bool {
        try RootUpdateSchedulingChallengeSignature.verify(signature: signature, authorityPublicKey: key, wireVersion: 1,
            canonicalPayload: payload, payloadLimits: limits, inputLimits: limits)
    }

    func testSharedChallengesPreserveTheQueryAndExactControl() throws {
        let vectors = try vectors(); XCTAssertEqual(vectors.valid.count, 5)
        for row in vectors.valid {
            let bytes = hex(row.hex), challenge = try RootUpdateSchedulingChallenge.decode(bytes, limits: limits)
            XCTAssertEqual(challenge.queryNonce, hex(row.queryNonce!))
            XCTAssertEqual(challenge.canonicalControl, hex(row.controlHex!))
            XCTAssertEqual(try challenge.encode(limits: limits), bytes)
            XCTAssertEqual(try RootUpdateSchedulingChallengeSigningInput.make(wireVersion: 1, canonicalPayload: bytes,
                payloadLimits: limits, inputLimits: limits), hex(row.signingInput!))
            XCTAssertTrue(try verify(hex(row.signature!), hex(vectors.publicKey), bytes))
        }
    }

    func testMalformedFramesAndNestedControlsRejectBeforeVerification() throws {
        let vectors = try vectors(); XCTAssertEqual(vectors.invalid.count, 118); var signed = 0
        for row in vectors.invalid {
            let bytes = hex(row.hex)
            XCTAssertThrowsError(try RootUpdateSchedulingChallenge.decode(bytes, limits: limits), row.name)
            XCTAssertThrowsError(try RootUpdateSchedulingChallengeSigningInput.make(wireVersion: 1,
                canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits), row.name)
            if let signature = row.signature {
                signed += 1
                XCTAssertTrue(P256Verification.verify(signature: hex(signature), publicKey: hex(vectors.publicKey), input: hex(row.signingInput!)))
                XCTAssertThrowsError(try verify(hex(signature), hex(vectors.publicKey), bytes))
            }
        }
        XCTAssertEqual(signed, 6)
    }

    func testSignaturesBindTheNonceControlKeyAndPurpose() throws {
        let vectors = try vectors(), key = hex(vectors.publicKey)
        for row in vectors.valid {
            let bytes = hex(row.hex), signature = hex(row.signature!)
            XCTAssertFalse(try verify(signature, hex(vectors.otherPublicKey), bytes))
            for wrong in [row.wrongVersionSignature, row.wrongTypeSignature, row.wrongPurposeSignature, row.phoneControlDomainSignature] {
                XCTAssertFalse(try verify(hex(wrong!), key, bytes))
            }
            let challenge = try RootUpdateSchedulingChallenge.decode(bytes, limits: limits)
            var nonce = challenge.queryNonce; nonce[0] ^= 1
            let changed = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: challenge.canonicalControl, limits: limits)
            XCTAssertFalse(try verify(signature, key, changed.encode(limits: limits)))
            XCTAssertFalse(try UpdateSchedulingSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                canonicalPayload: challenge.canonicalControl, payloadLimits: limits, inputLimits: limits))
        }
        let row = vectors.valid[0], challenge = try RootUpdateSchedulingChallenge.decode(hex(row.hex), limits: limits)
        guard case let .map(original) = try DeterministicCBOR.decode(challenge.canonicalControl, limits: limits) else { return XCTFail() }
        for field in UInt64(1)...13 {
            var changed = original
            switch changed[field] {
            case var .bytes(value): value[0] ^= 1; changed[field] = .bytes(value)
            case let .unsigned(value): changed[field] = .unsigned(value + 1)
            default: return XCTFail()
            }
            let control = try DeterministicCBOR.encode(.map(changed), limits: limits)
            let bytes = try RootUpdateSchedulingChallenge(queryNonce: challenge.queryNonce, canonicalControl: control, limits: limits).encode(limits: limits)
            XCTAssertFalse(try verify(hex(row.signature!), key, bytes))
        }
    }

    func testResourceLimitsAndWireVersionRemainStrict() throws {
        let row = try vectors().valid[0], bytes = hex(row.hex)
        let challenge = try RootUpdateSchedulingChallenge.decode(bytes, limits: limits)
        for size in [31, 33] {
            XCTAssertThrowsError(try RootUpdateSchedulingChallenge(queryNonce: Data(repeating: 1, count: size),
                canonicalControl: challenge.canonicalControl, limits: limits))
        }
        for bounds in [try CBORLimits(maxBytes: bytes.count - 1, maxDepth: 8, maxItems: 64),
                       try CBORLimits(maxBytes: 2048, maxDepth: 1, maxItems: 2)] {
            XCTAssertThrowsError(try RootUpdateSchedulingChallenge.decode(bytes, limits: bounds))
            XCTAssertThrowsError(try challenge.encode(limits: bounds))
        }
        for version: UInt64 in [0, 2, .max] {
            XCTAssertThrowsError(try RootUpdateSchedulingChallengeSigningInput.make(wireVersion: version,
                canonicalPayload: bytes, payloadLimits: limits, inputLimits: limits))
        }
        let short = try CBORLimits(maxBytes: hex(row.signingInput!).count - 1, maxDepth: 8, maxItems: 64)
        XCTAssertThrowsError(try RootUpdateSchedulingChallengeSigningInput.make(wireVersion: 1,
            canonicalPayload: bytes, payloadLimits: limits, inputLimits: short))
    }

    func testValueSemanticsAndDescriptions() throws {
        let row = try vectors().valid[0]
        var nonce = hex(row.queryNonce!), control = hex(row.controlHex!)
        let challenge = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: control, limits: limits)
        nonce[0] ^= 1; control[0] ^= 1
        var exposed = challenge.canonicalControl; exposed[0] ^= 1
        XCTAssertEqual(try challenge.encode(limits: limits), hex(row.hex))
        XCTAssertEqual(String(describing: challenge), "RootUpdateSchedulingChallenge(redacted)")
        XCTAssertEqual(String(reflecting: challenge), "RootUpdateSchedulingChallenge(redacted)")
    }
}
