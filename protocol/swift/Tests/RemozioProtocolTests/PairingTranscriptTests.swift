#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingTranscriptTests: XCTestCase {
    private struct Valid: Decodable { let name: String; let hex: String; let phoneInput: String; let macInput: String; let digest: String; let verificationCode: String }
    private struct Invalid: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let valid: [Valid]; let invalid: [Invalid] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/pairing-v1.json")))
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    func testSharedAddAndReplacementTranscriptsAgree() throws {
        for row in try vectors().valid {
            let transcript = try PairingTranscript.decode(hex(row.hex))
            XCTAssertEqual(try transcript.encode(), hex(row.hex))
            XCTAssertEqual(try transcript.signingInput(purpose: .phoneBiometric), hex(row.phoneInput))
            XCTAssertEqual(try transcript.signingInput(purpose: .macCommit), hex(row.macInput))
            XCTAssertEqual(try transcript.digest(), hex(row.digest))
            XCTAssertEqual(try transcript.verificationCode(), row.verificationCode)
            XCTAssertEqual(transcript.description, "PairingTranscript(redacted)")
        }
    }
    func testMalformedAndIncompatibleTranscriptsFail() throws {
        for row in try vectors().invalid { XCTAssertThrowsError(try PairingTranscript.decode(hex(row.hex)), row.name) }
        XCTAssertThrowsError(try PairingTranscript.decode(Data(repeating: 0, count: 132001)))
    }
    func testSignaturesBindPurposeAndTranscript() throws {
        let transcript = try PairingTranscript.decode(hex(vectors().valid[0].hex))
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: transcript.signingInput(purpose: .phoneBiometric)).rawRepresentation
        XCTAssertTrue(try transcript.verify(signature: signature, publicKey: key.publicKey.x963Representation, purpose: .phoneBiometric))
        XCTAssertFalse(try transcript.verify(signature: signature, publicKey: key.publicKey.x963Representation, purpose: .macCommit))
        let limits = try CBORLimits(maxBytes: 132000, maxDepth: 4, maxItems: 80)
        guard case let .map(fields) = try DeterministicCBOR.decode(transcript.encode(), limits: limits) else { return XCTFail() }
        for field: UInt64 in [1, 2, 10, 12] {
            var changed = fields
            guard case var .bytes(bytes) = fields[field] else { return XCTFail() }
            bytes[0] ^= 1; changed[field] = .bytes(bytes)
            let altered = try PairingTranscript.decode(DeterministicCBOR.encode(.map(changed), limits: limits))
            XCTAssertNotEqual(try altered.verificationCode(), try transcript.verificationCode())
            XCTAssertFalse(try altered.verify(signature: signature, publicKey: key.publicKey.x963Representation, purpose: .phoneBiometric))
        }
    }
}
