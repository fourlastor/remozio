#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class ApprovalSignatureTests: XCTestCase {
    private struct Vector: Decodable {
        let type: UInt64
        let purpose: UInt64
        let payload: String
        let publicKey: String
        let signature: String
        let derSignature: String
        let producer: String
    }

    private func vectors() throws -> [Vector] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: root.appendingPathComponent("vectors/approval-signatures-v1.json")))
    }

    private func verify(_ vector: Vector, signature: Data? = nil, key: Data? = nil,
                        payload: Data? = nil, type: ApprovalMessageType? = nil, purpose: SigningPurpose? = nil) throws -> Bool {
        let limits = try CBORLimits(maxBytes: 1024, maxDepth: 8, maxItems: 64)
        return try ApprovalSignature.verify(signature: signature ?? hex(vector.signature), publicKey: key ?? hex(vector.publicKey),
            wireVersion: 1, messageType: type ?? XCTUnwrap(ApprovalMessageType(rawValue: vector.type)),
            purpose: purpose ?? XCTUnwrap(SigningPurpose(rawValue: vector.purpose)),
            canonicalPayload: payload ?? hex(vector.payload), payloadLimits: limits, inputLimits: limits)
    }

    func testBothNativeProducersVerifyAndChangedContextFails() throws {
        let rows = try vectors()
        XCTAssertEqual(rows.count, 20)
        XCTAssertEqual(Set(rows.map(\.producer)), ["CryptoKit", "Java 21 SunEC"])
        for row in rows {
            let der = try P256.Signing.ECDSASignature(derRepresentation: hex(row.derSignature))
            XCTAssertEqual(der.rawRepresentation, hex(row.signature))
            XCTAssertEqual(der.derRepresentation, hex(row.derSignature))
            XCTAssertTrue(try verify(row, signature: der.rawRepresentation), row.producer)
            XCTAssertFalse(try verify(row, payload: hex("a10002")))
            let alteredType: ApprovalMessageType = row.type == 3 ? .request : .status
            let alteredPurpose: SigningPurpose = row.type == 3 ? .issuedRequest : .status
            XCTAssertFalse(try verify(row, type: alteredType, purpose: alteredPurpose))
            var changed = hex(row.signature)
            changed[changed.startIndex] ^= 1
            XCTAssertFalse(try verify(row, signature: changed))
        }
        XCTAssertFalse(try verify(rows[0], key: hex(rows[10].publicKey)))
        XCTAssertFalse(try verify(rows[2], purpose: .oneTimeUI))
    }

    func testMalformedSignaturesAndPointsFail() throws {
        let row = try XCTUnwrap(vectors().first)
        for count in [0, 1, 63, 65, 128] {
            XCTAssertFalse(try verify(row, signature: Data(repeating: 0, count: count)))
        }
        let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        for scalar in [Data(repeating: 0, count: 32), order, Data(repeating: 255, count: 32)] {
            let signature = hex(row.signature)
            XCTAssertFalse(try verify(row, signature: scalar + signature.suffix(32)))
            XCTAssertFalse(try verify(row, signature: signature.prefix(32) + scalar))
        }
        for count in [0, 1, 33, 64, 66, 128] {
            XCTAssertFalse(try verify(row, key: Data(repeating: 4, count: count)))
        }
        var wrongPrefix = hex(row.publicKey)
        wrongPrefix[wrongPrefix.startIndex] = 2
        XCTAssertFalse(try verify(row, key: wrongPrefix))
        XCTAssertFalse(try verify(row, key: Data([4]) + Data(repeating: 0, count: 64)))
        XCTAssertFalse(try verify(row, key: Data([4]) + Data(repeating: 255, count: 64)))
    }

    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }
}
