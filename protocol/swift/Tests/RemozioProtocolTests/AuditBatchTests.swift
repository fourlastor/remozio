#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class AuditBatchTests: XCTestCase {
    private struct Row: Decodable {
        let name: String; let hex: String; let input: String; let signature: String
        let nextAfter: String; let hasMore: Bool; let retentionGap: Bool
    }
    private struct Invalid: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let publicKey: String; let valid: [Row]; let invalid: [Invalid] }
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 256) } }
    private var recordLimits: CBORLimits { get throws { try CBORLimits(maxBytes: 1024, maxDepth: 4, maxItems: 64) } }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/audit-batches-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }
    private func decode(_ bytes: Data) throws -> AuditBatch {
        try AuditBatch.decode(bytes, batchLimits: limits, recordLimits: recordLimits, maximumRecords: 2)
    }

    func testSharedPagesHaveExactBytesAndExplicitBoundaries() throws {
        let rows = try vectors().valid
        XCTAssertEqual(rows.count, 8)
        for row in rows {
            let body = hex(row.hex), batch = try decode(body)
            XCTAssertEqual(try batch.encode(limits: limits), body, row.name)
            XCTAssertEqual(batch.nextAfter, UInt64(row.nextAfter))
            XCTAssertEqual(batch.hasMore, row.hasMore)
            XCTAssertEqual(batch.retentionGap, row.retentionGap)
            XCTAssertEqual(try AuditBatchSigningInput.make(wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: limits), hex(row.input))
        }
    }

    func testMalformedPagesAndIndependentBoundsFail() throws {
        let fixture = try vectors()
        XCTAssertEqual(fixture.invalid.count, 39)
        for row in fixture.invalid { XCTAssertThrowsError(try decode(hex(row.hex)), row.name) }
        let body = hex(try XCTUnwrap(fixture.valid.first).hex)
        XCTAssertThrowsError(try AuditBatch.decode(body, batchLimits: limits, recordLimits: recordLimits, maximumRecords: 1))
        XCTAssertThrowsError(try AuditBatch.decode(body, batchLimits: limits, recordLimits: recordLimits, maximumRecords: 0))
        let small = try CBORLimits(maxBytes: body.count - 1, maxDepth: 8, maxItems: 256)
        XCTAssertThrowsError(try AuditBatch.decode(body, batchLimits: small, recordLimits: recordLimits, maximumRecords: 2))
        XCTAssertThrowsError(try AuditBatch.decode(body, batchLimits: limits,
            recordLimits: CBORLimits(maxBytes: 1, maxDepth: 4, maxItems: 64), maximumRecords: 2))
        XCTAssertThrowsError(try decode(body + Data([0])))
        XCTAssertThrowsError(try decode(body).encode(limits: small))
    }

    func testSignaturesBindEveryByteAndCannotCrossApprovalDomain() throws {
        let fixture = try vectors(), key = hex(fixture.publicKey)
        for row in fixture.valid {
            let body = hex(row.hex), signature = hex(row.signature)
            XCTAssertTrue(try AuditBatchSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertFalse(try ApprovalSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                messageType: .request, purpose: .issuedRequest, canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            guard case let .map(fields) = try DeterministicCBOR.decode(body, limits: limits) else { return XCTFail() }
            for field in 1...UInt64(8) {
                var changed = fields
                switch fields[field] {
                case var .bytes(data): data[0] ^= 1; changed[field] = .bytes(data)
                case let .unsigned(value): changed[field] = .unsigned(value ^ 1)
                default: return XCTFail()
                }
                XCTAssertFalse(try AuditBatchSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                    canonicalPayload: DeterministicCBOR.encode(.map(changed), limits: limits), payloadLimits: limits, inputLimits: limits))
            }
            XCTAssertFalse(try AuditBatchSignature.verify(signature: signature.dropLast(), publicKey: key, wireVersion: 1,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertFalse(try AuditBatchSignature.verify(signature: signature, publicKey: Data(repeating: 0, count: 65), wireVersion: 1,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertThrowsError(try AuditBatchSignature.verify(signature: signature, publicKey: key, wireVersion: 2,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertThrowsError(try AuditBatchSigningInput.make(wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: CBORLimits(maxBytes: 1, maxDepth: 8, maxItems: 256)))
            // Sign under the approval domain and ensure the audit verifier rejects the reverse substitution too.
            let disposable = P256.Signing.PrivateKey()
            let approval = try SigningInput.make(wireVersion: 1, messageType: .request, purpose: .issuedRequest,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits)
            XCTAssertFalse(try AuditBatchSignature.verify(signature: disposable.signature(for: approval).rawRepresentation,
                publicKey: disposable.publicKey.x963Representation, wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: limits))
        }
    }
}
