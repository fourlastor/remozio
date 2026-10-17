#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation
import XCTest
@testable import RemozioProtocol

final class AuditHistoryStatusTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String; let input: String; let signature: String; let disposition: UInt64 }
    private struct Invalid: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let publicKey: String; let valid: [Row]; let invalid: [Invalid] }
    private var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 256) } }
    private var descriptorLimits: CBORLimits { get throws { try CBORLimits(maxBytes: 1024, maxDepth: 4, maxItems: 64) } }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/audit-history-status-v1.json")))
    }
    private func hex(_ text: String) -> Data {
        let chars = Array(text)
        return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }
    private func decode(_ bytes: Data) throws -> AuditHistoryStatus {
        try AuditHistoryStatus.decode(bytes, limits: limits, descriptorLimits: descriptorLimits)
    }
    func testSharedResponsesRoundTripAndKeepExplicitReconciliationStates() throws {
        let rows = try vectors().valid
        XCTAssertEqual(rows.count, 15)
        for row in rows {
            let body = hex(row.hex), status = try decode(body)
            XCTAssertEqual(try status.encode(limits: limits), body, row.name)
            XCTAssertEqual(status.disposition.rawValue, row.disposition)
            XCTAssertEqual(try AuditHistoryStatusSigningInput.make(wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: limits), hex(row.input))
        }
    }
    func testImpossibleStatesMalformedDescriptorsAndBoundsFail() throws {
        let fixture = try vectors()
        XCTAssertEqual(fixture.invalid.count, 61)
        for row in fixture.invalid { XCTAssertThrowsError(try decode(hex(row.hex)), row.name) }
        let body = hex(try XCTUnwrap(fixture.valid.first).hex)
        XCTAssertThrowsError(try AuditHistoryStatus.decode(body,
            limits: CBORLimits(maxBytes: body.count - 1, maxDepth: 8, maxItems: 256), descriptorLimits: descriptorLimits))
        XCTAssertThrowsError(try AuditHistoryStatus.decode(body, limits: limits,
            descriptorLimits: CBORLimits(maxBytes: 1, maxDepth: 4, maxItems: 64)))
        XCTAssertThrowsError(try decode(body + Data([0])))
        XCTAssertThrowsError(try decode(body).encode(limits: CBORLimits(maxBytes: 1, maxDepth: 8, maxItems: 256)))
    }
    func testSignaturesBindStatusAndCannotBeUsedAsBatchOrApproval() throws {
        let fixture = try vectors(), key = hex(fixture.publicKey)
        for row in fixture.valid {
            let body = hex(row.hex), signature = hex(row.signature)
            XCTAssertTrue(try AuditHistoryStatusSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertFalse(try AuditBatchSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertFalse(try ApprovalSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                messageType: .status, purpose: .status, canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            guard case let .map(fields) = try DeterministicCBOR.decode(body, limits: limits) else { return XCTFail() }
            for field in 1...UInt64(12) {
                var changed = fields; changed[field] = .text("altered")
                XCTAssertFalse(try AuditHistoryStatusSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                    canonicalPayload: DeterministicCBOR.encode(.map(changed), limits: limits), payloadLimits: limits, inputLimits: limits))
            }
            XCTAssertThrowsError(try AuditHistoryStatusSignature.verify(signature: signature, publicKey: key, wireVersion: 2,
                canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
            XCTAssertThrowsError(try AuditHistoryStatusSigningInput.make(wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: CBORLimits(maxBytes: 1, maxDepth: 8, maxItems: 256)))
            let disposable = P256.Signing.PrivateKey()
            let batchInput = try AuditBatchSigningInput.make(wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: limits)
            XCTAssertFalse(try AuditHistoryStatusSignature.verify(signature: disposable.signature(for: batchInput).rawRepresentation,
                publicKey: disposable.publicKey.x963Representation, wireVersion: 1, canonicalPayload: body,
                payloadLimits: limits, inputLimits: limits))
        }
    }
}
