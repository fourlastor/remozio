import Foundation
import XCTest
@testable import RemozioProtocol

final class PhoneAuditTests: XCTestCase {
    private struct Row: Decodable {
        let name: String; let hex: String; let query: Bool?
        let payloadHex: String?; let signature: String?; let publicKey: String?; let innerKind: String?; let sourceName: String?
    }
    private struct Vectors: Decodable { let valid: [Row]; let invalid: [Row] }
    private struct OriginalRow: Decodable { let name: String; let hex: String; let signature: String }
    private struct Original: Decodable { let publicKey: String; let valid: [OriginalRow] }
    private var directory: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("vectors")
    }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 8, maxItems: 256) } }
    private func vectors() throws -> Vectors { try JSONDecoder().decode(Vectors.self,
        from: Data(contentsOf: directory.appendingPathComponent("phone-audit-v1.json"))) }
    private func hex(_ text: String) -> Data {
        Data(stride(from: 0, to: text.count, by: 2).map { offset in
            let start = text.index(text.startIndex, offsetBy: offset)
            return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
        })
    }

    func testSharedFramesKeepExactBytesAndRoles() throws {
        let rows = try vectors().valid; XCTAssertEqual(rows.count, 32)
        for row in rows {
            let bytes = hex(row.hex), frame = try PhoneAuditFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes, row.name)
            XCTAssertEqual(frame.isQuery, row.query, row.name)
            XCTAssertEqual(String(reflecting: frame), "PhoneAuditFrame(redacted)")
            if frame.isQuery { XCTAssertLessThanOrEqual(bytes.count, PhoneAuditFrame.maximumQueryBytes) }
        }
    }
    func testMalformedOuterFramesFailClosed() throws {
        let rows = try vectors().invalid; XCTAssertEqual(rows.count, 89)
        for row in rows { XCTAssertThrowsError(try PhoneAuditFrame.decode(hex(row.hex)), row.name) }
    }
    func testExistingSignedPayloadsAreUnchangedAndKeepTheirOwnPurposes() throws {
        let history = try JSONDecoder().decode(Original.self, from: Data(contentsOf: directory.appendingPathComponent("audit-history-status-v1.json")))
        let pages = try JSONDecoder().decode(Original.self, from: Data(contentsOf: directory.appendingPathComponent("audit-batches-v1.json")))
        let rows = try vectors().valid.filter { $0.payloadHex != nil }; XCTAssertEqual(rows.count, 23)
        for row in rows {
            let body = hex(row.payloadHex!), signature = hex(row.signature!), key = hex(row.publicKey!)
            let original = row.innerKind == "history" ? history : pages
            let source = try XCTUnwrap(original.valid.first { $0.name == row.sourceName })
            XCTAssertEqual(source.hex, row.payloadHex); XCTAssertEqual(source.signature, row.signature)
            XCTAssertEqual(original.publicKey, row.publicKey)
            let frame = try PhoneAuditFrame.decode(hex(row.hex))
            switch frame {
            case .historyResponse(let nonce, let payload, let signed):
                XCTAssertEqual(payload, body); XCTAssertEqual(signed, signature)
                let status = try AuditHistoryStatus.decode(body, limits: limits, descriptorLimits: limits)
                XCTAssertEqual(nonce, status.queryNonce)
                XCTAssertTrue(try AuditHistoryStatusSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                    canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
                XCTAssertFalse((try? AuditBatchSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                    canonicalPayload: body, payloadLimits: limits, inputLimits: limits)) ?? false)
            case .pageResponse(let nonce, let payload, let signed):
                XCTAssertEqual(payload, body); XCTAssertEqual(signed, signature)
                let batch = try AuditBatch.decode(body, batchLimits: limits, recordLimits: limits, maximumRecords: 2)
                XCTAssertEqual(nonce, batch.queryNonce)
                XCTAssertTrue(try AuditBatchSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                    canonicalPayload: body, payloadLimits: limits, inputLimits: limits))
                XCTAssertFalse((try? AuditHistoryStatusSignature.verify(signature: signature, publicKey: key, wireVersion: 1,
                    canonicalPayload: body, payloadLimits: limits, inputLimits: limits)) ?? false)
            default: XCTFail(row.name)
            }
        }
    }
    func testConstructorsRejectPartialHistoryAndInvalidIdentifiers() throws {
        let nonce = Data(repeating: 9, count: 32), epoch = Data(repeating: 3, count: 16)
        for frame: PhoneAuditFrame in [.historyQuery(queryNonce: nonce, epoch: nil, after: 0),
            .historyQuery(queryNonce: nonce, epoch: epoch, after: nil),
            .historyQuery(queryNonce: Data(), epoch: nil, after: nil),
            .pageQuery(queryNonce: nonce, epoch: Data(repeating: 3, count: 15), generation: 0, after: 0),
            .historyResponse(queryNonce: nonce, canonicalPayload: Data([0]), signature: Data(repeating: 0, count: 63))] {
            XCTAssertThrowsError(try frame.encode())
        }
    }
    func testReplyPayloadAndCarrierResourceBounds() throws {
        let nonce = Data(repeating: 9, count: 32), signature = Data(repeating: 0, count: 64)
        let body = Data(repeating: 7, count: PhoneAuditFrame.maximumPayloadBytes)
        let bytes = try PhoneAuditFrame.pageResponse(queryNonce: nonce, canonicalPayload: body, signature: signature).encode()
        XCTAssertLessThanOrEqual(bytes.count, body.count + PhoneAuditFrame.overheadBytes)
        XCTAssertEqual(try PhoneAuditFrame.decode(bytes).encode(), bytes)
        XCTAssertThrowsError(try PhoneAuditFrame.pageResponse(queryNonce: nonce,
            canonicalPayload: body + Data([7]), signature: signature).encode())
        XCTAssertThrowsError(try PhoneAuditFrame.decode(Data(repeating: 0, count: PhoneAuditFrame.maximumBytes + 1)))
        XCTAssertThrowsError(try PhoneAuditFrame.historyResponse(queryNonce: nonce, canonicalPayload: Data(), signature: signature).encode())
    }
    func testValueCopiesAndDescriptionsDoNotExposeMutablePayloads() throws {
        var nonce = Data(repeating: 9, count: 32), body = Data([0]), signature = Data(repeating: 0, count: 64)
        let frame = PhoneAuditFrame.historyResponse(queryNonce: nonce, canonicalPayload: body, signature: signature)
        let before = try frame.encode(); nonce[0] = 1; body[0] = 1; signature[0] = 1
        var returnedNonce = frame.queryNonce; returnedNonce[0] = 1
        XCTAssertEqual(try frame.encode(), before); XCTAssertNotEqual(frame.queryNonce, returnedNonce)
        XCTAssertEqual(String(reflecting: frame), "PhoneAuditFrame(redacted)")
    }
    func testOpaqueReplyParsingDoesNotEstablishAuditValidity() throws {
        let bytes = try PhoneAuditFrame.historyResponse(queryNonce: Data(repeating: 9, count: 32),
            canonicalPayload: Data([0]), signature: Data(repeating: 0, count: 64)).encode()
        guard case .historyResponse(_, let body, _) = try PhoneAuditFrame.decode(bytes) else { return XCTFail() }
        XCTAssertEqual(body, Data([0]))
        XCTAssertThrowsError(try AuditHistoryStatus.decode(body, limits: limits, descriptorLimits: limits))
    }
}
