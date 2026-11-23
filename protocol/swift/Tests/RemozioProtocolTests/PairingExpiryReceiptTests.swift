import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingExpiryReceiptTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Valid: Decodable {
        let name: String
        let hex: String
        let signingInput: String
        let reason: UInt64
    }
    private struct Vectors: Decodable {
        let transcript: String
        let ordinaryTranscript: String
        let valid: [Valid]
        let invalid: [Row]
        let unverified: [Row]
    }

    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self,
            from: Data(contentsOf: root.appendingPathComponent("vectors/pairing-expiry-receipt-v1.json")))
    }

    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }

    func testSharedExpiryReceiptsRoundTripAndVerify() throws {
        let values = try vectors()
        let transcript = try PairingTranscript.decode(hex(values.transcript))
        for row in values.valid {
            let bytes = hex(row.hex)
            let receipt = try PairingExpiryReceipt.decode(bytes)
            XCTAssertEqual(try receipt.encode(), bytes, row.name)
            XCTAssertEqual(receipt.setupID, transcript.setupID, row.name)
            XCTAssertEqual(receipt.reason.rawValue, row.reason, row.name)
            XCTAssertEqual(receipt.description, "PairingExpiryReceipt(redacted)", row.name)
            XCTAssertEqual(try PairingExpiryReceipt.signingInput(transcript: transcript, reason: receipt.reason),
                hex(row.signingInput), row.name)
            XCTAssertEqual(try PairingExpiryReceipt(transcript: transcript, reason: receipt.reason, signature: receipt.signature)
                .encode(), bytes, row.name)
            XCTAssertTrue(try receipt.verify(transcript: transcript), row.name)
        }
    }

    func testMalformedExpiryReceiptsAndEnrolledReceiptFramesAreRejected() throws {
        let values = try vectors()
        for row in values.invalid {
            XCTAssertThrowsError(try PairingExpiryReceipt.decode(hex(row.hex)), row.name)
        }
        for row in values.valid {
            XCTAssertThrowsError(try PairingReceiptFrame.decode(hex(row.hex)), row.name)
        }
        XCTAssertThrowsError(try PairingExpiryReceipt.decode(Data(count: PairingExpiryReceipt.maximumBytes + 1)))
    }

    func testExpiryVerificationBindsTheRetainedTranscriptAndRootSignature() throws {
        let values = try vectors()
        let transcript = try PairingTranscript.decode(hex(values.transcript))
        for row in values.unverified {
            let receipt = try PairingExpiryReceipt.decode(hex(row.hex))
            XCTAssertFalse(try receipt.verify(transcript: transcript), row.name)
        }
        let ordinary = try PairingTranscript.decode(hex(values.ordinaryTranscript))
        let row = try XCTUnwrap(values.valid.first)
        let receipt = try PairingExpiryReceipt.decode(hex(row.hex))
        XCTAssertFalse(try receipt.verify(transcript: ordinary))
        XCTAssertThrowsError(try PairingExpiryReceipt.signingInput(transcript: ordinary, reason: .deadlineElapsed))
    }
}
