import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingReceiptFrameTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let applicationProtocol: String; let valid: [Row]; let invalid: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/pairing-receipt-v1.json")))
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    func testSharedRecoveryVectorsAndMessageRoles() throws {
        let values = try vectors()
        XCTAssertEqual(PairingReceiptFrame.applicationProtocol, values.applicationProtocol)
        for row in values.valid {
            let frame = try PairingReceiptFrame.decode(hex(row.hex))
            XCTAssertEqual(try frame.encode(), hex(row.hex))
            XCTAssertEqual(frame.description, "PairingReceiptFrame(redacted)")
            switch (row.name, frame) {
            case ("query", .query(let id)): XCTAssertEqual(id, Data(0..<16))
            case ("receipt", .response(let id, let signature)):
                XCTAssertEqual(id, Data(0..<16)); XCTAssertEqual(signature, Data(0..<64))
            case ("unavailable", .response(let id, nil)): XCTAssertEqual(id, Data(0..<16))
            default: XCTFail(row.name)
            }
        }
    }
    func testMalformedAndConfusedRecoveryMessagesFail() throws {
        for row in try vectors().invalid {
            XCTAssertThrowsError(try PairingReceiptFrame.decode(hex(row.hex)), row.name)
        }
        XCTAssertThrowsError(try PairingReceiptFrame.decode(Data(count: PairingReceiptFrame.maximumBytes + 1)))
        XCTAssertThrowsError(try PairingReceiptFrame.query(setupID: Data(count: 15)).encode())
        XCTAssertThrowsError(try PairingReceiptFrame.response(setupID: Data(count: 16), signature: Data(count: 63)).encode())
    }
}
