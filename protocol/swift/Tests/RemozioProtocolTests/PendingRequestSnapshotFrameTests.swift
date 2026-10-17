import Foundation
import XCTest
@testable import RemozioProtocol

final class PendingRequestSnapshotFrameTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Transfer: Decodable { let name: String; let query: String; let incoming: [String]; let valid: Bool }
    private struct Vectors: Decodable { let applicationProtocol: String; let valid: [Row]; let invalid: [Row]; let transfers: [Transfer] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/pending-snapshot-v1.json")))
    }
    private func hex(_ value: String) -> Data {
        Data(stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    func testSharedSnapshotVectorsAndRoles() throws {
        let values = try vectors()
        XCTAssertEqual(PendingRequestSnapshotFrame.applicationProtocol, values.applicationProtocol)
        for row in values.valid {
            let frame = try PendingRequestSnapshotFrame.decode(hex(row.hex))
            XCTAssertEqual(try frame.encode(), hex(row.hex), row.name)
            XCTAssertEqual(frame.description, "PendingRequestSnapshotFrame(redacted)")
            switch (row.name, frame) {
            case ("query", .query(let nonce, let frames, let bytes, let ids)):
                XCTAssertEqual(nonce, Data(0..<32)); XCTAssertEqual(frames, 128); XCTAssertEqual(bytes, 1_048_576); XCTAssertTrue(ids.isEmpty)
            case ("item", .item(let nonce, let ordinal, let bytes)):
                XCTAssertEqual(nonce, Data(0..<32)); XCTAssertEqual(ordinal, 0); XCTAssertEqual(bytes, Data([1, 2, 3]))
            case ("complete", .complete(let nonce, let frames, let bytes)):
                XCTAssertEqual(nonce, Data(0..<32)); XCTAssertEqual(frames, 1); XCTAssertEqual(bytes, 3)
            case ("empty", .complete(_, let frames, let bytes)):
                XCTAssertEqual(frames, 0); XCTAssertEqual(bytes, 0)
            case ("query-retained", .query(_, _, _, let ids)):
                XCTAssertEqual(ids, [Data(repeating: 1, count: 16), Data(repeating: 2, count: 16)])
            case ("maximum-query", .query), ("maximum-completion", .complete), ("last-ordinal", .item): break
            default: XCTFail(row.name)
            }
        }
    }
    func testMalformedOrConfusedSnapshotsFail() throws {
        for row in try vectors().invalid {
            XCTAssertThrowsError(try PendingRequestSnapshotFrame.decode(hex(row.hex)), row.name)
        }
        XCTAssertThrowsError(try PendingRequestSnapshotFrame.query(nonce: Data(count: 31), maximumFrames: 1, maximumBytes: 1).encode())
        XCTAssertThrowsError(try PendingRequestSnapshotFrame.item(nonce: Data(count: 32), ordinal: 0,
            frame: Data(count: PendingRequestSnapshotFrame.maximumFrameBytes + 1)).encode())
        XCTAssertThrowsError(try PendingRequestSnapshotFrame.decode(Data(count: PendingRequestSnapshotFrame.maximumBytes + 1)))
    }
    func testSharedTransferBoundariesAndPermanentFailure() throws {
        for row in try vectors().transfers {
            var owner = try PendingRequestSnapshotProgress(query: PendingRequestSnapshotFrame.decode(hex(row.query)))
            if row.valid {
                for bytes in row.incoming { _ = try owner.accept(hex(bytes)) }
                try owner.requireComplete()
                XCTAssertTrue(owner.isComplete, row.name)
            } else {
                XCTAssertThrowsError(try {
                    for bytes in row.incoming { _ = try owner.accept(hex(bytes)) }
                    try owner.requireComplete()
                }(), row.name)
                XCTAssertFalse(owner.isComplete, row.name)
                XCTAssertThrowsError(try owner.accept(PendingRequestSnapshotFrame.complete(nonce: Data(0..<32), frames: 0, bytes: 0).encode()), row.name)
                XCTAssertThrowsError(try owner.requireComplete(), row.name)
            }
        }
    }
    func testItemsRemainOpaqueUntilTheCallerVerifiesThem() throws {
        let nonce = Data(count: 32)
        var owner = try PendingRequestSnapshotProgress(query: .query(nonce: nonce, maximumFrames: 1, maximumBytes: 3))
        let frame = Data([1, 2, 3])
        XCTAssertEqual(try owner.accept(PendingRequestSnapshotFrame.item(nonce: nonce, ordinal: 0, frame: frame).encode()), frame)
        XCTAssertFalse(owner.isComplete)
    }
    func testRetainedRequestLimitAndCanonicalOrder() throws {
        func id(_ value: Int) -> Data { Data([UInt8(value >> 8), UInt8(value & 255)]) + Data(count: 14) }
        let ids = (0..<PendingRequestSnapshotFrame.maximumRetainedRequests).map(id)
        let query = PendingRequestSnapshotFrame.query(nonce: Data(count: 32), maximumFrames: 4096,
            maximumBytes: 67_108_864, retainedRequestIDs: ids.reversed())
        let bytes = try query.encode()
        guard case .query(_, _, _, let decoded) = try PendingRequestSnapshotFrame.decode(bytes) else { return XCTFail("Missing query") }
        XCTAssertEqual(decoded, ids)
        XCTAssertThrowsError(try PendingRequestSnapshotFrame.query(nonce: Data(count: 32), maximumFrames: 1,
            maximumBytes: 1, retainedRequestIDs: ids + [id(4096)]).encode())
    }
}
