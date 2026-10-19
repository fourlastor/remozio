import Foundation
import XCTest
@testable import RemozioProtocol

final class CBORTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 1_048_576, maxDepth: 32, maxItems: 65_536)

    func testSharedVectors() throws {
        struct Vector: Decodable { let name: String; let hex: String; let valid: Bool }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let file = root.appendingPathComponent("vectors/cbor-subset-v1.json")
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: file))
        XCTAssertGreaterThan(vectors.count, 50)
        for vector in vectors {
            let bytes = hex(vector.hex)
            if vector.valid {
                let value = try DeterministicCBOR.decode(bytes, limits: limits)
                XCTAssertEqual(try DeterministicCBOR.encode(value, limits: limits), bytes, vector.name)
            } else {
                XCTAssertThrowsError(try DeterministicCBOR.decode(bytes, limits: limits), vector.name)
            }
        }
    }

    func testDecodedMeaningsAndMapOrdering() throws {
        let examples: [(String, CBORValue)] = [
            ("1bffffffffffffffff", .unsigned(UInt64.max)),
            ("4300ff80", .bytes(Data([0, 255, 128]))),
            ("64f09f9982", .text("🙂")),
            ("63efbbbf", .text("\u{FEFF}")),
            ("64efbbbf61", .text("\u{FEFF}a")),
            ("83001818f6", .array([.unsigned(0), .unsigned(24), .null])),
            ("a300f401f518186178", .map([24: .text("x"), 1: .boolean(true), 0: .boolean(false)])),
            ("a1008200a10142ff00", .map([0: .array([.unsigned(0), .map([1: .bytes(Data([255, 0]))])])])),
        ]
        for (encoded, value) in examples {
            XCTAssertEqual(try DeterministicCBOR.decode(hex(encoded), limits: limits), value)
            XCTAssertEqual(try DeterministicCBOR.encode(value, limits: limits), hex(encoded))
        }
    }

    func testUnsupportedMajorTypesRejectBeforeReadingArguments() {
        // Negative integers and tags stay unsupported even when their argument is
        // missing or would otherwise be noncanonical. Preserve that error order.
        for major: UInt8 in [1, 6] {
            for additional: UInt8 in 0..<32 {
                let head = major << 5 | additional
                assertError(.unsupportedType) {
                    try DeterministicCBOR.decode(Data([head]), limits: limits)
                }
                assertError(.unsupportedType) {
                    try DeterministicCBOR.decode(Data([head, 0]), limits: limits)
                }
            }
        }
    }

    func testSimpleValuesKeepTheirExactAcceptedHeaders() throws {
        for head: UInt8 in 0xe0...0xff {
            switch head {
            case 0xf4:
                XCTAssertEqual(try DeterministicCBOR.decode(Data([head]), limits: limits), .boolean(false))
            case 0xf5:
                XCTAssertEqual(try DeterministicCBOR.decode(Data([head]), limits: limits), .boolean(true))
            case 0xf6:
                XCTAssertEqual(try DeterministicCBOR.decode(Data([head]), limits: limits), .null)
            default:
                assertError(.unsupportedType) {
                    try DeterministicCBOR.decode(Data([head]), limits: limits)
                }
            }
        }
        for head: UInt8 in [0xf4, 0xf5, 0xf6] {
            assertError(.trailingBytes) {
                try DeterministicCBOR.decode(Data([head, 0]), limits: limits)
            }
        }
    }

    func testTextRetainsExactUTF8() throws {
        // Swift text equality can normalize canonically equivalent spellings; wire bytes must not.
        let nfc = try DeterministicCBOR.encode(.text("é"), limits: limits)
        let decomposed = try DeterministicCBOR.encode(.text("e\u{301}"), limits: limits)
        XCTAssertEqual(nfc, hex("62c3a9"))
        XCTAssertEqual(decomposed, hex("6365cc81"))
        XCTAssertNotEqual(nfc, decomposed)
        XCTAssertNotEqual(try DeterministicCBOR.decode(nfc, limits: limits),
                          try DeterministicCBOR.decode(decomposed, limits: limits))
    }

    func testLimitsAtBoundaries() throws {
        let oneByte = try CBORLimits(maxBytes: 1, maxDepth: 0, maxItems: 1)
        XCTAssertEqual(try DeterministicCBOR.encode(.unsigned(23), limits: oneByte), hex("17"))
        XCTAssertEqual(try DeterministicCBOR.decode(hex("17"), limits: oneByte), .unsigned(23))
        assertError(.limitExceeded(.bytes)) { try DeterministicCBOR.encode(.unsigned(24), limits: oneByte) }
        assertError(.limitExceeded(.bytes)) { try DeterministicCBOR.decode(hex("1818"), limits: oneByte) }

        let shallow = try CBORLimits(maxBytes: 100, maxDepth: 1, maxItems: 10)
        let nested = CBORValue.array([.array([.null])])
        assertError(.limitExceeded(.depth)) { try DeterministicCBOR.encode(nested, limits: shallow) }
        assertError(.limitExceeded(.depth)) { try DeterministicCBOR.decode(hex("8181f6"), limits: shallow) }
        XCTAssertEqual(try DeterministicCBOR.decode(hex("8180"), limits: shallow), .array([.array([])]))

        let threeItems = try CBORLimits(maxBytes: 100, maxDepth: 8, maxItems: 3)
        XCTAssertEqual(try DeterministicCBOR.encode(.map([0: .null]), limits: threeItems), hex("a100f6"))
        XCTAssertEqual(try DeterministicCBOR.decode(hex("a100f6"), limits: threeItems), .map([0: .null]))
        assertError(.limitExceeded(.items)) { try DeterministicCBOR.encode(.array([.null, .null, .null]), limits: threeItems) }
        assertError(.limitExceeded(.items)) { try DeterministicCBOR.decode(hex("83f6f6f6"), limits: threeItems) }
        XCTAssertThrowsError(try CBORLimits(maxBytes: 0, maxDepth: 1, maxItems: 1))
        XCTAssertThrowsError(try CBORLimits(maxBytes: 1, maxDepth: 65, maxItems: 1))
        XCTAssertThrowsError(try CBORLimits(maxBytes: 1, maxDepth: -1, maxItems: 1))
        XCTAssertThrowsError(try CBORLimits(maxBytes: 1, maxDepth: 1, maxItems: 0))
    }

    func testSlicedData() throws {
        let data = Data([255, 130, 0, 1, 255])
        XCTAssertEqual(try DeterministicCBOR.decode(data[1..<4], limits: limits), .array([.unsigned(0), .unsigned(1)]))
    }

    func testDeterministicMalformedCorpus() throws {
        var random: UInt64 = 0x52454d4f5a494f
        for _ in 0..<10_000 {
            random = random &* 6364136223846793005 &+ 1
            let length = Int(random % 64)
            var bytes = Data()
            for _ in 0..<length {
                random = random &* 6364136223846793005 &+ 1
                bytes.append(UInt8(truncatingIfNeeded: random >> 32))
            }
            do {
                let value = try DeterministicCBOR.decode(bytes, limits: limits)
                XCTAssertEqual(try DeterministicCBOR.encode(value, limits: limits), bytes)
            } catch is CBORError {
                // Rejection is expected. Any other error or crash fails the corpus run.
            }
        }
    }

    private func hex(_ string: String) -> Data {
        let bytes = Array(string.utf8)
        precondition(bytes.count.isMultiple(of: 2))
        return Data(stride(from: 0, to: bytes.count, by: 2).map { offset in
            UInt8(String(bytes: bytes[offset..<offset + 2], encoding: .utf8)!, radix: 16)!
        })
    }

    private func assertError<T>(_ expected: CBORError, _ action: () throws -> T,
                                file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) { error in
            XCTAssertEqual(error as? CBORError, expected, file: file, line: line)
        }
    }
}
