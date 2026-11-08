import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

final class LowercaseHexadecimalTests: XCTestCase {
    func testEveryByteMatchesTheFoundationFormatItReplaces() {
        let bytes = Data(0...255)
        XCTAssertEqual(LowercaseHexadecimal.encode(bytes), bytes.map { String(format: "%02x", $0) }.joined())
    }

    func testEmptyInputsAndDigestPrefixesKeepTheirText() {
        XCTAssertEqual(LowercaseHexadecimal.encode(Data()), "")
        XCTAssertEqual(LowercaseHexadecimal.encode([UInt8]()), "")
        let digest = SHA256.hash(data: Data("remozio".utf8))
        XCTAssertEqual(LowercaseHexadecimal.encode(digest.prefix(12)), digest.prefix(12).map { String(format: "%02x", $0) }.joined())
        XCTAssertEqual(XPCPeerPolicy.hexadecimalCodeDirectoryHash(Data([0, 0x0f, 0xa0, 0xff])), "000fa0ff")
    }
}
