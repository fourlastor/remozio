import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingInvitationTests: XCTestCase {
    private struct Valid: Decodable { let name: String; let hex: String; let text: String; let fingerprint: String }
    private struct Invalid: Decodable { let name: String; let hex: String }
    private struct RePair: Decodable { let hex: String; let ordinaryHex: String; let text: String }
    private struct Vectors: Decodable {
        let valid: [Valid]
        let invalid: [Invalid]
        let rePairValid: [RePair]
        let rePairInvalid: [Invalid]
    }
    private var vectorRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("vectors")
    }
    private func vectors() throws -> Vectors {
        try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: vectorRoot.appendingPathComponent("pairing-invitation-v1.json")))
    }
    private func hex(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map { n in
            let start = s.index(s.startIndex, offsetBy: n)
            return UInt8(s[start..<s.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    private func sample() throws -> PairingInvitation { try .decode(hex(vectors().valid[0].hex)) }
    private func transcript() throws -> PairingTranscript {
        let data = try Data(contentsOf: vectorRoot.appendingPathComponent("pairing-v1.json"))
        let rows = try XCTUnwrap((JSONSerialization.jsonObject(with: data) as? [String: Any])?["valid"] as? [[String: String]])
        return try PairingTranscript.decode(hex(XCTUnwrap(rows.first?["hex"])))
    }
    func testSharedQRAndTextInvitationsAgree() throws {
        for row in try vectors().valid {
            let invitation = try PairingInvitation.decode(hex(row.hex))
            XCTAssertEqual(try invitation.exportText(), row.text)
            XCTAssertEqual(try invitation.fingerprint(), row.fingerprint)
            XCTAssertEqual(try PairingInvitation.importText(row.text).encode(), hex(row.hex))
            XCTAssertEqual(invitation.description, "PairingInvitation(redacted)")
        }
    }
    func testSharedRePairInvitationWrapsTheExactOrdinaryBytes() throws {
        for row in try vectors().rePairValid {
            let rePair = try RePairInvitation.importText(row.text)
            XCTAssertEqual(try rePair.encode(), hex(row.hex))
            XCTAssertEqual(try rePair.invitation.encode(), hex(row.ordinaryHex))
            XCTAssertEqual(try RePairInvitation.decode(hex(row.hex)).exportText(), row.text)
            XCTAssertEqual(rePair.predecessor.phoneID, Data(repeating: 3, count: 16))
            XCTAssertEqual(rePair.predecessor.epoch, Data(repeating: 10, count: 16))
            XCTAssertThrowsError(try PairingInvitation.importText(row.text))
        }
    }

    func testRePairInvitationRefusesMalformedAndOversizedInputs() throws {
        let samples = try vectors()
        for row in samples.rePairInvalid {
            XCTAssertThrowsError(try RePairInvitation.decode(hex(row.hex)), row.name)
        }
        let text = try XCTUnwrap(samples.rePairValid.first).text
        for bad in [text + "=", text + "\n", text.replacingOccurrences(of: ":v1:", with: ":v2:"),
                    "remozio-repair:v1:" + String(repeating: "A", count: 900)] {
            XCTAssertThrowsError(try RePairInvitation.importText(bad))
        }
        XCTAssertThrowsError(try RePairInvitation.decode(Data(repeating: 0, count: 641)))
    }

    func testMalformedAndOversizedInvitationsFail() throws {
        for row in try vectors().invalid { XCTAssertThrowsError(try PairingInvitation.decode(hex(row.hex)), row.name) }
        XCTAssertThrowsError(try PairingInvitation.decode(Data(repeating: 0, count: 513)))
        let text = try sample().exportText()
        for bad in ["", text + "=", text + "\n", " " + text, text.replacingOccurrences(of: "v1:", with: "v2:"),
            text.replacingOccurrences(of: "remozio-pairing:", with: "https://example.com/"), "remozio-pairing:v1:A",
            "remozio-pairing:v1:" + String(repeating: "A", count: 700), "remozio-pairing:v1:" + String(repeating: "é", count: 300)] {
            XCTAssertThrowsError(try PairingInvitation.importText(bad))
        }
    }
    func testNonzeroBase64PadBitsCannotAliasAnInvitation() throws {
        let text = try sample().exportText(), alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        XCTAssertEqual((text.count - "remozio-pairing:v1:".count) % 4, 3)
        let i = try XCTUnwrap(alphabet.firstIndex(of: text.last!))
        XCTAssertEqual(i & 3, 0)
        for offset in 1...3 { XCTAssertThrowsError(try PairingInvitation.importText(String(text.dropLast()) + String(alphabet[i + offset]))) }
    }
    func testEveryClaimChangesTheFullFingerprint() throws {
        let invitation = try sample(), limits = try CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 15)
        guard case .map(let f) = try DeterministicCBOR.decode(invitation.encode(), limits: limits) else { return XCTFail() }
        let anotherPoint = try transcript().transportKey.publicKey
        let variants: [UInt64: CBORValue] = [1: .bytes(Data(repeating: 8, count: 16)), 2: .bytes(Data(repeating: 9, count: 16)),
            3: .text("Another Mac"), 4: .bytes(anotherPoint), 5: .bytes(anotherPoint), 6: .unsigned(2)]
        for (field, value) in variants {
            var changed = f; changed[field] = value
            let other = try PairingInvitation.decode(DeterministicCBOR.encode(.map(changed), limits: limits))
            XCTAssertNotEqual(try invitation.fingerprint(), try other.fingerprint())
        }
    }
    func testTranscriptChecksScopeBothPinsAndExactFloor() throws {
        let transcript = try transcript()
        let invitation = try sample(), limits = try CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 15)
        try invitation.validateMacClaims(in: transcript)
        guard case .map(let f) = try DeterministicCBOR.decode(invitation.encode(), limits: limits) else { return XCTFail() }
        var authority = f; authority[4] = .bytes(transcript.transportKey.publicKey)
        var transport = f; transport[5] = .bytes(transcript.transportKey.publicKey)
        var mac = f; mac[1] = .bytes(Data(repeating: 8, count: 16))
        var account = f; account[2] = .bytes(Data(repeating: 9, count: 16))
        var floor = f; floor[6] = .unsigned(2)
        for claims in [authority, transport, mac, account, floor] {
            let changed = try PairingInvitation.decode(DeterministicCBOR.encode(.map(claims), limits: limits))
            XCTAssertThrowsError(try changed.validateMacClaims(in: transcript))
        }
    }
}
