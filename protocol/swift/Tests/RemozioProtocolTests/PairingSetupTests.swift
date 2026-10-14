import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingSetupTests: XCTestCase {
    private struct Row: Decodable { let name: String; let hex: String }
    private struct Vectors: Decodable { let proposal: String; let transcript: String; let frames: [Row]; let invalidProposals: [Row]; let invalidFrames: [Row] }
    private func vectors() throws -> Vectors {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("vectors/pairing-setup-v1.json")))
    }
    private func hex(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map { offset in
            let start = s.index(s.startIndex, offsetBy: offset)
            return UInt8(s[start..<s.index(start, offsetBy: 2)], radix: 16)!
        })
    }
    func testSharedProposalAndEverySetupFrameAgree() throws {
        let v = try vectors(), proposal = try PairingPhoneProposal.decode(hex(v.proposal))
        XCTAssertEqual(try proposal.encode(), hex(v.proposal))
        try proposal.validate(PairingTranscript.decode(hex(v.transcript)))
        for row in v.frames {
            let value = try PairingSetupFrame.decode(hex(row.hex))
            XCTAssertEqual(try value.encode(), hex(row.hex)); XCTAssertEqual(value.description, "PairingSetupFrame(redacted)")
        }
        XCTAssertEqual(proposal.description, "PairingPhoneProposal(redacted)")
    }
    func testUnknownVersionsFieldsKindsAndAuthorityConfusionFail() throws {
        let v = try vectors()
        for row in v.invalidProposals { XCTAssertThrowsError(try PairingPhoneProposal.decode(hex(row.hex)), row.name) }
        for row in v.invalidFrames { XCTAssertThrowsError(try PairingSetupFrame.decode(hex(row.hex)), row.name) }
        XCTAssertThrowsError(try PairingSetupFrame.decode(Data(count: PairingSetupFrame.maximumBytes + 1)))
        XCTAssertThrowsError(try PairingPhoneProposal.decode(Data(count: 66001)))
    }
    func testPhoneClaimsBindOfferNonceAndEachKeyRole() throws {
        let v = try vectors(), transcript = try PairingTranscript.decode(hex(v.transcript)), proposal = try PairingPhoneProposal.decode(hex(v.proposal))
        let limits = try CBORLimits(maxBytes: 66000, maxDepth: 3, maxItems: 24)
        guard case .map(let f) = try DeterministicCBOR.decode(proposal.encode(), limits: limits), case .array(let keys) = f[3] else { return XCTFail() }
        let offerLimits = try CBORLimits(maxBytes: 65536, maxDepth: 5, maxItems: 5000)
        guard case .map(var offer) = try DeterministicCBOR.decode(proposal.phone.encode(), limits: offerLimits) else { return XCTFail() }
        offer[3] = .bytes(Data(repeating: 8, count: 32))
        var changedOffer = f; changedOffer[2] = .bytes(try DeterministicCBOR.encode(.map(offer), limits: offerLimits))
        var changedKeys = f; changedKeys[3] = .array([keys[1], keys[0], keys[2]])
        for changed in [changedOffer, changedKeys] {
            let other = try PairingPhoneProposal.decode(DeterministicCBOR.encode(.map(changed), limits: limits))
            XCTAssertThrowsError(try other.validate(transcript))
        }
    }
}
