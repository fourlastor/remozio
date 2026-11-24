import Foundation
import XCTest
@testable import RemozioProtocol

final class PairingRecoveryFrameTests: XCTestCase {
    private struct RecoveryVectors: Decodable {
        let exporter: String
        let challenge: String
        let signingInput: String
        let transcript: String
        let frames: [String: String]
    }

    func testSharedRecoveryFramesRoundTripIncludingSignedExpiry() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let vectors = try JSONDecoder().decode(RecoveryVectors.self,
            from: Data(contentsOf: root.appendingPathComponent("vectors/pairing-recovery-frames-v1.json")))
        func hex(_ value: String) throws -> Data {
            let bytes = Array(value.utf8)
            return try Data(stride(from: 0, to: bytes.count, by: 2).map { offset in
                try XCTUnwrap(UInt8(String(decoding: bytes[offset..<offset + 2], as: UTF8.self), radix: 16))
            })
        }
        let transcript = try PairingTranscript.decode(hex(vectors.transcript))
        for (name, value) in vectors.frames {
            let bytes = try hex(value)
            let frame = try PairingRecoveryFrame.decode(bytes)
            XCTAssertEqual(try frame.encode(), bytes, name)
            switch frame {
            case .lookup(let query):
                XCTAssertEqual(try query.signingInput(exporter: hex(vectors.exporter), challenge: hex(vectors.challenge)),
                    try hex(vectors.signingInput))
            case .expired(let receipt):
                XCTAssertTrue(try receipt.verify(transcript: transcript), name)
            default:
                XCTAssertFalse(name.hasPrefix("expired-"))
            }
        }
    }

    func testLookupAndProofUseFixedLengths() throws {
        let query = try makeQuery()
        let lookup = try PairingRecoveryFrame.lookup(query).encode()
        XCTAssertEqual(lookup.count, 113)
        guard case let .lookup(decoded) = try PairingRecoveryFrame.decode(lookup) else {
            return XCTFail("Expected a lookup")
        }
        XCTAssertEqual(decoded, query)
        let challenge = Data(repeating: 7, count: 32)
        let proof = Data(repeating: 8, count: 64)
        XCTAssertEqual(try PairingRecoveryFrame.challenge(challenge).encode(), Data([1]) + challenge)
        XCTAssertEqual(try PairingRecoveryFrame.proof(proof).encode(), Data([2]) + proof)
        XCTAssertEqual(try PairingRecoveryFrame.refused.encode(), Data([3]))
        XCTAssertEqual(try PairingRecoveryFrame.committed(signature: proof).encode(), Data([4]) + proof)
    }

    func testDecoderRejectsUnknownTagsMissingBytesAndTrailingData() throws {
        let lookup = try PairingRecoveryFrame.lookup(makeQuery()).encode()
        let truncatedLookup = Data(lookup.dropLast())
        let extendedLookup = lookup + Data([0])
        let shortChallenge = Data([1]) + Data(count: 31)
        let shortProof = Data([2]) + Data(count: 63)
        let longCommit = Data([4]) + Data(count: 65)
        let invalidFrames: [Data] = [Data(), Data([255]), Data([3, 0]), truncatedLookup, extendedLookup,
                                     shortChallenge, shortProof, longCommit]
        for invalid in invalidFrames {
            XCTAssertThrowsError(try PairingRecoveryFrame.decode(invalid))
        }
        XCTAssertThrowsError(try PairingRecoveryFrame.decode(Data(count: PairingRecoveryFrame.maximumBytes + 1)))
    }

    func testSigningInputBindsEveryFieldInOrder() throws {
        let exporter = Data(repeating: 7, count: 32)
        let challenge = Data(repeating: 8, count: 32)
        let query = try makeQuery()
        var expected = Data("dev.remozio.pairing.recovery-lookup/1".utf8)
        expected.append(0)
        for field in [exporter, challenge, query.setupID, query.transcriptDigest, query.scope.macID,
                      query.scope.accountID, query.scope.phoneID, query.scope.enrollmentEpoch] {
            expected.append(field)
        }
        XCTAssertEqual(try query.signingInput(exporter: exporter, challenge: challenge), expected)
        XCTAssertNotEqual(try query.signingInput(exporter: challenge, challenge: exporter), expected)
        XCTAssertThrowsError(try query.signingInput(exporter: exporter.dropLast(), challenge: challenge))
        XCTAssertThrowsError(try query.signingInput(exporter: exporter, challenge: challenge.dropLast()))
    }

    private func makeQuery() throws -> PairingRecoveryQuery {
        let scope = try ChannelScope(macID: Data(repeating: 3, count: 16), accountID: Data(repeating: 4, count: 16),
            phoneID: Data(repeating: 5, count: 16), enrollmentEpoch: Data(repeating: 6, count: 16))
        return try PairingRecoveryQuery(setupID: Data(repeating: 1, count: 16),
            transcriptDigest: Data(repeating: 2, count: 32), scope: scope)
    }
}
