import Foundation
import RemozioHostCore
import RemozioProtocol
import XCTest

final class ContinuityCheckpointTests: XCTestCase {
    private let authority = Data(repeating: 0x11, count: 32)
    private let ledger = Data(repeating: 0x22, count: 32)
    private let epoch = Data(repeating: 0x33, count: 16)
    private let changedAuthority = Data(repeating: 0x44, count: 32)
    private let legacyHex = "a600010105025820111111111111111111111111111111111111111111111111111111111111111103582022222222222222222222222222222222222222222222222222222222222222220450333333333333333333333333333333330507"
    private let currentHex = "a7000201050258201111111111111111111111111111111111111111111111111111111111111111035820222222222222222222222222222222222222222222222222222222222222222204503333333333333333333333333333333305070603"

    private func bytes(_ hex: String) -> Data {
        let characters = Array(hex)
        return Data(stride(from: 0, to: characters.count, by: 2).map {
            UInt8(String(characters[$0...($0 + 1)]), radix: 16)!
        })
    }

    private func checkpoint(generation: UInt64 = 5, authorityGeneration: UInt64? = nil) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: generation, authorityDigest: authority, ledgerDigest: ledger,
            journalEpoch: epoch, journalHead: 7, authorityGeneration: authorityGeneration)
    }

    private func expectInvalid(_ operation: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try operation(), file: file, line: line) {
            XCTAssertEqual($0 as? ContinuityStoreError, .invalidCheckpoint, file: file, line: line)
        }
    }

    func testFrozenLegacyAndCurrentEncodings() throws {
        // Fixed bytes independently specify the persisted format; a matching encoder/decoder change must not pass.
        for (value, encoded) in [(try checkpoint(), bytes(legacyHex)), (try checkpoint(authorityGeneration: 3), bytes(currentHex))] {
            XCTAssertEqual(try value.bytes, encoded)
            XCTAssertEqual(try ContinuityCheckpoint.decode(encoded), value)
        }
        XCTAssertEqual(bytes(legacyHex).count, 95)
        XCTAssertEqual(bytes(currentHex).count, 97)
        XCTAssertEqual(try checkpoint().currentAuthorityGeneration, 5)
        XCTAssertEqual(try checkpoint(authorityGeneration: 3).currentAuthorityGeneration, 3)
    }

    func testFrozenHistoryIntentFramesTheCheckpointAsBytesAndAbsentPendingAsNull() throws {
        let previous = try ContinuityState(committed: checkpoint(), pending: nil, recoveryRequired: false)
        let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: Data(repeating: 0x44, count: 16))
        let encoded = bytes("a6000101585f" + legacyHex + "02f6035820" + String(repeating: "11", count: 32)
            + "045820" + String(repeating: "22", count: 32) + "0550" + String(repeating: "44", count: 16))
        XCTAssertEqual(encoded.count, 191)
        XCTAssertEqual(try intent.bytes, encoded)
        XCTAssertEqual(try HistoryRecoveryIntent.decode(encoded), intent)
    }

    func testDecoderRequiresExactVersionedFieldsAndValidValues() throws {
        let limits = try CBORLimits(maxBytes: 512, maxDepth: 4, maxItems: 64)
        for encoded in [bytes(legacyHex), bytes(currentHex)] {
            guard case .map(let original) = try DeterministicCBOR.decode(encoded, limits: limits) else {
                return XCTFail("Expected map")
            }
            for key in original.keys {
                var fields = original
                fields.removeValue(forKey: key)
                expectInvalid { _ = try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(fields), limits: limits)) }
            }
            let mutations: [(UInt64, CBORValue)] = [
                (0, .unsigned(0)), (0, .unsigned(3)), (0, .text("1")), (1, .unsigned(0)), (1, .null),
                (2, .bytes(Data(repeating: 0, count: 31))), (3, .bytes(Data(repeating: 0, count: 33))),
                (4, .bytes(Data(repeating: 0, count: 15))), (5, .text("7")),
            ]
            for (key, replacement) in mutations {
                var fields = original
                fields[key] = replacement
                expectInvalid { _ = try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(fields), limits: limits)) }
            }
            var wrongVersion = original
            wrongVersion[0] = original[0] == .unsigned(1) ? .unsigned(2) : .unsigned(1)
            expectInvalid { _ = try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(wrongVersion), limits: limits)) }
            var unknownField = original
            unknownField.removeValue(forKey: 6)
            unknownField[7] = .null
            expectInvalid { _ = try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(unknownField), limits: limits)) }
            for replacement: CBORValue in [.unsigned(0), .null, .text("3")] {
                var fields = original
                fields[6] = replacement
                expectInvalid { _ = try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(fields), limits: limits)) }
            }
        }
    }

    func testDecoderRejectsTruncatedTrailingNoncanonicalAndOversizedEvidence() throws {
        let encoded = bytes(legacyHex)
        let nonminimalGeneration = Data([0xa6, 0x00, 0x01, 0x01, 0x18, 0x05]) + encoded.dropFirst(5)
        for invalid in [Data(encoded.dropLast()), encoded + Data([0]), nonminimalGeneration, Data(repeating: 0, count: 257)] {
            XCTAssertThrowsError(try ContinuityCheckpoint.decode(invalid))
        }
    }

    func testSuccessorSeparatesAuthorityChangesFromHistoryChanges() throws {
        for authorityGeneration: UInt64? in [nil, 3] {
            let original = try checkpoint(authorityGeneration: authorityGeneration)
            let sameAuthority = try original.successor(authorityDigest: authority,
                ledgerDigest: Data(repeating: 0x55, count: 32), journalEpoch: Data(repeating: 0x66, count: 16), journalHead: 0)
            XCTAssertEqual(sameAuthority.generation, 6)
            XCTAssertEqual(sameAuthority.authorityGeneration, authorityGeneration ?? 5)
            XCTAssertEqual(sameAuthority.ledgerDigest, Data(repeating: 0x55, count: 32))
            XCTAssertEqual(sameAuthority.journalEpoch, Data(repeating: 0x66, count: 16))
            XCTAssertEqual(sameAuthority.journalHead, 0)
            let changed = try original.successor(authorityDigest: changedAuthority,
                ledgerDigest: ledger, journalEpoch: epoch, journalHead: 7)
            XCTAssertEqual(changed.generation, 6)
            XCTAssertEqual(changed.authorityGeneration, (authorityGeneration ?? 5) + 1)
            XCTAssertEqual(changed.authorityDigest, changedAuthority)
            XCTAssertEqual(original.generation, 5)
        }
    }

    func testUInt64BoundsAndExhaustionDoNotWrap() throws {
        let exhausted = try ContinuityCheckpoint(generation: .max, authorityDigest: authority, ledgerDigest: ledger,
            journalEpoch: epoch, journalHead: .max, authorityGeneration: .max)
        XCTAssertEqual(try ContinuityCheckpoint.decode(exhausted.bytes), exhausted)
        expectInvalid { _ = try exhausted.successor(authorityDigest: self.authority, ledgerDigest: self.ledger,
            journalEpoch: self.epoch, journalHead: 0) }
        expectInvalid { _ = try ContinuityState(committed: exhausted, pending: exhausted, recoveryRequired: false) }
        let lastAuthority = try checkpoint(authorityGeneration: .max)
        let auditOnly = try lastAuthority.successor(authorityDigest: authority, ledgerDigest: ledger, journalEpoch: epoch, journalHead: .max)
        XCTAssertEqual(auditOnly.generation, 6)
        XCTAssertEqual(auditOnly.authorityGeneration, .max)
        XCTAssertEqual(auditOnly.journalHead, .max)
        expectInvalid { _ = try lastAuthority.successor(authorityDigest: self.changedAuthority, ledgerDigest: self.ledger,
            journalEpoch: self.epoch, journalHead: 7) }
        let lastLegacy = try checkpoint(generation: .max)
        expectInvalid { _ = try lastLegacy.successor(authorityDigest: self.authority, ledgerDigest: self.ledger,
            journalEpoch: self.epoch, journalHead: 7) }
        for authorityGeneration: UInt64? in [nil, UInt64.max - 1] {
            let penultimate = try checkpoint(generation: UInt64.max - 1, authorityGeneration: authorityGeneration)
            for digest in [authority, changedAuthority] {
                let last = try penultimate.successor(authorityDigest: digest, ledgerDigest: ledger, journalEpoch: epoch, journalHead: 7)
                XCTAssertEqual(last.generation, .max)
                XCTAssertEqual(last.authorityGeneration, digest == authority ? UInt64.max - 1 : .max)
            }
        }
    }

    func testPendingStateRejectsSkippedGenerationsFalseAdvancesAndDowngrades() throws {
        let original = try checkpoint(authorityGeneration: 3)
        for (digest, generation): (Data, UInt64?) in [(authority, 4), (changedAuthority, 3), (changedAuthority, 5), (authority, nil)] {
            let invalid = try ContinuityCheckpoint(generation: 6, authorityDigest: digest, ledgerDigest: ledger,
                journalEpoch: epoch, journalHead: 7, authorityGeneration: generation)
            expectInvalid { _ = try ContinuityState(committed: original, pending: invalid, recoveryRequired: false) }
        }
        for generation: UInt64 in [5, 7] {
            let invalid = try checkpoint(generation: generation, authorityGeneration: 3)
            expectInvalid { _ = try ContinuityState(committed: original, pending: invalid, recoveryRequired: false) }
        }
        for digest in [authority, changedAuthority] {
            let candidate = try original.successor(authorityDigest: digest, ledgerDigest: ledger, journalEpoch: epoch, journalHead: 8)
            let state = try ContinuityState(committed: original, pending: candidate, recoveryRequired: false)
            XCTAssertEqual(state.committed, original)
            XCTAssertEqual(state.pending, candidate)
        }
        let legacy = try checkpoint(), legacyPending = try checkpoint(generation: 6)
        XCTAssertEqual(try ContinuityState(committed: legacy, pending: legacyPending, recoveryRequired: false).pending, legacyPending)
        let upgrade = try legacy.successor(authorityDigest: authority, ledgerDigest: ledger, journalEpoch: epoch, journalHead: 7)
        XCTAssertEqual(try ContinuityState(committed: legacy, pending: upgrade, recoveryRequired: true).pending, upgrade)
    }

    func testConstructorRejectsZeroGenerationsAndWrongDigestOrEpochLengths() throws {
        expectInvalid { _ = try self.checkpoint(generation: 0) }
        expectInvalid { _ = try self.checkpoint(authorityGeneration: 0) }
        for count in [0, 31, 33] {
            expectInvalid { _ = try ContinuityCheckpoint(generation: 1, authorityDigest: Data(repeating: 0, count: count),
                ledgerDigest: self.ledger, journalEpoch: self.epoch, journalHead: 0) }
            expectInvalid { _ = try ContinuityCheckpoint(generation: 1, authorityDigest: self.authority,
                ledgerDigest: Data(repeating: 0, count: count), journalEpoch: self.epoch, journalHead: 0) }
        }
        for count in [0, 15, 17] {
            expectInvalid { _ = try ContinuityCheckpoint(generation: 1, authorityDigest: self.authority,
                ledgerDigest: self.ledger, journalEpoch: Data(repeating: 0, count: count), journalHead: 0) }
        }
    }
}
