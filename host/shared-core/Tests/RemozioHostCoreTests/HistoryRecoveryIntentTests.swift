import Foundation
import XCTest
import RemozioProtocol
import RemozioHostCore

final class HistoryRecoveryIntentTests: XCTestCase {
    private let authority = Data(repeating: 1, count: 32)
    private let changedAuthority = Data(repeating: 2, count: 32)
    private let ledger = Data(repeating: 3, count: 32)
    private let freshEpoch = Data(repeating: 4, count: 16)

    private func checkpoint(generation: UInt64 = 10, authorityGeneration: UInt64? = 5) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: generation, authorityDigest: authority, ledgerDigest: ledger,
            journalEpoch: Data(repeating: 6, count: 16), journalHead: 12, authorityGeneration: authorityGeneration)
    }

    func testRoundTripPreservesBothBoundariesAndSelectsMatchingAuthority() throws {
        let old = try checkpoint()
        let proposed = try old.successor(authorityDigest: changedAuthority, ledgerDigest: ledger,
            journalEpoch: old.journalEpoch, journalHead: 13)
        let previous = try ContinuityState(committed: old, pending: proposed, recoveryRequired: false)
        for (digest, generation) in [(authority, UInt64(5)), (changedAuthority, UInt64(6))] {
            let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: digest,
                ledgerDigest: Data(repeating: 7, count: 32), recoveryEpoch: freshEpoch)
            XCTAssertEqual(try HistoryRecoveryIntent.decode(intent.bytes), intent)
            XCTAssertEqual(intent.previous, previous)
            XCTAssertEqual(intent.authorityGeneration, generation)
            XCTAssertEqual(intent.checkpointGeneration, 12)
        }
    }

    func testLegacyBoundaryUsesProtectedGenerationWithoutPending() throws {
        let old = try checkpoint(authorityGeneration: nil)
        let intent = try HistoryRecoveryIntent(previous: ContinuityState(committed: old, pending: nil, recoveryRequired: false),
            authorityDigest: authority, ledgerDigest: ledger, recoveryEpoch: freshEpoch)
        XCTAssertEqual(intent.authorityGeneration, 10)
        XCTAssertEqual(intent.checkpointGeneration, 11)
        XCTAssertEqual(try HistoryRecoveryIntent.decode(intent.bytes), intent)
    }

    func testRejectsAuthorityMismatchRepairEpochReuseAndGenerationExhaustion() throws {
        let old = try checkpoint()
        for repair in [false, true] {
            let previous = try ContinuityState(committed: old, pending: nil, recoveryRequired: repair)
            XCTAssertThrowsError(try HistoryRecoveryIntent(previous: previous, authorityDigest: changedAuthority,
                ledgerDigest: ledger, recoveryEpoch: freshEpoch))
            if repair {
                XCTAssertThrowsError(try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
                    ledgerDigest: ledger, recoveryEpoch: freshEpoch))
            }
        }
        let previous = try ContinuityState(committed: old, pending: nil, recoveryRequired: false)
        XCTAssertThrowsError(try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: old.journalEpoch))
        let exhausted = try ContinuityState(committed: checkpoint(generation: UInt64.max), pending: nil, recoveryRequired: false)
        XCTAssertThrowsError(try HistoryRecoveryIntent(previous: exhausted, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: freshEpoch))
    }

    func testSameAuthorityPrefersPendingLegacyGenerationAndRejectsPendingEpochReuse() throws {
        let old = try checkpoint(authorityGeneration: nil)
        let pending = try ContinuityCheckpoint(generation: 11, authorityDigest: authority, ledgerDigest: ledger,
            journalEpoch: Data(repeating: 8, count: 16), journalHead: 0)
        let previous = try ContinuityState(committed: old, pending: pending, recoveryRequired: false)
        let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: freshEpoch)
        XCTAssertEqual(intent.authorityGeneration, 11)
        XCTAssertEqual(intent.checkpointGeneration, 12)
        XCTAssertThrowsError(try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: pending.journalEpoch))
        let last = try checkpoint(generation: UInt64.max - 1)
        let lastPending = try last.successor(authorityDigest: authority, ledgerDigest: ledger,
            journalEpoch: last.journalEpoch, journalHead: 13)
        XCTAssertThrowsError(try HistoryRecoveryIntent(previous:
            ContinuityState(committed: last, pending: lastPending, recoveryRequired: false),
            authorityDigest: authority, ledgerDigest: ledger, recoveryEpoch: freshEpoch))
    }

    func testDecoderRejectsUnknownFieldsVersionsAndMalformedEvidence() throws {
        let previous = try ContinuityState(committed: checkpoint(), pending: nil, recoveryRequired: false)
        let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: freshEpoch)
        let limits = try CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 32)
        guard case .map(let original) = try DeterministicCBOR.decode(intent.bytes, limits: limits) else {
            return XCTFail("Expected map")
        }
        let mutations: [(UInt64, CBORValue)] = [(0, .unsigned(2)), (2, .unsigned(0)),
            (2, .bytes(Data([0]))), (3, .bytes(changedAuthority)), (4, .bytes(Data())),
            (5, .bytes(Data(repeating: 0, count: 15))), (6, .null)]
        for (key, value) in mutations {
            var fields = original
            fields[key] = value
            XCTAssertThrowsError(try HistoryRecoveryIntent.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        for key in original.keys {
            var fields = original
            fields.removeValue(forKey: key)
            XCTAssertThrowsError(try HistoryRecoveryIntent.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
    }

    func testRejectsTruncatedAndTrailingEncodedEvidence() throws {
        let previous = try ContinuityState(committed: checkpoint(), pending: nil, recoveryRequired: false)
        let intent = try HistoryRecoveryIntent(previous: previous, authorityDigest: authority,
            ledgerDigest: ledger, recoveryEpoch: freshEpoch)
        let encoded = try intent.bytes
        XCTAssertThrowsError(try HistoryRecoveryIntent.decode(encoded.dropLast()))
        XCTAssertThrowsError(try HistoryRecoveryIntent.decode(encoded + Data([0])))
    }
}
