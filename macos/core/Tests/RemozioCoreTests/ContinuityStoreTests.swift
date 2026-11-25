import Darwin
import Foundation
import SQLite3
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class ContinuityStoreTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private func checkpoint(_ generation: UInt64) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: generation, authorityDigest: Data(repeating: 3, count: 32),
            ledgerDigest: Data(repeating: UInt8(generation), count: 32), journalEpoch: Data(repeating: 4, count: 16),
            journalHead: generation, authorityGeneration: 1)
    }
    private func open(_ fixture: Fixture, initial: ContinuityCheckpoint? = nil, readOnly: Bool = false) throws -> ContinuityStore {
        try ContinuityStore(lease: fixture.acquire(), macID: mac, accountID: account, initialize: initial, readOnlyForCutover: readOnly)
    }

    func testOpenRejectsUnsupportedSchemaObjectsWithoutChangingTheStore() throws {
        let unsupportedObjects = [
            "CREATE TRIGGER fixture_trigger BEFORE UPDATE ON continuity_v1 BEGIN SELECT 1; END",
            "CREATE VIEW fixture_view AS SELECT 1 AS value",
            "CREATE VIRTUAL TABLE fixture_search USING fts5(value)",
        ]
        for sql in unsupportedObjects {
            let fixture = try Fixture()
            try open(fixture, initial: checkpoint(1)).close()
            try fixture.sql(sql)
            let file = URL(fileURLWithPath: fixture.path("continuity/continuity.sqlite"))
            let before = try Data(contentsOf: file)
            for readOnly in [false, true] {
                XCTAssertThrowsError(try open(fixture, readOnly: readOnly), sql) {
                    XCTAssertEqual($0 as? ContinuityStoreError, .incompatibleStore, sql)
                }
                XCTAssertEqual(try Data(contentsOf: file), before, sql)
                let lease = try fixture.acquire()
                lease.close()
            }
        }
    }

    func testOpenAllowsAdditionalOrdinaryTablesAndIndexes() throws {
        let fixture = try Fixture()
        let initial = try checkpoint(1)
        try open(fixture, initial: initial).close()
        try fixture.sql("CREATE TABLE fixture_auxiliary(value INTEGER)")
        try fixture.sql("CREATE INDEX fixture_auxiliary_value ON fixture_auxiliary(value)")
        let reopened = try open(fixture)
        defer { reopened.close() }
        XCTAssertEqual(try reopened.read().committed, initial)
    }

    func testPreparationAndFinalizationSurviveReopen() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        XCTAssertEqual(try store.read().committed, first)
        try store.prepare(expected: first, candidate: second)
        let prepared = try store.read()
        XCTAssertEqual(prepared.pending, second)
        store.close()
        store = try open(fixture)
        XCTAssertEqual(try store.read(), prepared)
        try store.finalize(expected: prepared)
        XCTAssertThrowsError(try store.finalize(expected: prepared))
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertEqual(try store.read().committed, second)
        XCTAssertNil(try store.read().pending)
    }

    func testDiscardAndStickyRecoveryMarker() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        try store.prepare(expected: first, candidate: second)
        try store.discardPreparation(expected: store.read())
        XCTAssertEqual(try store.read().committed, first)
        XCTAssertNil(try store.read().pending)
        try store.prepare(expected: first, candidate: second)
        let prepared = try store.read()
        try store.requireRecovery(); try store.requireRecovery()
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertTrue(try store.read().recoveryRequired)
        XCTAssertThrowsError(try store.finalize(expected: prepared))
        XCTAssertThrowsError(try store.discardPreparation(expected: prepared))
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: second))
        XCTAssertEqual(try store.read().pending, second)
    }

    func testRejectsMissingInitializationWrongScopeAndStaleTransitions() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        XCTAssertThrowsError(try open(fixture))
        let store = try open(fixture, initial: first)
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: checkpoint(3)))
        XCTAssertEqual(try store.read().committed, first)
        try store.prepare(expected: first, candidate: second)
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: second))
        store.close()
        XCTAssertThrowsError(try store.read()) { XCTAssertEqual($0 as? ContinuityStoreError, .closed) }
        XCTAssertThrowsError(try open(fixture, initial: first))
        XCTAssertThrowsError(try ContinuityStore(lease: fixture.acquire(), macID: Data(repeating: 9, count: 16),
            accountID: account, initialize: nil)) { XCTAssertEqual($0 as? ContinuityStoreError, .wrongScope) }
        let reopened = try open(fixture)
        defer { reopened.close() }
        XCTAssertEqual(try reopened.read().pending, second)
    }

    func testFailedWritesPreserveBothBoundariesAndDoNotSetRecovery() throws {
        for operation in ["prepare", "finalize", "discard", "marker"] {
            let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
            var store = try open(fixture, initial: first)
            if operation != "prepare" { try store.prepare(expected: first, candidate: second) }
            let before = try store.read()
            try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            func mutate(_ store: ContinuityStore) throws {
                switch operation {
                case "prepare": try store.prepare(expected: first, candidate: second)
                case "finalize": try store.finalize(expected: before)
                case "discard": try store.discardPreparation(expected: before)
                default: try store.requireRecovery()
                }
            }
            XCTAssertThrowsError(try mutate(store)) { XCTAssertEqual($0 as? ContinuityStoreError, .storage(SQLITE_CONSTRAINT)) }
            XCTAssertEqual(try store.read(), before)
            store.close()
            try fixture.sql("DROP TRIGGER fail_update")
            store = try open(fixture)
            XCTAssertEqual(try store.read(), before)
            try mutate(store)
            XCTAssertNotEqual(try store.read(), before)
            store.close()
        }
    }

    func testCorruptAndUnsupportedStateCannotBeOpenedOrReinitialized() throws {
        for corruption in ["UPDATE continuity_v1 SET committed=x'00'", "UPDATE continuity_v1 SET pending=zeroblob(257)",
                           "DELETE FROM continuity_v1", "PRAGMA user_version=2"] {
            let fixture = try Fixture(), first = try checkpoint(1)
            let store = try open(fixture, initial: first)
            store.close()
            try fixture.sql(corruption)
            XCTAssertThrowsError(try open(fixture))
            XCTAssertThrowsError(try open(fixture, initial: first))
        }
    }

    func testCheckpointBoundsAndExhaustedGeneration() throws {
        let authority = Data(repeating: 1, count: 32), epoch = Data(repeating: 2, count: 16)
        let last = try ContinuityCheckpoint(generation: .max, authorityDigest: authority, ledgerDigest: authority,
                                            journalEpoch: epoch, journalHead: .max)
        XCTAssertEqual(try ContinuityCheckpoint.decode(last.bytes), last)
        XCTAssertThrowsError(try ContinuityState(committed: last, pending: last, recoveryRequired: false))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 0, authorityDigest: authority, ledgerDigest: authority,
                                                       journalEpoch: epoch, journalHead: 0))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 1, authorityDigest: Data(), ledgerDigest: authority,
                                                       journalEpoch: epoch, journalHead: 0))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 1, authorityDigest: authority, ledgerDigest: Data(),
                                                       journalEpoch: epoch, journalHead: 0))
        XCTAssertThrowsError(try ContinuityCheckpoint(generation: 1, authorityDigest: authority, ledgerDigest: authority,
                                                       journalEpoch: Data(), journalHead: 0))
    }

    func testVersionedCheckpointsRoundTripAndRejectMalformedGenerationFields() throws {
        let legacy = try ContinuityCheckpoint(generation: 5, authorityDigest: mac + mac,
            ledgerDigest: account + account, journalEpoch: mac, journalHead: 0)
        let legacyBytes = try legacy.bytes
        XCTAssertEqual(try ContinuityCheckpoint.decode(legacyBytes).bytes, legacyBytes)
        XCTAssertNil(try ContinuityCheckpoint.decode(legacyBytes).authorityGeneration)
        let current = try legacy.successor(authorityDigest: legacy.authorityDigest, ledgerDigest: legacy.ledgerDigest,
            journalEpoch: legacy.journalEpoch, journalHead: legacy.journalHead)
        XCTAssertEqual(current.authorityGeneration, 5)
        XCTAssertEqual(try ContinuityCheckpoint.decode(current.bytes), current)
        let limits = try CBORLimits(maxBytes: 256, maxDepth: 2, maxItems: 64)
        guard case .map(let fields) = try DeterministicCBOR.decode(current.bytes, limits: limits) else { return XCTFail("not a map") }
        for replacement: CBORValue? in [nil, .null, .unsigned(0), .text("5")] {
            var invalid = fields; invalid[6] = replacement
            XCTAssertThrowsError(try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(invalid), limits: limits)))
        }
        for version: UInt64 in [0, 1, 3] {
            var invalid = fields; invalid[0] = .unsigned(version)
            XCTAssertThrowsError(try ContinuityCheckpoint.decode(DeterministicCBOR.encode(.map(invalid), limits: limits)))
        }
    }

    func testGenerationTransitionRulesRejectFalseAdvancesAndDowngrades() throws {
        let fixture = try Fixture(), first = try checkpoint(1), store = try open(fixture, initial: first)
        defer { store.close() }
        for (digest, generation): (Data, UInt64?) in [
            (first.authorityDigest, 2), (Data(repeating: 9, count: 32), 1),
            (Data(repeating: 9, count: 32), 3), (first.authorityDigest, nil)
        ] {
            let invalid = try ContinuityCheckpoint(generation: 2, authorityDigest: digest,
                ledgerDigest: first.ledgerDigest, journalEpoch: first.journalEpoch, journalHead: 0,
                authorityGeneration: generation)
            XCTAssertThrowsError(try store.prepare(expected: first, candidate: invalid)) {
                XCTAssertEqual($0 as? ContinuityStoreError, .invalidCheckpoint)
            }
            XCTAssertNil(try store.read().pending)
        }
        let valid = try first.successor(authorityDigest: Data(repeating: 9, count: 32),
            ledgerDigest: first.ledgerDigest, journalEpoch: first.journalEpoch, journalHead: 0)
        XCTAssertEqual(valid.authorityGeneration, 2)
        try store.prepare(expected: first, candidate: valid)
        XCTAssertEqual(try store.read().pending, valid)
    }

    private func recovery(_ state: ContinuityState) throws -> HistoryRecoveryIntent {
        try HistoryRecoveryIntent(previous: state, authorityDigest: state.committed.authorityDigest,
            ledgerDigest: Data(repeating: 9, count: 32), recoveryEpoch: Data(repeating: 8, count: 16))
    }

    private func recoveredCheckpoint(_ intent: HistoryRecoveryIntent) throws -> ContinuityCheckpoint {
        try ContinuityCheckpoint(generation: intent.checkpointGeneration, authorityDigest: intent.authorityDigest,
            ledgerDigest: Data(repeating: 7, count: 32), journalEpoch: intent.recoveryEpoch, journalHead: 1,
            authorityGeneration: intent.authorityGeneration)
    }

    func testHistoryRecoverySurvivesReopenAndBlocksOrdinaryTransitions() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        XCTAssertNil(try store.historyRecovery())
        try store.prepare(expected: first, candidate: second)
        let previous = try store.read(), intent = try recovery(previous)
        try store.prepareHistoryRecovery(intent)
        store.close()
        store = try open(fixture)
        XCTAssertEqual(try store.historyRecovery(), intent)
        XCTAssertThrowsError(try store.read()) {
            XCTAssertEqual($0 as? ContinuityStoreError, .historyRecoveryPending)
            XCTAssertEqual(AuthorityStartupFailure(error: $0), .historyRecoveryRequired)
        }
        XCTAssertThrowsError(try store.prepare(expected: first, candidate: second))
        XCTAssertThrowsError(try store.finalize(expected: previous))
        XCTAssertThrowsError(try store.discardPreparation(expected: previous))
        XCTAssertThrowsError(try store.prepareHistoryRecovery(intent))
        XCTAssertEqual(try store.historyRecovery(), intent)
        let candidate = try recoveredCheckpoint(intent)
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate))
        try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
        store.close()
        store = try open(fixture)
        XCTAssertEqual(try store.historyRecoveryCandidate(), candidate)
        try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertNil(try store.historyRecovery())
        XCTAssertNil(try store.historyRecoveryCandidate())
        XCTAssertEqual(try store.read().committed, candidate)
        XCTAssertNil(try store.read().pending)
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate))
        let next = try candidate.successor(authorityDigest: candidate.authorityDigest, ledgerDigest: candidate.ledgerDigest,
            journalEpoch: candidate.journalEpoch, journalHead: 2)
        try store.prepare(expected: candidate, candidate: next)
        try store.finalize(expected: store.read())
        XCTAssertEqual(try store.read().committed, next)
    }

    func testFailedHistoryPreparationRollsBackMigrationAndEvidence() throws {
        let fixture = try Fixture(), first = try checkpoint(1)
        var store = try open(fixture, initial: first)
        let previous = try store.read(), intent = try recovery(previous)
        try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try store.prepareHistoryRecovery(intent))
        XCTAssertEqual(try store.read(), previous)
        XCTAssertNil(try store.historyRecovery())
        store.close()
        try fixture.sql("DROP TRIGGER fail_update")
        store = try open(fixture)
        defer { store.close() }
        XCTAssertEqual(try store.read(), previous)
        try store.prepareHistoryRecovery(intent)
        XCTAssertEqual(try store.historyRecovery(), intent)
    }

    func testFailedHistoryFinalizationRetainsEvidenceAcrossReopen() throws {
        let fixture = try Fixture(), first = try checkpoint(1)
        var store = try open(fixture, initial: first)
        let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent)
        try store.prepareHistoryRecovery(intent)
        try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
        try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate))
        XCTAssertEqual(try store.historyRecovery(), intent)
        store.close()
        try fixture.sql("DROP TRIGGER fail_update")
        store = try open(fixture)
        defer { store.close() }
        XCTAssertEqual(try store.historyRecovery(), intent)
        XCTAssertThrowsError(try store.read())
        try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)
        XCTAssertEqual(try store.read().committed, candidate)
    }

    func testHistoryRecoveryRejectsStaleAndWrongCandidatesAndPreservesRepairMarker() throws {
        let fixture = try Fixture(), first = try checkpoint(1), second = try checkpoint(2)
        var store = try open(fixture, initial: first)
        let stale = try recovery(store.read())
        try store.prepare(expected: first, candidate: second)
        XCTAssertThrowsError(try store.prepareHistoryRecovery(stale))
        let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent)
        try store.prepareHistoryRecovery(intent)
        XCTAssertThrowsError(try store.prepareHistoryRecoveryCandidate(expected: stale, candidate: candidate))
        XCTAssertThrowsError(try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: second))
        for field in 0..<4 {
            let invalid = try ContinuityCheckpoint(generation: candidate.generation + (field == 0 ? 1 : 0),
                authorityDigest: field == 1 ? Data(repeating: 6, count: 32) : candidate.authorityDigest,
                ledgerDigest: candidate.ledgerDigest,
                journalEpoch: field == 2 ? Data(repeating: 6, count: 16) : candidate.journalEpoch,
                journalHead: candidate.journalHead,
                authorityGeneration: field == 3 ? candidate.authorityGeneration! + 1 : candidate.authorityGeneration)
            XCTAssertThrowsError(try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: invalid))
        }
        XCTAssertNil(try store.historyRecoveryCandidate())
        try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: stale, candidate: candidate))
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: second))
        XCTAssertEqual(try store.historyRecovery(), intent)
        try store.requireRecovery()
        store.close()
        store = try open(fixture)
        defer { store.close() }
        XCTAssertThrowsError(try store.historyRecovery()) { XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired) }
        XCTAssertThrowsError(try store.historyRecoveryCandidate()) { XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired) }
        XCTAssertThrowsError(try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)) {
            XCTAssertEqual($0 as? ContinuityStoreError, .recoveryRequired)
        }
    }

    func testCorruptHistoryEvidenceFailsReopen() throws {
        for corruption in ["UPDATE continuity_v1 SET history=x'00'", "UPDATE continuity_v1 SET history=zeroblob(1025)",
                           "UPDATE continuity_v1 SET pending=NULL"] {
            let fixture = try Fixture(), first = try checkpoint(1), store = try open(fixture, initial: first)
            try store.prepare(expected: first, candidate: checkpoint(2))
            try store.prepareHistoryRecovery(recovery(store.read()))
            store.close()
            try fixture.sql(corruption)
            XCTAssertThrowsError(try open(fixture))
        }
    }

    func testCandidatePreparationIsAtomicAndCannotBeReplaced() throws {
        let fixture = try Fixture(), first = try checkpoint(1)
        var store = try open(fixture, initial: first)
        let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent)
        try store.prepareHistoryRecovery(intent)
        XCTAssertNil(try store.historyRecoveryCandidate())
        try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
        XCTAssertThrowsError(try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate))
        store.close()
        try fixture.sql("DROP TRIGGER fail_update")
        store = try open(fixture)
        XCTAssertEqual(try store.historyRecovery(), intent)
        XCTAssertNil(try store.historyRecoveryCandidate())
        try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
        store.close()
        store = try open(fixture)
        defer { store.close() }
        try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
        let different = try ContinuityCheckpoint(generation: candidate.generation,
            authorityDigest: candidate.authorityDigest, ledgerDigest: Data(repeating: 6, count: 32),
            journalEpoch: candidate.journalEpoch, journalHead: candidate.journalHead + 1,
            authorityGeneration: candidate.authorityGeneration)
        XCTAssertThrowsError(try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: different))
        XCTAssertThrowsError(try store.finalizeHistoryRecovery(expected: intent, candidate: different))
        XCTAssertEqual(try store.historyRecoveryCandidate(), candidate)
        XCTAssertThrowsError(try store.read())
        try store.finalizeHistoryRecovery(expected: intent, candidate: candidate)
        XCTAssertEqual(try store.read().committed, candidate)
        let nextIntent = try HistoryRecoveryIntent(previous: store.read(), authorityDigest: candidate.authorityDigest,
            ledgerDigest: candidate.ledgerDigest, recoveryEpoch: Data(repeating: 5, count: 16))
        try store.prepareHistoryRecovery(nextIntent)
        XCTAssertNil(try store.historyRecoveryCandidate())
    }

    func testMalformedOrOrphanedHistoryCandidateFailsReopen() throws {
        for corruption in ["UPDATE continuity_v1 SET history_candidate=x'00'",
                           "UPDATE continuity_v1 SET history_candidate=zeroblob(257)",
                           "UPDATE continuity_v1 SET history=NULL",
                           "UPDATE continuity_v1 SET history_candidate=committed"] {
            let fixture = try Fixture(), store = try open(fixture, initial: checkpoint(1))
            let intent = try recovery(store.read())
            try store.prepareHistoryRecovery(intent)
            try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: recoveredCheckpoint(intent))
            store.close()
            try fixture.sql(corruption)
            XCTAssertThrowsError(try open(fixture))
        }
    }

    private func replacement(_ intent: HistoryRecoveryIntent, epoch: UInt8 = 5) throws -> HistoryRecoveryIntent {
        try HistoryRecoveryIntent(previous: intent.previous, authorityDigest: intent.authorityDigest,
            ledgerDigest: Data(repeating: epoch, count: 32), recoveryEpoch: Data(repeating: epoch, count: 16))
    }

    func testSupersessionPreservesEvidenceAndCanFinishAcrossReopen() throws {
        for prepared in [false, true] {
            let fixture = try Fixture(), first = try checkpoint(1)
            var store = try open(fixture, initial: first)
            let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent)
            let next = try replacement(intent)
            try store.prepareHistoryRecovery(intent)
            if prepared { try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate) }
            try store.supersedeHistoryRecovery(expected: intent, expectedCandidate: prepared ? candidate : nil, replacement: next)
            store.close()
            store = try open(fixture)
            let archived = try XCTUnwrap(store.supersededHistoryRecovery(epoch: intent.recoveryEpoch))
            XCTAssertEqual(archived.intent, intent)
            XCTAssertEqual(archived.candidate, prepared ? candidate : nil)
            XCTAssertEqual(try store.historyRecovery(), next)
            XCTAssertNil(try store.historyRecoveryCandidate())
            XCTAssertThrowsError(try store.read())
            let third = try replacement(next, epoch: 6)
            try store.supersedeHistoryRecovery(expected: next, expectedCandidate: nil, replacement: third)
            XCTAssertEqual(try store.supersededHistoryRecovery(epoch: next.recoveryEpoch)?.intent, next)
            let final = try recoveredCheckpoint(third)
            try store.prepareHistoryRecoveryCandidate(expected: third, candidate: final)
            try store.finalizeHistoryRecovery(expected: third, candidate: final)
            store.close()
            store = try open(fixture)
            XCTAssertEqual(try store.read().committed, final)
            XCTAssertEqual(try store.supersededHistoryRecovery(epoch: intent.recoveryEpoch)?.candidate, prepared ? candidate : nil)
            XCTAssertEqual(try store.supersededHistoryRecovery(epoch: next.recoveryEpoch)?.intent, next)
            store.close()
        }
    }

    func testFailedSupersessionRollsBackArchiveMigrationAndReplacement() throws {
        for prepared in [false, true] {
            let fixture = try Fixture()
            var store = try open(fixture, initial: checkpoint(1))
            let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent), next = try replacement(intent)
            try store.prepareHistoryRecovery(intent)
            if prepared { try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate) }
            try fixture.sql("CREATE TRIGGER fail_update BEFORE UPDATE ON continuity_v1 BEGIN SELECT RAISE(ABORT,'injected'); END")
            XCTAssertThrowsError(try store.supersedeHistoryRecovery(expected: intent,
                expectedCandidate: prepared ? candidate : nil, replacement: next))
            store.close()
            try fixture.sql("DROP TRIGGER fail_update")
            store = try open(fixture)
            XCTAssertEqual(try store.historyRecovery(), intent)
            XCTAssertEqual(try store.historyRecoveryCandidate(), prepared ? candidate : nil)
            XCTAssertNil(try store.supersededHistoryRecovery(epoch: intent.recoveryEpoch))
            try store.supersedeHistoryRecovery(expected: intent, expectedCandidate: prepared ? candidate : nil, replacement: next)
            XCTAssertEqual(try store.historyRecovery(), next)
            store.close()
        }
    }

    func testSupersessionRejectsStaleCandidateAndReusedEpoch() throws {
        let fixture = try Fixture(), store = try open(fixture, initial: checkpoint(1))
        defer { store.close() }
        let intent = try recovery(store.read()), candidate = try recoveredCheckpoint(intent), next = try replacement(intent)
        try store.prepareHistoryRecovery(intent)
        try store.prepareHistoryRecoveryCandidate(expected: intent, candidate: candidate)
        XCTAssertThrowsError(try store.supersedeHistoryRecovery(expected: intent, expectedCandidate: nil, replacement: next))
        XCTAssertThrowsError(try store.supersedeHistoryRecovery(expected: intent, expectedCandidate: candidate, replacement: intent))
        try store.supersedeHistoryRecovery(expected: intent, expectedCandidate: candidate, replacement: next)
        XCTAssertThrowsError(try store.supersedeHistoryRecovery(expected: next, expectedCandidate: nil, replacement: intent))
        XCTAssertEqual(try store.historyRecovery(), next)
        XCTAssertEqual(try store.supersededHistoryRecovery(epoch: intent.recoveryEpoch)?.candidate, candidate)
        try store.requireRecovery()
        XCTAssertThrowsError(try store.supersedeHistoryRecovery(expected: next, expectedCandidate: nil,
            replacement: replacement(next, epoch: 6)))
        XCTAssertEqual(try store.supersededHistoryRecovery(epoch: intent.recoveryEpoch)?.intent, intent)
    }

    func testMissingOrMalformedArchiveFailsReopenAfterFinalization() throws {
        for corruption in ["DROP TABLE history_attempts_v1",
                           "ALTER TABLE history_attempts_v1 RENAME COLUMN candidate TO missing_candidate"] {
            let fixture = try Fixture(), store = try open(fixture, initial: checkpoint(1))
            let intent = try recovery(store.read()), next = try replacement(intent)
            try store.prepareHistoryRecovery(intent)
            try store.supersedeHistoryRecovery(expected: intent, expectedCandidate: nil, replacement: next)
            let candidate = try recoveredCheckpoint(next)
            try store.prepareHistoryRecoveryCandidate(expected: next, candidate: candidate)
            try store.finalizeHistoryRecovery(expected: next, candidate: candidate)
            store.close()
            try fixture.sql(corruption)
            XCTAssertThrowsError(try open(fixture))
        }
    }

    private final class Fixture {
        let root: URL
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else {
                throw JournalLeaseError.system(errno)
            }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["journal", "continuity"] {
                try FileManager.default.createDirectory(atPath: path(name), withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
                try Self.file(path(name + "/writer.lock"))
                try Self.file(path(name + "/" + name + ".sqlite"))
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func path(_ suffix: String) -> String { root.appendingPathComponent(suffix).path }
        func acquire() throws -> ProtectedContinuityLease {
            try ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: geteuid())
        }
        func sql(_ query: String) throws {
            var connection: OpaquePointer?
            let result = sqlite3_open(path("continuity/continuity.sqlite"), &connection)
            guard result == SQLITE_OK, let connection else { throw ContinuityStoreError.storage(result) }
            defer { sqlite3_close(connection) }
            let status = sqlite3_exec(connection, query, nil, nil, nil)
            guard status == SQLITE_OK else { throw ContinuityStoreError.storage(status) }
        }
        static func file(_ path: String) throws {
            let fd = Darwin.open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            Darwin.close(fd)
        }
    }
}
