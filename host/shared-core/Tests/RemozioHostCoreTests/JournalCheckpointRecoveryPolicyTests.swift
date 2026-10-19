import Foundation
import RemozioHostCore
import XCTest

final class JournalCheckpointRecoveryPolicyTests: XCTestCase {
    private let authority = Data(repeating: 1, count: 32)
    private let pendingAuthority = Data(repeating: 2, count: 32)
    private let unknownAuthority = Data(repeating: 3, count: 32)

    private func state(pending: Bool = true, recoveryRequired: Bool = false, unchangedAuthority: Bool = false) throws -> ContinuityState {
        let committed = try ContinuityCheckpoint(generation: 5, authorityDigest: authority,
            ledgerDigest: Data(repeating: 4, count: 32), journalEpoch: Data(repeating: 5, count: 16),
            journalHead: 7, authorityGeneration: 3)
        let candidate = try committed.successor(authorityDigest: unchangedAuthority ? authority : pendingAuthority,
            ledgerDigest: committed.ledgerDigest, journalEpoch: committed.journalEpoch, journalHead: committed.journalHead)
        return try ContinuityState(committed: committed, pending: pending ? candidate : nil, recoveryRequired: recoveryRequired)
    }

    func testPendingMatchWinsIncludingIdenticalBoundaries() throws {
        for unchangedAuthority in [false, true] {
            let state = try state(unchangedAuthority: unchangedAuthority), pending = try XCTUnwrap(state.pending)
            for committedMatches in [false, true] {
                XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: pending.authorityDigest,
                    pendingMatches: true, committedMatches: committedMatches), .finalizePending(pending))
            }
        }
    }

    func testCommittedMatchSelectsDiscardOnlyWhenPreparationExists() throws {
        for hasPending in [false, true] {
            let state = try state(pending: hasPending)
            XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: authority,
                pendingMatches: false, committedMatches: true), hasPending ? .discardPending(state.committed) : .unchanged(state.committed))
        }
    }

    func testHistoryDiscontinuityPreservesBothBoundariesWithoutSelectingAMutation() throws {
        let state = try state()
        for digest in [authority, pendingAuthority] {
            XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: digest,
                pendingMatches: false, committedMatches: false), .historyDiscontinuity(state))
        }
        let committedOnly = try self.state(pending: false)
        XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: committedOnly, currentAuthorityDigest: authority,
            pendingMatches: false, committedMatches: false), .historyDiscontinuity(committedOnly))
        XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: unknownAuthority,
            pendingMatches: false, committedMatches: false), .requireRepair)
        XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: committedOnly, currentAuthorityDigest: pendingAuthority,
            pendingMatches: false, committedMatches: false), .requireRepair)
    }

    func testStickyRepairIgnoresMatchObservations() throws {
        for hasPending in [false, true] {
            let state = try state(pending: hasPending, recoveryRequired: true)
            for pendingMatches in [false, true] {
                for committedMatches in [false, true] {
                    XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: authority,
                        pendingMatches: pendingMatches, committedMatches: committedMatches), .requireRepair)
                }
            }
        }
    }

    func testStrayPendingObservationCannotInventAPreparation() throws {
        let state = try state(pending: false)
        XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: authority,
            pendingMatches: true, committedMatches: true), .unchanged(state.committed))
        XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: authority,
            pendingMatches: true, committedMatches: false), .historyDiscontinuity(state))
        XCTAssertEqual(JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: unknownAuthority,
            pendingMatches: true, committedMatches: false), .requireRepair)
    }
}
