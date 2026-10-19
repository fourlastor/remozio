import Foundation
import RemozioHostCore

/// Storage reconciliation only. Every result still requires the host's admission and outcome-recovery gates.
enum JournalCheckpointRecovery {
    enum Result: Equatable {
        case unchanged(ContinuityCheckpoint)
        case finalized(ContinuityCheckpoint)
        case discarded(ContinuityCheckpoint)
        case historyDiscontinuity(ContinuityState)
        case repairRequired
    }

    /// Confine both exclusively owned stores to the same serialization boundary throughout this call.
    /// No callback, retained request, permit, or execution result is reconstructed by recovery.
    static func reconcile(journal: JournalDatabase, continuity: ContinuityStore) throws -> Result {
        let state = try continuity.read()
        guard !state.recoveryRequired else { return .repairRequired }
        return try journal.read { transaction in
            let digests = try transaction.continuityDigests()
            func matches(_ checkpoint: ContinuityCheckpoint) throws -> Bool {
                guard checkpoint.authorityDigest == digests.authority, checkpoint.ledgerDigest == digests.ledger,
                      let epoch = try transaction.epoch(checkpoint.journalEpoch) else { return false }
                return epoch.head == checkpoint.journalHead
            }
            let pendingMatches = try state.pending.map(matches) ?? false
            // Preserve lazy reads: a matching candidate never inspects the committed epoch.
            let committedMatches = pendingMatches ? false : try matches(state.committed)
            switch JournalCheckpointRecoveryPolicy.select(state: state, currentAuthorityDigest: digests.authority,
                                                           pendingMatches: pendingMatches, committedMatches: committedMatches) {
            case .unchanged(let checkpoint):
                return .unchanged(checkpoint)
            case .finalizePending(let checkpoint):
                try continuity.finalize(expected: state)
                return .finalized(checkpoint)
            case .discardPending(let checkpoint):
                try continuity.discardPreparation(expected: state)
                return .discarded(checkpoint)
            case .historyDiscontinuity(let previous):
                return .historyDiscontinuity(previous)
            case .requireRepair:
                // Storage errors propagate instead of being converted into a persistent repair condition.
                try continuity.requireRecovery()
                return .repairRequired
            }
        }
    }
}
