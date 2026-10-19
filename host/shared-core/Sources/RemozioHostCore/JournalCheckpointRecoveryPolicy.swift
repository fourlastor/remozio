import Foundation

/// Selects a storage reconciliation action from caller-supplied observations only.
/// No selection proves provenance, completes a storage mutation, grants admission or permits action replay.
public enum JournalCheckpointRecoveryPolicy {
    public enum Selection: Equatable, Sendable {
        case unchanged(ContinuityCheckpoint)
        case finalizePending(ContinuityCheckpoint)
        case discardPending(ContinuityCheckpoint)
        case historyDiscontinuity(ContinuityState)
        case requireRepair
    }

    /// The host must obtain the state and observations under its exclusive storage serialization boundary.
    /// A match means authority digest, ledger digest, epoch existence and head all match in one journal transaction.
    /// Evaluate pending first; when it matches, committed may remain false without being read.
    /// Storage errors must propagate before selection. Apply the selected mutation within the same boundary,
    /// then complete the host's independent admission and outcome-recovery gates.
    public static func select(state: ContinuityState, currentAuthorityDigest: Data,
                              pendingMatches: Bool, committedMatches: Bool) -> Selection {
        guard !state.recoveryRequired else { return .requireRepair }
        // Prefer the candidate when both describe identical bytes, as with a no-op transaction.
        if let pending = state.pending, pendingMatches { return .finalizePending(pending) }
        if committedMatches {
            return state.pending == nil ? .unchanged(state.committed) : .discardPending(state.committed)
        }
        if state.committed.authorityDigest == currentAuthorityDigest || state.pending?.authorityDigest == currentAuthorityDigest {
            // Preserve all evidence. A separate recovery step must record the gap and unresolved outcomes.
            return .historyDiscontinuity(state)
        }
        return .requireRepair
    }
}
