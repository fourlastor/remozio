import Foundation

/// Actual preparation facts before or after intent retention. The proposal grants no policy permit, writer or admission authority.
struct MachineUpdateCompletionPreparationSnapshot {
    let restart: MachineUpdateRestartSnapshot
    let proposal: MachineUpdateCompletionIntentArchive
    let intentRetained: Bool
    let runtime: RuntimeReleaseCompatibilitySnapshot.Inputs
    func requireSame(as other: Self) throws {
        try restart.requireSame(as: other.restart)
        guard proposal == other.proposal, intentRetained == other.intentRetained, runtime == other.runtime else {
            throw PreparationStoreError.staleRevision
        }
    }
}
