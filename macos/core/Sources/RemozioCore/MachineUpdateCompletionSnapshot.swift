import Foundation

/// Current completion facts and their historical source. This value grants no writer, health or admission authority.
struct MachineUpdateCompletionSnapshot {
    let restart: MachineUpdateRestartSnapshot
    let intent: MachineUpdateCompletionIntentArchive
    func requireSame(as other: Self) throws {
        try restart.requireSame(as: other.restart)
        guard intent == other.intent else { throw PreparationStoreError.staleRevision }
    }
}
