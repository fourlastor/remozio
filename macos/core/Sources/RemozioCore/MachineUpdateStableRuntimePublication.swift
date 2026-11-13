import Foundation

/// A synchronous metadata loan. Its owner supplies and expires both callbacks.
enum MachineUpdateStableRuntimePublication {
    typealias Snapshot = MachineUpdateStableRuntimePreparationSnapshot
    typealias Verify = () throws -> Void
    struct Scope {
        let read: () throws -> Snapshot
        let verify: Verify
    }
}
