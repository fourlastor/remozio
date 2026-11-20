import Foundation

/// Phase decisions only. They grant no custody, RPC, write, or registration permission.
enum RuntimeMaintenanceStartupPolicy {
    typealias Record = RuntimeMaintenanceWindowRecord
    enum Action: Equatable, Sendable {
        case nothing, ownerRecovery(Record.Failure), probeIncarnation, cancelAndReopen, restartRestoration
        case observeOperation, restore
    }
    static func initial(_ row: Record) throws -> Action {
        try RuntimeMaintenanceCommitments.requireProfile(row.purpose)
        switch row.phase {
        case .authorized: return .ownerRecovery(.cleanupPending)
        case .draining, .stopping:
            return row.shutdownBinding == nil ? .ownerRecovery(.cleanupPending) : .probeIncarnation
        case .stopped, .workSettled, .restoring:
            return row.shutdownBinding == nil ? .ownerRecovery(.cleanupPending) : .restore
        case .executing:
            return row.shutdownBinding == nil ? .ownerRecovery(.cleanupPending) : .observeOperation
        case .reopenPending: return .ownerRecovery(.admissionUnconfirmed)
        case .restored, .needsOwnerRecovery: return .nothing
        }
    }
    /// The caller must authenticate a live proof before it supplies this comparison result.
    static func afterProbe(_ row: Record, sameIncarnation: Bool) throws -> Action {
        guard try initial(row) == .probeIncarnation, row.operation == .notStarted else {
            throw RuntimePreparationError.changedScope
        }
        if !sameIncarnation { return .restartRestoration }
        return row.phase == .draining ? .cancelAndReopen : .ownerRecovery(.cleanupPending)
    }
    static func operation(_ state: RuntimeMaintenanceRuntimeObservation.State) -> Record.OperationOutcome {
        switch state {
        case .new: return .committed
        case .old: return .failed
        case .partial, .unknown: return .unknown
        }
    }
    static func row(_ previous: Record, phase: Record.Phase, operation: Record.OperationOutcome? = nil,
        service: Record.ServiceOutcome, failure: Record.Failure? = nil,
        revision: Data = AccountPreparationIntent.randomID()) throws -> Record {
        let next = try Record(id: previous.id, revision: revision, purpose: previous.purpose,
            scope: previous.scope, phase: phase, operation: operation ?? previous.operation,
            service: service, failure: failure, shutdownBinding: previous.shutdownBinding, unboundRelease: previous.unboundRelease)
        try next.requireReplacing(previous); return next
    }
}
