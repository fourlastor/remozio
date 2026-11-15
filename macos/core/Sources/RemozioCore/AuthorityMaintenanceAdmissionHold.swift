import Darwin
import Foundation

/// A local request restriction. Only the authenticated command owner may release the exact retained window.
final class AuthorityMaintenanceAdmissionHold: @unchecked Sendable {
    private enum State { case open(Data?), held(Data), unknown, closed }
    private let lock = NSLock(), processID = getpid(), ownerUID = getuid()
    private var state: State
    private let startupAttempt: Data?
    init(projection: RuntimeMaintenanceAdmissionProjection) {
        startupAttempt = projection.requiresLocalHold ? projection.attemptID : nil
        if !projection.requiresLocalHold { state = .open(nil) }
        else if let id = projection.attemptID, projection.revision != nil { state = .held(id) }
        else { state = .unknown }
    }
    func validate() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        try lock.withLock { if case .closed = state { throw JournalLeaseError.invalidated } }
    }
    func requireOpen() throws {
        try validate()
        try lock.withLock { guard case .open = state else { throw UpdateAdmissionBarrierError.busy } }
    }
    /// The caller supplies the actual protected row after the native peer and command checks.
    func retain(_ record: RuntimeMaintenanceWindowRecord) throws {
        try validate()
        guard record.purpose == .retainedRuntime, record.phase == .draining else { throw RuntimePreparationError.changedScope }
        try lock.withLock {
            switch state {
            case .open: state = .held(record.id)
            case .held(let id): guard id == record.id else { throw RuntimePreparationError.changedScope }
            case .unknown, .closed: throw RuntimePreparationError.changedScope
            }
        }
    }
    /// Pre-stop release only. Healthy restoration needs its separately verified new-incarnation path.
    func reopen(_ record: RuntimeMaintenanceWindowRecord, binding: AuthorityMaintenanceBinding, incarnation: Data,
        releaseBinding: () throws -> Void) throws {
        try validate()
        guard record.purpose == .retainedRuntime, record.phase == .reopenPending,
              record.operation == .notStarted, record.service == .notStopped,
              record.shutdownBinding == binding, binding.incarnation == incarnation,
              binding.accountID == record.scope.authority.accountID, binding.attemptID == record.id else {
            throw RuntimePreparationError.changedScope
        }
        try lock.withLock {
            switch state {
            case .held(let id):
                guard id == record.id else { throw RuntimePreparationError.changedScope }
                try releaseBinding(); state = .open(id)
            case .open(let id):
                guard id == record.id else { throw RuntimePreparationError.changedScope }; try releaseBinding()
            case .unknown, .closed: throw RuntimePreparationError.changedScope
            }
        }
    }
    /// Only the original startup restriction can admit a healthy candidate. Command retention cannot create it.
    func requireHealthyStartup(_ record: RuntimeMaintenanceWindowRecord) throws {
        try validate()
        guard record.purpose == .retainedRuntime, record.phase == .restoring, startupAttempt == record.id else {
            throw RuntimePreparationError.changedScope
        }
        try lock.withLock {
            guard case .held(let id) = state, id == record.id else { throw RuntimePreparationError.changedScope }
        }
    }
    func reopenHealthy(_ record: RuntimeMaintenanceWindowRecord, restoring: RuntimeMaintenanceWindowRecord,
        binding: AuthorityMaintenanceBinding, incarnation: Data, releaseBinding: () throws -> Void) throws {
        try requireHealthyStartup(restoring); try record.requireReplacing(restoring)
        guard record.phase == .reopenPending, record.service == .healthy, record.operation == restoring.operation,
              let stopped = record.shutdownBinding, stopped.incarnation != incarnation,
              binding.incarnation == incarnation, binding.accountID == record.scope.authority.accountID,
              binding.attemptID == record.id, binding.revision == restoring.revision else {
            throw RuntimePreparationError.changedScope
        }
        try lock.withLock {
            guard case .held(let id) = state, id == record.id else { throw RuntimePreparationError.changedScope }
            try releaseBinding(); state = .open(id)
        }
    }
    /// An observation grants no release. The caller must bind the current protected row independently.
    func gateHold(attemptID: Data) throws -> RuntimeMaintenanceWindowRecord.GateReadback.Hold {
        try validate()
        return try lock.withLock {
            switch state {
            case .held(let id): guard id == attemptID else { throw RuntimePreparationError.changedScope }; return .held
            case .open(let id): guard id == attemptID else { throw RuntimePreparationError.changedScope }; return .released
            case .unknown: return .unknown
            case .closed: throw JournalLeaseError.invalidated
            }
        }
    }
    func close() { lock.withLock { state = .closed } }
}
