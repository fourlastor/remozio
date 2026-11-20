import Darwin
import Foundation

/// A local request restriction. Only the authenticated command owner may release the exact retained window.
final class AuthorityMaintenanceAdmissionHold: @unchecked Sendable {
    private enum State { case open(Data?), held(Data), unknown, closed }
    private let lock = NSLock(), processID = getpid(), ownerUID = getuid()
    private var state: State
    private let startupAttempt: Data?
    private let startupProjection: RuntimeMaintenanceAdmissionProjection
    private var commandAttempt: Data?
    private var unboundAuthorityIncarnation: Data?
    private var releasedUnboundRow: RuntimeMaintenanceWindowRecord?
    init(projection: RuntimeMaintenanceAdmissionProjection) {
        startupProjection = projection
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
            commandAttempt = record.id
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
    /// The trusted operation owner binds its actual admission epoch, never a request-supplied expectation.
    func bindUnboundAuthority(_ incarnation: Data) throws {
        try validate()
        guard incarnation.count == 16 else { throw RuntimePreparationError.changedScope }
        try lock.withLock {
            guard unboundAuthorityIncarnation == nil || unboundAuthorityIncarnation == incarnation else {
                throw RuntimePreparationError.changedScope
            }
            unboundAuthorityIncarnation = incarnation
        }
    }
    private func requireUnboundScope(_ row: RuntimeMaintenanceWindowRecord, incarnation: Data) throws {
        guard incarnation == unboundAuthorityIncarnation, row.purpose == .retainedRuntime,
              [.reopenPending, .needsOwnerRecovery].contains(row.phase), row.unboundRelease != nil,
              row.operation == .notStarted, row.service == .notStopped, row.shutdownBinding == nil,
              startupProjection.startupMacID == row.scope.macID,
              startupProjection.startupInstallationID == row.scope.installationID,
              startupProjection.startupAccount == row.scope.authority else { throw RuntimePreparationError.changedScope }
    }
    private func requireUnboundStartupOrigin(_ row: RuntimeMaintenanceWindowRecord) throws {
        guard let origin = startupProjection.startupRecord, let descriptor = row.unboundRelease,
              origin.id == row.id, origin.scope == row.scope, origin.purpose == row.purpose,
              origin.operation == .notStarted,
              origin.service == .notStopped, origin.shutdownBinding == nil else { throw RuntimePreparationError.changedScope }
        if origin.phase == .authorized {
            guard origin.revision == descriptor.authorizedRevision,
                  try RuntimeMaintenanceUnboundRelease.digest(origin) == descriptor.authorizedDigest else {
                throw RuntimePreparationError.changedScope
            }
        } else {
            guard [.reopenPending, .needsOwnerRecovery].contains(origin.phase),
                  origin.unboundRelease == descriptor else { throw RuntimePreparationError.changedScope }
        }
    }
    private func matchesReleasedUnbound(_ row: RuntimeMaintenanceWindowRecord) -> Bool {
        guard let releasedUnboundRow else { return false }
        return releasedUnboundRow.id == row.id && releasedUnboundRow.scope == row.scope
            && releasedUnboundRow.unboundRelease == row.unboundRelease
    }
    /// Hold and pairing remain locked together only for the local state change. Protected reads happen outside both.
    func releaseUnbound(_ row: RuntimeMaintenanceWindowRecord, incarnation: Data,
        pairing: AuthorityMaintenancePairingAdmission) throws -> AuthorityMaintenanceUnboundReleaseResponse.Outcome {
        try releaseUnbound(row, incarnation: incarnation, pairing: pairing, mutationBoundary: { _ in })
    }
    enum UnboundMutationBoundary { case before, after }
    /// Ordinary-owner synchronization probe. It cannot grant an installed caller access or substitute the mutation.
    /// Its synchronous callback must not reenter the hold, read storage, await or acquire an earlier lock.
    func releaseUnboundOwned(_ row: RuntimeMaintenanceWindowRecord, incarnation: Data,
        pairing: AuthorityMaintenancePairingAdmission, mutationBoundary: (UnboundMutationBoundary) -> Void)
        throws -> AuthorityMaintenanceUnboundReleaseResponse.Outcome {
        try RuntimeMaintenanceOwnedControl.require()
        return try releaseUnbound(row, incarnation: incarnation, pairing: pairing, mutationBoundary: mutationBoundary)
    }
    private func releaseUnbound(_ row: RuntimeMaintenanceWindowRecord, incarnation: Data,
        pairing: AuthorityMaintenancePairingAdmission, mutationBoundary: (UnboundMutationBoundary) -> Void)
        throws -> AuthorityMaintenanceUnboundReleaseResponse.Outcome {
        try validate()
        return try lock.withLock {
            try requireUnboundScope(row, incarnation: incarnation)
            return try pairing.withUnboundCommandIdle {
                switch state {
                case .held(let id):
                    guard id == row.id, commandAttempt != row.id else { throw RuntimePreparationError.changedScope }
                    try requireUnboundStartupOrigin(row)
                    mutationBoundary(.before)
                    releasedUnboundRow = row; state = .open(row.id)
                    mutationBoundary(.after); return .released
                case .open:
                    guard matchesReleasedUnbound(row) else { throw RuntimePreparationError.changedScope }
                    return .alreadyReleased
                case .unknown, .closed: throw RuntimePreparationError.changedScope
                }
            }
        }
    }
    /// This distinguishes an actual release from an attempt that the current process never held.
    func unboundObservation(_ row: RuntimeMaintenanceWindowRecord, incarnation: Data) throws -> AuthorityMaintenanceUnboundGateResponse.Hold {
        try validate()
        return try lock.withLock {
            guard incarnation == unboundAuthorityIncarnation else { throw RuntimePreparationError.changedScope }
            // Unknown startup metadata cannot prove scope. The observation reports that uncertainty without releasing it.
            if case .unknown = state { return .unknown }
            try requireUnboundScope(row, incarnation: incarnation)
            switch state {
            case .held(let id):
                guard id == row.id, commandAttempt != row.id else { throw RuntimePreparationError.changedScope }
                try requireUnboundStartupOrigin(row); return .held
            case .open:
                if matchesReleasedUnbound(row) { return .released }
                guard commandAttempt != row.id,
                      !startupProjection.requiresLocalHold || startupProjection.attemptID != row.id else {
                    throw RuntimePreparationError.changedScope
                }
                return .neverHeld
            case .unknown: return .unknown
            case .closed: throw JournalLeaseError.invalidated
            }
        }
    }
    func close() { lock.withLock { state = .closed } }
}
