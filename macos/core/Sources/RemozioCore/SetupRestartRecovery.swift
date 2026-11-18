import Darwin
import Foundation

enum SetupRestartRecoveryError: Error { case completionNeedsAdoption, uncertainWriter, unsettledWindow }

/// Fresh restart custody has no in-process ledger and cannot issue Joined or never-entered evidence.
final class SetupRestartRecovery: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    typealias Work = SetupRetainedInvocationReservation.RestorationWork
    typealias Phases = SetupRetainedInvocationReservation.RestorationPhases
    private let permit: SetupAccountOwner.RestartPermit
    var accountID: Data { permit.accountID }
    var accountOwner: LocalAccountIdentity { permit.accountOwner }
    var admission: SetupOwnerAsyncWork.Token { permit.admission }
    var reply: SetupOwnerAsyncWork.Token { permit.reply }
    /// A reclaim adds its worker hold here before it enters the executor.
    var hold: SetupAccountOwner.ExecutorAdmission { permit.hold }
    private let phases: Phases
    private let lock = NSLock(), processID = getpid(), ownerUID = getuid()
    private var captured: SetupRetainedInvocationStatus.Window?
    private var claimID: UUID?, latestClaimID: UUID?, attemptedClaim: UUID?, work: Work?
    private var settled = false
    private var attempt: RuntimeMaintenanceStartupRecovery.RestartAttempt?

    fileprivate init(permit: SetupAccountOwner.RestartPermit) {
        self.permit = permit; phases = .restart(permit: permit)
    }
    /// The permit's initializer is private to the owner file. No caller can inject the owner check or executor.
    static func reserve(permit: SetupAccountOwner.RestartPermit, authorization: SetupRetainedRecoveryAuthorization,
        processLease: SetupProcessLease) throws -> (record: SetupRestartRecovery, claim: Claim) {
        let record = SetupRestartRecovery(permit: permit)
        return (record, try record.claim(authorization: authorization, processLease: processLease,
            accountID: permit.accountID, native: permit.native))
    }
    static func reclaim(_ record: SetupRestartRecovery, authorization: SetupRetainedRecoveryAuthorization,
        processLease: SetupProcessLease, accountID: Data, native: Bool) throws -> Claim {
        try record.requireProcess(); try record.permit.requireOwner(record, windowID: record.lock.withLock { record.captured?.id })
        return try record.claim(authorization: authorization, processLease: processLease, accountID: accountID, native: native)
    }
    var isSettled: Bool { lock.withLock { settled } }
    fileprivate func claim(authorization: SetupRetainedRecoveryAuthorization, processLease: SetupProcessLease,
        accountID: Data, native: Bool) throws -> Claim {
        try requireProcess()
        guard accountID == self.accountID, native == permit.native, authorization.currentOwner == accountOwner,
              authorization.peer.userID == accountOwner.uid else { throw XPCPeerPolicyError.wrongPeer }
        return try lock.withLock {
            guard !settled, claimID == nil else { throw AdministrativeSetupError.unavailable }
            let id = UUID(); claimID = id; latestClaimID = id
            return Claim(record: self, authorization: authorization, processLease: processLease, id: id)
        }
    }
    private func requireProcess() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
    }
    private func requireClaim(_ id: UUID) throws {
        try requireProcess()
        guard !settled, claimID == id else { throw JournalLeaseError.invalidated }
    }
    private func requireCurrent(_ id: UUID, starting: Bool = false) throws {
        try requireProcess()
        let windowID = try lock.withLock { try requireClaim(id); return captured?.id }
        try permit.requireOwner(self, windowID: windowID, starting: starting)
        try lock.withLock { try requireClaim(id) }
    }
    private func capture(_ row: RuntimeMaintenanceWindowRecord, claim id: UUID) throws {
        try requireCurrent(id)
        var directory = accountOwner.directoryID.uuid
        guard row.scope.authority.accountID == accountID, row.scope.authority.ownerUID == accountOwner.uid,
              row.scope.authority.directoryID == withUnsafeBytes(of: &directory, { Data($0) }) else {
            throw RuntimePreparationError.changedScope
        }
        try permit.requireOwner(self, windowID: row.id)
        try lock.withLock {
            try requireClaim(id)
            guard captured == nil || captured?.identifies(row) == true else { throw RuntimePreparationError.changedScope }
            if captured == nil { captured = .init(row) }
        }
    }
    private func requireWindow(_ row: RuntimeMaintenanceWindowRecord, claim id: UUID) throws {
        try requireCurrent(id)
        try lock.withLock {
            try requireClaim(id)
            guard captured?.identifies(row) == true else { throw RuntimePreparationError.changedScope }
        }
    }
    private func start(claim id: UUID, attempt: RuntimeMaintenanceStartupRecovery.RestartAttempt) throws -> Work {
        try requireCurrent(id, starting: true)
        let (started, retired, retiredAttempt, open) = try lock.withLock {
            try requireClaim(id)
            guard self.attempt?.hasUncertainWriter != true else { throw SetupRestartRecoveryError.uncertainWriter }
            guard self.attempt?.hasRestingRow != false else { throw SetupRestartRecoveryError.unsettledWindow }
            guard work?.holdsUnsettledCompletion != true else { throw SetupRestartRecoveryError.completionNeedsAdoption }
            guard attemptedClaim != id, work == nil || work?.actualReturnObserved == true else { throw AdministrativeSetupError.unavailable }
            let retired = work, retiredAttempt = self.attempt
            let next = Work.restart(permit: permit) { try await attempt.run(workID: $0) }
            work = next.work; attemptedClaim = id; self.attempt = attempt
            return (next.work, retired, retiredAttempt, next.open)
        }
        withExtendedLifetime((retired, retiredAttempt)) {}
        // This observer only joins the retained task. It never writes, opens custody or fabricates a completion.
        Task {
            _ = try? await started.value()
            _ = try? await self.phases.cleanup { try self.releaseSafe(claim: id, allowAbandoned: true,
                releasingAbandonedSuccessor: true, allowForwardEffects: false) }
        }
        open()
        return started
    }
    private func currentWork(claim id: UUID) throws -> Work? {
        try requireCurrent(id)
        return try lock.withLock { try requireClaim(id); return work }
    }
    /// Admission release does not reopen the durable window. Account startup stays held by its real row.
    private func releaseSafe(claim id: UUID, allowAbandoned: Bool = false,
        releasingAbandonedSuccessor: Bool = false, allowForwardEffects: Bool) throws -> Bool {
        try requireProcess()
        if lock.withLock({ settled || !(latestClaimID == id || releasingAbandonedSuccessor && claimID == nil) }) { return false }
        try permit.requireOwner(self, windowID: lock.withLock { captured?.id })
        let release = try lock.withLock { () throws -> (@Sendable () -> Void)? in
            guard !settled, latestClaimID == id || releasingAbandonedSuccessor && claimID == nil,
                  allowAbandoned || claimID == id else { return nil }
            guard attempt?.permitsRelease(allowForwardEffects: allowForwardEffects) != false,
                  work == nil || work?.actualReturnObserved == true,
                  work?.holdsUnsettledCompletion != true else { return nil }
            try permit.activity?.validate(); settled = true
            return permit.hold.markRecordReleased()
        }
        guard let release else { return false }
        release()
        return true
    }
    private func settle(_ completed: RuntimeMaintenanceStartupRecovery.ExplicitCompletion, work: Work, claim id: UUID) throws {
        try requireWindow(completed.window, claim: id)
        let release = try lock.withLock {
            try requireClaim(id)
            guard self.work === work, work.actualReturnObserved, completed.workID == work.id,
                  attempt?.permitsRelease(allowForwardEffects: true) == true, completed.window.phase == .restored,
                  completed.window.gate?.hold == .released, completed.window.gate?.admission == .available else {
                throw RuntimePreparationError.changedScope
            }
            try permit.activity?.validate(); settled = true
            return permit.hold.markRecordReleased()
        }
        release()
    }
    var description: String { "SetupRestartRecovery(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    /// Each caller owns fresh rights. Losing it preserves live tasks, uncertain writers and unsettled completions.
    final class Claim: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        private let record: SetupRestartRecovery, authorization: SetupRetainedRecoveryAuthorization, id: UUID
        let processLease: SetupProcessLease
        fileprivate init(record: SetupRestartRecovery, authorization: SetupRetainedRecoveryAuthorization,
            processLease: SetupProcessLease, id: UUID) {
            self.record = record; self.authorization = authorization; self.processLease = processLease; self.id = id
        }
        static func openNative(owner: SetupAccountOwner, authorization: SetupRetainedRecoveryAuthorization,
            processLease: SetupProcessLease, accountID: Data, until deadline: ContinuousClock.Instant) async throws -> Claim {
            try await owner.claimRestartRecovery(authorization: authorization, processLease: processLease,
                accountID: accountID, native: true, until: deadline)
        }
        static func openOwned(owner: SetupAccountOwner, authorization: SetupRetainedRecoveryAuthorization,
            processLease: SetupProcessLease, accountID: Data, until deadline: ContinuousClock.Instant) async throws -> Claim {
            try RuntimeMaintenanceOwnedControl.require()
            return try await owner.claimRestartRecovery(authorization: authorization, processLease: processLease,
                accountID: accountID, native: false, until: deadline)
        }
        func requireCurrentAuthorization() throws {
            try processLease.validate(); try authorization.requireCurrent(); try record.requireCurrent(id)
        }
        func restorationPhases() -> Phases { record.phases }
        func requireRestorationAccount(_ accountID: Data) throws {
            try requireCurrentAuthorization()
            guard accountID == record.accountID else { throw RuntimePreparationError.changedScope }
        }
        func capture(_ row: RuntimeMaintenanceWindowRecord) throws {
            try requireCurrentAuthorization(); try record.capture(row, claim: id)
        }
        func requireRestorationWindow(_ row: RuntimeMaintenanceWindowRecord) throws {
            try requireCurrentAuthorization(); try record.requireWindow(row, claim: id)
        }
        /// This awaits only a real restart task. It never supplies M12a join evidence.
        func joinPreviousRestoration() async throws {
            let previous = try record.currentWork(claim: id)
            if let previous { _ = try? await previous.value() }
            try await record.phases.run { try self.requireCurrentAuthorization() }
        }
        func startRestoration(_ attempt: RuntimeMaintenanceStartupRecovery.RestartAttempt) throws -> Work {
            try record.start(claim: id, attempt: attempt)
        }
        func finishRecordedRestoration() async throws -> RuntimeMaintenanceWindowRecord {
            guard let work = try record.currentWork(claim: id) else { throw PreparationStoreError.notFound }
            return try await finishRestoration(work: work)
        }
        func finishRestoration(work: Work) async throws -> RuntimeMaintenanceWindowRecord {
            let completed: RuntimeMaintenanceStartupRecovery.ExplicitCompletion
            do { completed = try await work.value() }
            catch {
                _ = try? await record.phases.cleanup { try self.record.releaseSafe(claim: self.id, allowAbandoned: true, allowForwardEffects: false) }
                throw error
            }
            try await record.phases.run {
                try self.requireCurrentAuthorization()
                if self.record.permit.native { try completed.requireNative(processLease: self.processLease) }
                else { try completed.requireOwned(processLease: self.processLease) }
                try self.requireCurrentAuthorization(); try self.record.settle(completed, work: work, claim: self.id)
            }
            return completed.window
        }
        /// Refusal before forward effects can release only an actually returned, closed and certain attempt.
        func releaseRefusedAttemptIfSafe() async {
            _ = try? await record.phases.cleanup { try self.record.releaseSafe(claim: self.id, allowAbandoned: true, allowForwardEffects: false) }
        }
        /// Fresh rights release only this process's idle slot. This writes no row and clears no account drain.
        func releaseWithoutRestoration() async throws -> Bool {
            // A record that released every hold is settled. As before, that answer is `false`.
            try await record.phases.cleanupUnlessReleased {
                try self.processLease.validate(); try self.authorization.requireCurrent()
                return try self.record.releaseSafe(claim: self.id, allowForwardEffects: true)
            } ?? false
        }
        /// The future endpoint calls this on connection loss, even while the actual task retains this claim.
        func abandon() {
            guard getpid() == record.processID else { return }
            record.lock.withLock { if record.claimID == id { record.claimID = nil } }
            authorization.close()
            _ = try? record.releaseSafe(claim: id, allowAbandoned: true, allowForwardEffects: false)
        }
        deinit { abandon() }
        var description: String { "SetupRestartRecoveryClaim(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
}
