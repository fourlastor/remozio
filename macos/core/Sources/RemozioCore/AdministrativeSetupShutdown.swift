import Darwin
import Foundation

/// Retains host placement until admitted Setup work and recovery have joined.
final class AdministrativeSetupShutdown: @unchecked Sendable {
    enum RecoveryCloseResult: Equatable, Sendable { case closed, pending, failed, timedOut }
    private let lock = NSLock()
    private var owner: SetupAccountOwner?
    private let placement: ReleaseDestinationLease
    private let processLease: SetupProcessLease
    private var closed = false, recoveryBound = false, externalClosing = false
    private var recoveryRetention: (any Sendable)?
    init(owner: SetupAccountOwner, placement: ReleaseDestinationLease, processLease: SetupProcessLease) {
        self.owner = owner; self.placement = placement; self.processLease = processLease
    }
    init(placement: ReleaseDestinationLease, processLease: SetupProcessLease) {
        self.placement = placement; self.processLease = processLease
    }
    func bind(_ candidate: SetupAccountOwner) throws {
        try lock.withLock {
            guard !closed, !externalClosing, owner == nil else { throw AdministrativeSetupError.unavailable }
            owner = candidate
        }
    }
    func belongs(to candidate: SetupAccountOwner) -> Bool { lock.withLock { owner === candidate } }
    func validateRecoveryCustody() throws { try processLease.validate() }
    func closeRecoveryAdmission() { lock.withLock { owner }?.closeMaintenanceRecoveryAdmission() }
    func reserveRecoverySupervisor() throws {
        try lock.withLock {
            guard !closed, !recoveryBound, !externalClosing else { throw AdministrativeSetupError.unavailable }
            recoveryBound = true
        }
    }
    func retainRecoverySupervisor(_ custody: any Sendable) { lock.withLock { recoveryRetention = custody } }
    /// Ordinary supervisor disposal joins its tasks but leaves the Setup lifecycle to its caller.
    private func releaseRecoverySupervisorAfterJoining() {
        lock.withLock { recoveryBound = false; recoveryRetention = nil }
    }
    /// One attempt after every recovery join. Failure keeps both leases and remains retryable by the lifecycle owner.
    private func closeAfterRecoveryJoined() -> RecoveryCloseResult {
        guard let owner = lock.withLock({ recoveryBound ? owner : nil }) else { return .failed }
        closeRecoveryAdmission()
        guard owner.retryAuditUpgradeCleanup() else { return .pending }
        do { try owner.close() } catch AdministrativeSetupError.unavailable { return .pending }
        catch { return .failed }
        lock.withLock {
            if !closed { placement.close(); processLease.close(); closed = true }
        }
        releaseRecoverySupervisorAfterJoining()
        return .closed
    }
    /// Only this factory exports the supervisor. Its close and release capabilities never escape to the service.
    func recoverySupervisor(owner: SetupAccountOwner) throws -> SetupMaintenanceRecoverySupervisor {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard belongs(to: owner) else { throw RuntimePreparationError.changedScope }
        return try SetupMaintenanceRecoveryNativeAdapter.supervisor(owner: owner, shutdown: self,
            closeAfterJoining: { self.closeAfterRecoveryJoined() },
            releaseAfterJoining: { self.releaseRecoverySupervisorAfterJoining() })
    }
    func closeAfterRecoveryJoinedOwned() throws -> RecoveryCloseResult {
        try RuntimeMaintenanceOwnedControl.require(); return closeAfterRecoveryJoined()
    }
    func releaseRecoverySupervisorOwned() throws {
        try RuntimeMaintenanceOwnedControl.require(); releaseRecoverySupervisorAfterJoining()
    }
    func close() async throws {
        try lock.withLock {
            guard !recoveryBound else { throw AdministrativeSetupError.unavailable }
            externalClosing = true
        }
        if let owner = lock.withLock({ owner }) { try await owner.closeWhenIdle() }
        lock.withLock { if !closed { placement.close(); processLease.close(); closed = true } }
    }
}
