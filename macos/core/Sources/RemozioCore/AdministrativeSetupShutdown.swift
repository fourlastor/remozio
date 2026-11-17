import Foundation

/// Retains host placement until admitted Setup work and recovery have joined.
final class AdministrativeSetupShutdown: @unchecked Sendable {
    enum RecoveryCloseResult: Equatable, Sendable { case closed, pending, failed, timedOut }
    private let lock = NSLock()
    private let owner: SetupAccountOwner
    private let placement: ReleaseDestinationLease
    private let processLease: SetupProcessLease
    private var closed = false, recoveryBound = false, externalClosing = false
    private var recoveryRetention: (any Sendable)?
    init(owner: SetupAccountOwner, placement: ReleaseDestinationLease, processLease: SetupProcessLease) {
        self.owner = owner; self.placement = placement; self.processLease = processLease
    }
    func belongs(to candidate: SetupAccountOwner) -> Bool { owner === candidate }
    func validateRecoveryCustody() throws { try processLease.validate() }
    func closeRecoveryAdmission() { owner.closeMaintenanceRecoveryAdmission() }
    func reserveRecoverySupervisor() throws {
        try lock.withLock {
            guard !closed, !recoveryBound, !externalClosing else { throw AdministrativeSetupError.unavailable }
            recoveryBound = true
        }
    }
    func retainRecoverySupervisor(_ custody: any Sendable) { lock.withLock { recoveryRetention = custody } }
    /// Ordinary supervisor disposal joins its tasks but leaves the Setup lifecycle to its caller.
    func releaseRecoverySupervisorAfterJoining() {
        lock.withLock { recoveryBound = false; recoveryRetention = nil }
    }
    /// One attempt after every recovery join. Failure keeps both leases and remains retryable by the lifecycle owner.
    func closeAfterRecoveryJoined() -> RecoveryCloseResult {
        guard lock.withLock({ recoveryBound }) else { return .failed }
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
    func close() async throws {
        try lock.withLock {
            guard !recoveryBound else { throw AdministrativeSetupError.unavailable }
            externalClosing = true
        }
        try await owner.closeWhenIdle()
        lock.withLock { if !closed { placement.close(); processLease.close(); closed = true } }
    }
}
