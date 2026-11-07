import Foundation

/// Borrows the original drain for asynchronous readiness. It grants no writer or permission to release admission.
final class MachineUpdateRestartSharedActivity: @unchecked Sendable {
    private let lock = NSLock()
    private let restart: UpdateRestartAdmissionLease
    private let activity: ReleaseActivityBarrier
    private let directory: ReleaseDestinationLease
    private let expectedMachine: PreparationFileIdentity
    private let macID: Data
    private let installationID: Data
    private let activationAttempt: UUID
    private var closed = false

    /// Owned fixtures use real local locks. The native handoff fixes the machine directory and original admission identity.
    init(restart: UpdateRestartAdmissionLease, activity: ReleaseActivityBarrier, directory: ReleaseDestinationLease,
        expectedMachine: PreparationFileIdentity, macID: Data, installationID: Data, activationAttempt: UUID) throws {
        guard macID.count == 16, installationID.count == 16 else { throw RuntimePreparationError.changedScope }
        self.restart = restart; self.activity = activity; self.directory = directory; self.expectedMachine = expectedMachine
        self.macID = macID; self.installationID = installationID; self.activationAttempt = activationAttempt
        try validate()
    }
    func validate() throws {
        try lock.withLock { guard !closed else { throw JournalLeaseError.invalidated } }
        try restart.validate(); try restart.validateMachineBoundary(directory: directory, expected: expectedMachine)
        try lock.withLock { guard !closed else { throw JournalLeaseError.invalidated } }
    }
    func acquireShared() throws -> MachineUpdateRestartReadinessLoan {
        try validate()
        let loan = try restart.acquireSharedActivity(activity: activity, directory: directory, expected: expectedMachine)
        let result = MachineUpdateRestartReadinessLoan(access: self, loan: loan)
        do { try result.validate(); return result } catch { result.close(); throw error }
    }
    func requireScope(macID: Data, installationID: Data, activationAttempt: UUID) throws {
        guard self.macID == macID, self.installationID == installationID,
              self.activationAttempt == activationAttempt else { throw RuntimePreparationError.changedScope }
        try validate()
    }
    /// Revokes future validation. Actual loans keep their activity and admission locks until their owners close them.
    func close() { lock.withLock { closed = true } }
}

/// A real loan from one original admission owner. Only its access factory can construct it.
final class MachineUpdateRestartReadinessLoan: OwnedReleaseActivity, Sendable {
    private let access: MachineUpdateRestartSharedActivity
    private let loan: UpdateRestartSharedActivityLease
    fileprivate init(access: MachineUpdateRestartSharedActivity, loan: UpdateRestartSharedActivityLease) {
        self.access = access; self.loan = loan
    }
    func validate() throws { try loan.validate(); try access.validate(); try loan.validate() }
    func requireScope(macID: Data, installationID: Data, activationAttempt: UUID) throws {
        try access.requireScope(macID: macID, installationID: installationID, activationAttempt: activationAttempt); try validate()
    }
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        try validate(); try loan.validateMachineBoundary(directory: directory, expected: expected); try validate()
    }
    func withClosedAdmission<Value>(_ body: () throws -> Value) throws -> Value {
        try loan.withClosedAdmission { try validate(); let value = try body(); try validate(); return value }
    }
    func close() { loan.close() }
    deinit { close() }
}
