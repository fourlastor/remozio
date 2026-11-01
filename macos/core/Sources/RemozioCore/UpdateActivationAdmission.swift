import Darwin
import Foundation

/// Joins machine activity and update admission. Callers must separately verify the candidate and commit scheduling before acknowledging a drain.
final class UpdateActivationAdmission: Sendable {
    private let activity: ReleaseActivityBarrier
    private let admission: UpdateAdmissionBarrier

    static func open(machineDirectory: String, expected: PreparationFileIdentity) throws -> UpdateActivationAdmission {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: machineDirectory)
        let admission = try UpdateAdmissionBarrier.open(machineDirectory: machineDirectory, expected: expected)
        try activity.validate(); try admission.validate()
        return try .init(activity: activity, admission: admission)
    }

    init(activity: ReleaseActivityBarrier, admission: UpdateAdmissionBarrier) throws {
        guard admission.scope == .machine else { throw MachineUpdateActivationError.wrongBoundary }
        try activity.validate(); try admission.validate()
        self.activity = activity; self.admission = admission
    }

    // Same-owner fixtures open both barriers under one pinned machine directory. They cannot grant native Root authority.
    init(anchor: String, relativeDirectory: String, owner: uid_t, expected: PreparationFileIdentity) throws {
        activity = try .init(directory: ReleaseDestinationLease(anchor: anchor, relativeDirectory: relativeDirectory, owner: owner), owner: owner)
        admission = try .init(directory: ReleaseDestinationLease(anchor: anchor, relativeDirectory: relativeDirectory, owner: owner),
            owner: owner, expected: expected)
        try activity.validate(); try admission.validate()
    }

    /// A busy automatic attempt leaves admission open and retains no activity token.
    func automatic() throws -> UpdateQuiescenceLease? {
        let exclusive: ReleaseActivityToken
        do { exclusive = try activity.acquireExclusive() }
        catch ReleaseActivityError.busy { return nil }
        do {
            let drain = try admission.beginDrain()
            do {
                try exclusive.validateExclusive(); try drain.validate()
                return UpdateQuiescenceLease(activity: exclusive, admission: drain)
            } catch { drain.close(); throw error }
        } catch UpdateAdmissionBarrierError.busy { exclusive.close(); return nil }
        catch { exclusive.close(); throw error }
    }

    /// Existing work keeps its activity references. The caller must restore a committed drain before starting admission listeners.
    func beginDrain() throws -> UpdateAdmissionDrain {
        try activity.validate()
        return try UpdateAdmissionDrain(activity: activity, admission: admission.beginDrain())
    }
}

/// Owns admission while existing work finishes. Transfer to a quiescence lease does not start irreversible activation.
final class UpdateAdmissionDrain: @unchecked Sendable {
    private let lock = NSLock()
    private let activity: ReleaseActivityBarrier
    private let processID = getpid()
    private var admission: UpdateDrainToken?
    private var closed = false
    private var operationActive = false

    fileprivate init(activity: ReleaseActivityBarrier, admission: UpdateDrainToken) {
        self.activity = activity; self.admission = admission
    }

    /// Returns nil while any participating activity remains. No timeout or cancellation is applied to that work.
    func acquireQuiescence() throws -> UpdateQuiescenceLease? {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        return try lock.withLock {
            guard !closed, let admission else { throw JournalLeaseError.invalidated }
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            try admission.validate()
            let exclusive: ReleaseActivityToken
            do { exclusive = try activity.acquireExclusive() }
            catch ReleaseActivityError.busy { return nil }
            do {
                try admission.validate(); try exclusive.validateExclusive()
                let lease = UpdateQuiescenceLease(activity: exclusive, admission: admission)
                self.admission = nil
                return lease
            } catch { exclusive.close(); throw error }
        }
    }

    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed || operationActive, let admission else { throw JournalLeaseError.invalidated }
            try activity.validate(); try admission.validateMachineBoundary(directory: directory, expected: expected)
        }
    }
    func withClosedAdmission<Value>(_ body: () throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        let token = try lock.withLock {
            guard !closed, let admission else { throw JournalLeaseError.invalidated }
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            try admission.validate(); operationActive = true; return admission
        }
        defer {
            lock.withLock {
                operationActive = false
                if closed { admission?.close(); admission = nil }
            }
        }
        let value = try body(); try token.validate(); return value
    }

    func close() {
        guard getpid() == processID else { return }
        lock.withLock {
            closed = true
            if !operationActive { admission?.close(); admission = nil }
        }
    }
    deinit { close() }
}

/// Retains both machine locks. Other roles, release identity, durable activation, and security floors still require their existing checks.
final class UpdateQuiescenceLease: @unchecked Sendable {
    private let lock = NSLock()
    private let activity: ReleaseActivityToken
    private var admission: UpdateDrainToken?
    private let processID = getpid()
    private var closed = false
    private var operationActive = false

    fileprivate init(activity: ReleaseActivityToken, admission: UpdateDrainToken) {
        self.activity = activity; self.admission = admission
    }

    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock { _ = try validateLocked() }
    }
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed || operationActive, let admission else { throw JournalLeaseError.invalidated }
            try activity.validateExclusive(in: directory)
            try admission.validateMachineBoundary(directory: directory, expected: expected)
        }
    }

    /// Lends the existing activity capability to synchronous activation code. Closing waits for the actual callback to settle.
    func withExclusiveActivity<Value>(_ body: (ReleaseActivityToken) throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        let admission = try lock.withLock {
            let admission = try validateLocked()
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            operationActive = true
            return admission
        }
        defer {
            lock.withLock {
                operationActive = false
                if closed { releaseLocked() }
            }
        }
        let value = try body(activity)
        try admission.validate(); try activity.validateExclusive()
        return value
    }

    /// Transfers closed admission to the restart phase. Startup can then acquire shared activity for health checks.
    func releaseActivityForRestart() throws -> UpdateRestartAdmissionLease {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        return try lock.withLock {
            let admission = try validateLocked()
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            let restart = UpdateRestartAdmissionLease(admission: admission)
            self.admission = nil
            closed = true
            activity.close()
            return restart
        }
    }

    func close() {
        guard getpid() == processID else { return }
        lock.withLock {
            closed = true
            if !operationActive { releaseLocked() }
        }
    }
    private func validateLocked() throws -> UpdateDrainToken {
        guard !closed, let admission else { throw JournalLeaseError.invalidated }
        try admission.validate(); try activity.validateExclusive()
        return admission
    }
    private func releaseLocked() { activity.close(); admission?.close(); admission = nil }
    deinit { close() }
}

/// Owns one real shared token and an admission loan. Closing the parent revokes validation but cannot release this loan early.
final class UpdateRestartSharedActivityLease: OwnedReleaseActivity, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let owner: UpdateRestartAdmissionLease
    private let token: ReleaseActivityToken
    private let directory: ReleaseDestinationLease
    private let verifyCurrent: @Sendable (ReleaseDestinationLease) throws -> Void
    private let releaseAdmission: @Sendable () -> Void
    private var closed = false, operationActive = false, released = false
    fileprivate init(owner: UpdateRestartAdmissionLease, token: ReleaseActivityToken, directory: ReleaseDestinationLease,
        verifyCurrent: @escaping @Sendable (ReleaseDestinationLease) throws -> Void, releaseAdmission: @escaping @Sendable () -> Void) {
        self.owner = owner; self.token = token; self.directory = directory; self.verifyCurrent = verifyCurrent; self.releaseAdmission = releaseAdmission
    }
    func validate() throws {
        try lock.withLock {
            guard !closed else { throw JournalLeaseError.invalidated }
            try token.validateShared(in: directory); try verifyCurrent(directory); try token.validateShared(in: directory)
            guard !closed else { throw JournalLeaseError.invalidated }
        }
    }
    func close() {
        lock.withLock {
            guard !closed else { return }
            closed = true; if !operationActive { releaseResources() }
        }
    }
    fileprivate func belongs(to owner: UpdateRestartAdmissionLease) -> Bool { self.owner === owner }
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        try lock.withLock {
            try validate(); try token.validateShared(in: directory)
            try owner.validateMachineBoundary(directory: directory, expected: expected); try validate()
        }
    }
    /// The synchronous callback cannot outlive its actual shared token or the original drain.
    func withClosedAdmission<Value>(_ body: () throws -> Value) throws -> Value {
        try lock.withLock {
            guard !closed, !operationActive else { throw UpdateAdmissionBarrierError.busy }
            operationActive = true
            defer { operationActive = false; if closed { releaseResources() } }
            return try owner.withSharedReadinessAdmission(self) {
                try validate(); let value = try body(); try validate(); return value
            }
        }
    }
    private func releaseResources() {
        guard !released else { return }; released = true; token.close(); releaseAdmission()
    }
    deinit { close() }
}

/// Retains closed admission while startup uses shared activity. The activation owner must verify health and commit floors before closing.
final class UpdateRestartAdmissionLease: @unchecked Sendable {
    private let lock = NSLock()
    private let admission: UpdateDrainToken
    private let processID = getpid()
    private var closed = false
    private var operationActive = false
    private var sharedActivityLoans = 0

    fileprivate init(admission: UpdateDrainToken) { self.admission = admission }

    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock { try validateLocked() }
    }
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed || operationActive || sharedActivityLoans > 0 else { throw JournalLeaseError.invalidated }
            try admission.validateMachineBoundary(directory: directory, expected: expected)
        }
    }

    /// Reuses the existing drain. No admission gap or second drain owner is introduced during this activity loan.
    func withExclusiveActivity<Value>(activity: ReleaseActivityBarrier, directory: ReleaseDestinationLease,
        expected: PreparationFileIdentity, _ body: (ReleaseActivityToken) throws -> Value) throws -> Value {
        try withClosedAdmission {
            try admission.validateMachineBoundary(directory: directory, expected: expected)
            let token = try activity.acquireExclusive(); defer { token.close() }
            try token.validateExclusive(in: directory)
            try admission.validateMachineBoundary(directory: directory, expected: expected)
            let result = try body(token)
            try token.validateExclusive(in: directory)
            try admission.validateMachineBoundary(directory: directory, expected: expected)
            return result
        }
    }

    /// A shared loan retains the original drain through asynchronous readiness and actual joined cleanup.
    func acquireSharedActivity(activity: ReleaseActivityBarrier, directory: ReleaseDestinationLease,
        expected: PreparationFileIdentity) throws -> UpdateRestartSharedActivityLease {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            try validateLocked()
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            let (count, overflow) = sharedActivityLoans.addingReportingOverflow(1)
            guard !overflow else { throw UpdateAdmissionBarrierError.busy }; sharedActivityLoans = count
        }
        var token: ReleaseActivityToken?
        var activityAcquisitionPending = true
        do {
            try admission.validateMachineBoundary(directory: directory, expected: expected)
            let opened = try activity.acquireShared(); token = opened
            try opened.validateShared(in: directory)
            try admission.validateMachineBoundary(directory: directory, expected: expected)
            let loan = UpdateRestartSharedActivityLease(owner: self, token: opened, directory: directory,
                verifyCurrent: { [self] scopedDirectory in
                    try validate(); try admission.validateMachineBoundary(directory: scopedDirectory, expected: expected)
                }, releaseAdmission: { [self] in releaseSharedActivityLoan() })
            // Transfer the count before validation can fail and close the new loan.
            token = nil; activityAcquisitionPending = false
            do { try loan.validate(); return loan } catch { loan.close(); throw error }
        } catch {
            if let token { token.close(); releaseSharedActivityLoan() }
            else {
                // Before token acquisition, this frame still owns the count. A transferred loan owns its own count.
                if activityAcquisitionPending { releaseSharedActivityLoan() }
            }
            throw error
        }
    }
    /// Only a retained loan from this owner can enter while shared readiness remains active.
    fileprivate func withSharedReadinessAdmission<Value>(_ loan: UpdateRestartSharedActivityLease,
        _ body: () throws -> Value) throws -> Value {
        guard getpid() == processID, loan.belongs(to: self) else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            try validateLocked()
            guard !operationActive, sharedActivityLoans > 0 else { throw UpdateAdmissionBarrierError.busy }
            operationActive = true
        }
        defer {
            lock.withLock {
                operationActive = false
                if closed, sharedActivityLoans == 0 { admission.close() }
            }
        }
        try loan.validate(); let value = try body(); try loan.validate(); return value
    }
    private func releaseSharedActivityLoan() {
        guard getpid() == processID else { return }
        lock.withLock {
            precondition(sharedActivityLoans > 0)
            sharedActivityLoans -= 1
            if closed, !operationActive, sharedActivityLoans == 0 { admission.close() }
        }
    }

    /// Runs synchronous restart checks with admission closed. Closing retains admission until the callback returns.
    func withClosedAdmission<Value>(_ body: () throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            try validateLocked()
            guard !operationActive, sharedActivityLoans == 0 else { throw UpdateAdmissionBarrierError.busy }
            operationActive = true
        }
        defer {
            lock.withLock {
                operationActive = false
                if closed, sharedActivityLoans == 0 { admission.close() }
            }
        }
        let value = try body()
        try admission.validate()
        return value
    }

    func close() {
        guard getpid() == processID else { return }
        lock.withLock {
            closed = true
            if !operationActive, sharedActivityLoans == 0 { admission.close() }
        }
    }
    private func validateLocked() throws {
        guard !closed else { throw JournalLeaseError.invalidated }
        try admission.validate()
    }
    deinit { close() }
}
