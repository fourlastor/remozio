import Darwin
import Foundation

/// Holds ordinary machine admission and shared activity. The caller must separately verify the actual store, account, and executing code.
final class UpdateOrdinaryAdmissionLease: @unchecked Sendable {
    /// A synchronous loan of the actual machine boundary. It expires when its callback returns.
    final class Scope: @unchecked Sendable {
        private let lock = NSLock()
        private let processID = getpid()
        private weak var owner: UpdateOrdinaryAdmissionLease?
        private var active = true
        fileprivate init(owner: UpdateOrdinaryAdmissionLease) { self.owner = owner }
        func validate() throws {
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            try lock.withLock {
                guard active, let owner else { throw JournalLeaseError.invalidated }
                try owner.validateBorrowed()
            }
        }
        func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            try lock.withLock {
                guard active, let owner else { throw JournalLeaseError.invalidated }
                try owner.validateBorrowed(directory: directory, expected: expected)
            }
        }
        fileprivate func expire() { lock.withLock { active = false; owner = nil } }
    }
    private let lock = NSLock()
    private let processID = getpid()
    private let activity: ReleaseActivityToken
    private let admission: UpdateAdmissionToken
    private let directory: ReleaseDestinationLease
    private let expected: PreparationFileIdentity
    private var closed = false, operationActive = false

    static func open(machineDirectory: String, expected: PreparationFileIdentity) throws -> UpdateOrdinaryAdmissionLease {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let directory = try ReleaseDestinationLease.acquire(path: machineDirectory)
        do {
            return try .init(activity: ReleaseActivityBarrier.open(machineDirectory: machineDirectory),
                admission: UpdateAdmissionBarrier.open(machineDirectory: machineDirectory, expected: expected),
                directory: directory, expected: expected)
        } catch { directory.close(); throw error }
    }
    /// Owned fixtures use the same file metadata checks. Construction does not grant native Root authority.
    init(activity: ReleaseActivityBarrier, admission: UpdateAdmissionBarrier,
        directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        guard admission.scope == .machine else { throw MachineUpdateActivationError.wrongBoundary }
        let shared = try activity.acquireShared()
        do {
            let token = try admission.acquireAdmission()
            do {
                try shared.validateShared(in: directory)
                try token.validateMachineBoundary(directory: directory, expected: expected)
                self.activity = shared; self.admission = token; self.directory = directory; self.expected = expected
            } catch { token.close(); throw error }
        } catch { shared.close(); throw error }
    }
    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed else { throw JournalLeaseError.invalidated }
            try validateLocked()
        }
    }
    /// Checks this held machine admission against an exact directory without creating a writer loan.
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed else { throw JournalLeaseError.invalidated }
            try validateLocked()
            guard self.expected == expected else { throw MachineUpdateActivationError.wrongBoundary }
            try activity.validateShared(in: directory)
            try admission.validateMachineBoundary(directory: directory, expected: expected)
        }
    }
    func withMachineAdmission<Value>(_ body: (Scope) throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard !closed else { throw JournalLeaseError.invalidated }
            guard !operationActive else { throw UpdateAdmissionBarrierError.busy }
            try validateLocked(); operationActive = true
        }
        let scope = Scope(owner: self)
        defer {
            scope.expire()
            lock.withLock { operationActive = false; if closed { releaseLocked() } }
        }
        let value = try body(scope); try scope.validate(); return value
    }
    private func validateBorrowed() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard operationActive else { throw JournalLeaseError.invalidated }
            try validateLocked()
        }
    }
    private func validateBorrowed(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard operationActive else { throw JournalLeaseError.invalidated }
            try validateLocked()
            guard self.expected == expected else { throw MachineUpdateActivationError.wrongBoundary }
            try activity.validateShared(in: directory)
            try admission.validateMachineBoundary(directory: directory, expected: expected)
        }
    }
    private func validateLocked() throws {
        try activity.validateShared(in: directory)
        try admission.validateMachineBoundary(directory: directory, expected: expected)
    }
    func close() {
        guard getpid() == processID else { return }
        lock.withLock { closed = true; if !operationActive { releaseLocked() } }
    }
    private func releaseLocked() { activity.close(); admission.close(); directory.close() }
    deinit { close() }
}
