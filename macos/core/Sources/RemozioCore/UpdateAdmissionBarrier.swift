import Darwin
import Foundation

enum UpdateAdmissionBarrierError: Error, Equatable { case busy }

/// Serializes new admission across participating Root processes. Existing work retains its separate activity tokens.
/// A drain token closes admission only. It cannot prove quiescence or authorize activation.
final class UpdateAdmissionBarrier: @unchecked Sendable {
    static let fileName = "update-admission.lock"
    private enum Mode { case admission, drain }
    private let lock = NSLock()
    private let directory: ReleaseDestinationLease
    private let owner: uid_t
    private let scopedFileName: String
    let scope: UpdateAdmissionScope
    private let expected: PreparationFileIdentity
    private let processID = getpid()
    private let baseline: Int32
    private var active: Int32 = -1
    private var mode: Mode?
    private var holders = Set<UUID>()
    private var retired = false

    /// The installer must already have provisioned and retained this machine file's identity.
    /// Opening never creates or adopts a missing or replacement file.
    static func open(machineDirectory: String, expected: PreparationFileIdentity, scope: UpdateAdmissionScope = .machine) throws -> UpdateAdmissionBarrier {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(directory: ReleaseDestinationLease.acquire(path: machineDirectory), owner: 0, expected: expected, scope: scope)
    }

    // Ordinary fixtures retain the same owner's ancestry and exact file identity. Production fixes ownership to Root.
    init(directory: ReleaseDestinationLease, owner: uid_t, expected: PreparationFileIdentity, scope: UpdateAdmissionScope = .machine) throws {
        let name = try scope.fileName
        self.directory = directory; self.owner = owner; self.expected = expected; self.scope = scope; scopedFileName = name
        var opened: Int32 = -1
        do {
            baseline = try directory.withDirectory { parent in
                let fd = openat(parent, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                opened = fd; try Self.inspect(fd, parent: parent, name: name, owner: owner, expected: expected)
                return fd
            }
        } catch { if opened >= 0 { _ = Darwin.close(opened) }; throw error }
    }
    deinit {
        if active >= 0 { _ = Darwin.close(active) }
        _ = Darwin.close(baseline); directory.close()
    }

    /// Validates retained metadata without requiring admission to be open.
    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock { try validateLocked() }
    }

    /// The exact file identity this barrier was opened for. `validate()` proves the held file still matches it.
    var expectedIdentity: PreparationFileIdentity { expected }

    /// Checks the retained file without taking admission or drain ownership.
    func requireRegisteredIdentity(_ identity: PreparationFileIdentity, scope: UpdateAdmissionScope) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard expected == identity, self.scope == scope else { throw RuntimePreparationError.changedScope }
            try validateLocked()
        }
    }

    /// Hold from the admission check through request creation. Never retain this token for the command's whole lifetime.
    func acquireAdmission() throws -> UpdateAdmissionToken {
        try .init(barrier: self, id: acquire(.admission))
    }
    /// The trusted coordinator commits scheduling before acknowledging a drain and retains this token until cancel or activation handoff.
    func beginDrain() throws -> UpdateDrainToken { try .init(barrier: self, id: acquire(.drain)) }

    private func acquire(_ requested: Mode) throws -> UUID {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        return try lock.withLock {
            try validateLocked()
            guard holders.isEmpty || (mode == .admission && requested == .admission) else {
                throw UpdateAdmissionBarrierError.busy
            }
            if holders.isEmpty {
                var opened: Int32 = -1
                do {
                    let fd = try directory.withDirectory { parent in
                        let fd = openat(parent, scopedFileName, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                        opened = fd; try Self.inspect(fd, parent: parent, name: scopedFileName, owner: owner, expected: expected)
                        let operation = requested == .admission ? LOCK_SH : LOCK_EX
                        guard flock(fd, operation | LOCK_NB) == 0 else {
                            if errno == EWOULDBLOCK { throw UpdateAdmissionBarrierError.busy }
                            throw JournalLeaseError.system(errno)
                        }
                        try Self.inspect(fd, parent: parent, name: scopedFileName, owner: owner, expected: expected)
                        return fd
                    }
                    active = fd; mode = requested
                } catch { if opened >= 0 { _ = Darwin.close(opened) }; throw error }
            }
            let id = UUID(); holders.insert(id); return id
        }
    }
    fileprivate func validateAdmission(_ id: UUID) throws { try validate(id, expected: .admission) }
    fileprivate func validateDrain(_ id: UUID) throws { try validate(id, expected: .drain) }
    fileprivate func validateMachineDrain(_ id: UUID, directory: ReleaseDestinationLease,
                                         expected identity: PreparationFileIdentity) throws {
        try validateScopedToken(id, directory: directory, expected: identity, scope: .machine, mode: .drain)
    }
    fileprivate func validateMachineAdmission(_ id: UUID, directory: ReleaseDestinationLease,
                                             expected identity: PreparationFileIdentity) throws {
        try validateScopedToken(id, directory: directory, expected: identity, scope: .machine, mode: .admission)
    }
    fileprivate func validateAccountAdmission(_ id: UUID, directory: ReleaseDestinationLease,
        accountID: Data, expected identity: PreparationFileIdentity) throws {
        guard accountID.count == 16 else { throw MachineUpdateActivationError.wrongBoundary }
        try validateScopedToken(id, directory: directory, expected: identity, scope: .account(accountID), mode: .admission)
    }
    private func validateScopedToken(_ id: UUID, directory: ReleaseDestinationLease,
        expected identity: PreparationFileIdentity, scope expectedScope: UpdateAdmissionScope, mode expectedMode: Mode) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard holders.contains(id), mode == expectedMode else { throw JournalLeaseError.invalidated }
            try validateLocked()
            guard scope == expectedScope, expected == identity,
                  let held = try self.directory.preparationAncestry().last,
                  let requested = try directory.preparationAncestry().last, held == requested else {
                throw MachineUpdateActivationError.wrongBoundary
            }
        }
    }
    private func validate(_ id: UUID, expected: Mode) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard holders.contains(id), mode == expected else { throw JournalLeaseError.invalidated }
            try validateLocked()
        }
    }
    fileprivate func release(_ id: UUID) {
        guard getpid() == processID else { return }
        lock.withLock {
            guard holders.remove(id) != nil, holders.isEmpty else { return }
            // Do not unlock a shared open description. A duplicate or inherited descriptor can still hold it.
            _ = Darwin.close(active); active = -1; mode = nil
        }
    }
    private func validateLocked() throws {
        guard !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            try directory.withDirectory { parent in
                try Self.inspect(baseline, parent: parent, name: scopedFileName, owner: owner, expected: expected)
                if active >= 0 { try Self.inspect(active, parent: parent, name: scopedFileName, owner: owner, expected: expected) }
            }
        } catch {
            // Keep the old kernel lock until its actual holders close, even after metadata retirement.
            retired = true; throw error
        }
    }
    private static func inspect(_ fd: Int32, parent: Int32, name: String, owner: uid_t, expected: PreparationFileIdentity) throws {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_size == 0,
              UInt32(bitPattern: held.st_dev) == expected.device, held.st_ino == expected.inode else {
            throw JournalLeaseError.identityChanged
        }
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, flags & FD_CLOEXEC != 0 else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
    }
}

/// An admission reference, not a live-work or installation capability.
final class UpdateAdmissionToken: Sendable {
    private let barrier: UpdateAdmissionBarrier
    private let id: UUID
    fileprivate init(barrier: UpdateAdmissionBarrier, id: UUID) { self.barrier = barrier; self.id = id }
    func validate() throws { try barrier.validateAdmission(id) }
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        try barrier.validateMachineAdmission(id, directory: directory, expected: expected)
    }
    func validateAccountBoundary(directory: ReleaseDestinationLease, accountID: Data, expected: PreparationFileIdentity) throws {
        try barrier.validateAccountAdmission(id, directory: directory, accountID: accountID, expected: expected)
    }
    func close() { barrier.release(id) }
    deinit { close() }
}

/// Excludes new admission only. Its distinct type cannot substitute for a release activity token.
final class UpdateDrainToken: Sendable {
    private let barrier: UpdateAdmissionBarrier
    private let id: UUID
    fileprivate init(barrier: UpdateAdmissionBarrier, id: UUID) { self.barrier = barrier; self.id = id }
    func validate() throws { try barrier.validateDrain(id) }
    func validateMachineBoundary(directory: ReleaseDestinationLease, expected: PreparationFileIdentity) throws {
        try barrier.validateMachineDrain(id, directory: directory, expected: expected)
    }
    func close() { barrier.release(id) }
    deinit { close() }
}
