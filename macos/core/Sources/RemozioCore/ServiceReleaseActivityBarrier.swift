import Darwin
import Foundation

protocol OwnedReleaseActivity: Sendable {
    func validate() throws
    func close()
}
extension ReleaseActivityToken: OwnedReleaseActivity {}

/// A service reads its Root-owned group lock. Root update checks must retain every participating role's exclusive token.
/// This lock alone does not authorize an update or prove that all installed roles participate.
final class ServiceReleaseActivityBarrier: @unchecked Sendable {
    private let lock = NSLock()
    private let directory: ReleaseDestinationLease
    private let role: ServiceAccountRole
    private let owner: uid_t
    private let group: gid_t
    private let reader: uid_t
    private let expected: PreparationFileIdentity
    private let exclusiveAllowed: Bool
    private let verifyCurrent: @Sendable () throws -> Void
    private let processID = getpid()
    private let baseline: Int32
    private var active: Int32 = -1
    private var exclusive = false
    private var holders = Set<UUID>()
    private var retired = false

    static func fileName(_ role: ServiceAccountRole) -> String {
        role == .transport ? "transport.activity.lock" : "gateway.activity.lock"
    }
    static func open(services: ServiceAccountPlan, role: ServiceAccountRole, expected: PreparationFileIdentity,
                     verifyCurrent: @escaping @Sendable () throws -> Void) throws -> ServiceReleaseActivityBarrier {
        guard let claim = services.claims.first(where: { $0.role == role }) else { throw GatewayPreparationError.changedScope }
        try DedicatedServiceAccount.requireCurrent(serviceUID: claim.number, ownerUID: services.ownerUID)
        guard getgid() == claim.number, getegid() == claim.number else { throw DedicatedServiceAccountError.unsafeAccount }
        let identities = try ServiceAccountDirectoryReader()
        guard try identities.state(claim: claim, kind: .user) == .retained,
              try identities.state(claim: claim, kind: .group) == .retained else { throw GatewayPreparationError.changedScope }
        try verifyCurrent()
        let directory = try ReleaseDestinationLease.readForServiceRegistration(path: RuntimePreparationPaths(accountID: services.accountID).serviceDirectory)
        return try .init(directory: directory, role: role, owner: 0, group: claim.number, reader: claim.number,
            expected: expected, exclusiveAllowed: false, verifyCurrent: verifyCurrent)
    }
    static func openForUpdate(services: ServiceAccountPlan, role: ServiceAccountRole, expected: PreparationFileIdentity,
                              verifyCurrent: @escaping @Sendable () throws -> Void) throws -> ServiceReleaseActivityBarrier {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard let claim = services.claims.first(where: { $0.role == role }) else { throw GatewayPreparationError.changedScope }
        try verifyCurrent()
        return try .init(directory: ReleaseDestinationLease.acquire(path: RuntimePreparationPaths(accountID: services.accountID).serviceDirectory),
            role: role, owner: 0, group: claim.number, reader: 0, expected: expected, exclusiveAllowed: true, verifyCurrent: verifyCurrent)
    }
    // Ordinary fixtures use retained ancestry and the current owner. No native entry accepts caller paths or ownership.
    init(directory: ReleaseDestinationLease, role: ServiceAccountRole, owner: uid_t, group: gid_t, reader: uid_t,
         expected: PreparationFileIdentity, exclusiveAllowed: Bool, verifyCurrent: @escaping @Sendable () throws -> Void = {}) throws {
        self.directory = directory; self.role = role; self.owner = owner; self.group = group; self.reader = reader
        self.expected = expected; self.exclusiveAllowed = exclusiveAllowed; self.verifyCurrent = verifyCurrent
        var opened: Int32 = -1
        do {
            try verifyCurrent()
            baseline = try directory.withDirectory { parent in
                let fd = openat(parent, Self.fileName(role), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                opened = fd; try Self.inspect(fd, parent: parent, role: role, owner: owner, group: group, expected: expected)
                return fd
            }
        } catch { if opened >= 0 { _ = Darwin.close(opened) }; throw error }
    }
    deinit { if active >= 0 { _ = Darwin.close(active) }; _ = Darwin.close(baseline); directory.close() }
    func acquireShared() throws -> ServiceReleaseActivityToken { try acquire(exclusive: false) }
    func acquireExclusive() throws -> ServiceReleaseActivityToken {
        guard exclusiveAllowed else { throw JournalLeaseError.rootRequired }
        return try acquire(exclusive: true)
    }
    private func acquire(exclusive requested: Bool) throws -> ServiceReleaseActivityToken {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        return try lock.withLock {
            try validateLocked()
            guard holders.isEmpty || (!exclusive && !requested) else { throw ReleaseActivityError.busy }
            if holders.isEmpty {
                var opened: Int32 = -1
                do {
                    let fd = try directory.withDirectory { parent in
                        let fd = openat(parent, Self.fileName(role), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                        opened = fd; try inspect(fd, parent: parent)
                        guard flock(fd, (requested ? LOCK_EX : LOCK_SH) | LOCK_NB) == 0 else {
                            if errno == EWOULDBLOCK { throw ReleaseActivityError.busy }
                            throw JournalLeaseError.system(errno)
                        }
                        try inspect(fd, parent: parent); return fd
                    }
                    active = fd; exclusive = requested
                } catch { if opened >= 0 { _ = Darwin.close(opened) }; throw error }
            }
            let id = UUID(); holders.insert(id); return .init(barrier: self, id: id)
        }
    }
    /// Lends the existing shared lock to synchronous spawn actions. Closing a copy must never unlock its shared description.
    fileprivate func withSharedDescriptorForSpawn<Value>(_ id: UUID, _ body: (Int32) throws -> Value) throws -> Value {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        let copied = try lock.withLock {
            guard holders.contains(id) else { throw JournalLeaseError.invalidated }
            try validateLocked()
            guard !exclusive, active >= 0 else { throw JournalLeaseError.unsafeMetadata }
            let copied = fcntl(active, F_DUPFD_CLOEXEC, 32)
            guard copied >= 0 else { throw JournalLeaseError.system(errno) }
            return copied
        }
        defer { _ = Darwin.close(copied) }
        // The copy pins activity while the callback runs without the barrier mutex.
        // The caller owns any child it creates. No validation can hide that child afterward.
        return try body(copied)
    }
    fileprivate func validate(_ id: UUID) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock { guard holders.contains(id) else { throw JournalLeaseError.invalidated }; try validateLocked() }
    }
    fileprivate func release(_ id: UUID) {
        guard getpid() == processID else { return }
        lock.withLock {
            guard holders.remove(id) != nil, holders.isEmpty else { return }
            // Closing the independently opened description preserves other holders, including a fork's inherited lock.
            _ = Darwin.close(active); active = -1; exclusive = false
        }
    }
    private func validateLocked() throws {
        guard !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, getuid() == reader, geteuid() == reader else { throw JournalLeaseError.unsafeMetadata }
            try verifyCurrent()
            try directory.withDirectory { parent in
                try inspect(baseline, parent: parent)
                if active >= 0 { try inspect(active, parent: parent) }
            }
            try verifyCurrent()
        } catch { retired = true; throw error }
    }
    private func inspect(_ fd: Int32, parent: Int32) throws {
        try Self.inspect(fd, parent: parent, role: role, owner: owner, group: group, expected: expected)
    }
    private static func inspect(_ fd: Int32, parent: Int32, role: ServiceAccountRole, owner: uid_t, group: gid_t,
                                expected: PreparationFileIdentity) throws {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, fileName(role), &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              UInt32(bitPattern: held.st_dev) == expected.device, held.st_ino == expected.inode else { throw JournalLeaseError.identityChanged }
        guard held.st_uid == owner, held.st_gid == group, held.st_mode & 0o7777 == 0o440,
              held.st_size == 0, held.st_nlink == 1 else { throw JournalLeaseError.unsafeMetadata }
        let flags = fcntl(fd, F_GETFD), status = fcntl(fd, F_GETFL)
        guard flags >= 0, flags & FD_CLOEXEC != 0, status >= 0, status & O_ACCMODE == O_RDONLY else {
            throw JournalLeaseError.unsafeMetadata
        }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
    }
}

final class ServiceReleaseActivityToken: OwnedReleaseActivity {
    private let barrier: ServiceReleaseActivityBarrier
    private let id: UUID
    fileprivate init(barrier: ServiceReleaseActivityBarrier, id: UUID) { self.barrier = barrier; self.id = id }
    func validate() throws { try barrier.validate(id) }
    func withSharedDescriptorForSpawn<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        try barrier.withSharedDescriptorForSpawn(id, body)
    }
    func close() { barrier.release(id) }
    deinit { close() }
}
