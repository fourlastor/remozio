import Darwin
import Foundation

enum ReleaseActivityError: Error, Equatable { case busy }

/// Coordinates Root activity across independent processes. This does not authorize release activation.
/// Installed callers open the existing machine file. Only fresh storage provisioning creates it.
public final class ReleaseActivityBarrier: @unchecked Sendable {
    static let fileName = "activity.lock"
    private enum Mode { case shared, exclusive }
    private let lock = NSLock()
    private let directory: ReleaseDestinationLease
    private let owner: uid_t
    private let processID = getpid()
    private let baseline: Int32
    private var active: Int32 = -1
    private var mode: Mode?
    private var holders = Set<UUID>()
    private var retired = false

    public static func open(machineDirectory: String) throws -> ReleaseActivityBarrier {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(directory: ReleaseDestinationLease.acquire(path: machineDirectory), owner: 0)
    }

    // Same-owner fixture seam. Production fixes both the directory ancestry and ownership to Root.
    init(directory: ReleaseDestinationLease, owner: uid_t) throws {
        self.directory = directory; self.owner = owner
        var opened: Int32 = -1
        do { baseline = try directory.withDirectory { parent in
            let fd = openat(parent, Self.fileName, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            opened = fd
            try Self.inspect(fd, parent: parent, owner: owner); return fd
        } } catch { if opened >= 0 { _ = Darwin.close(opened) }; throw error }
    }
    deinit {
        if active >= 0 { _ = Darwin.close(active) }
        _ = Darwin.close(baseline)
        directory.close()
    }

    func acquireShared() throws -> ReleaseActivityToken { try acquire(.shared) }
    // A future installer must retain this token through its entire validated activation transaction.
    // Obtaining it alone does not establish that every release role participates in this barrier.
    func acquireExclusive() throws -> ReleaseActivityToken { try acquire(.exclusive) }

    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock { try validateLocked() }
    }

    private func acquire(_ requested: Mode) throws -> ReleaseActivityToken {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        return try lock.withLock {
            try validateLocked()
            // Exclusive tokens never share their ownership with a second caller, including this process.
            guard holders.isEmpty || (mode == .shared && requested == .shared) else { throw ReleaseActivityError.busy }
            if holders.isEmpty {
                var opened: Int32 = -1
                let fd: Int32
                do { fd = try directory.withDirectory { parent in
                    let fd = openat(parent, Self.fileName, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                    guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                    opened = fd
                    try Self.inspect(fd, parent: parent, owner: owner, matching: baseline)
                    let operation = requested == .shared ? LOCK_SH : LOCK_EX
                    guard flock(fd, operation | LOCK_NB) == 0 else {
                        if errno == EWOULDBLOCK { throw ReleaseActivityError.busy }
                        throw JournalLeaseError.system(errno)
                    }
                    try Self.inspect(fd, parent: parent, owner: owner, matching: baseline)
                    return fd
                } } catch { if opened >= 0 { _ = Darwin.close(opened) }; throw error }
                active = fd; mode = requested
            }
            let id = UUID(); holders.insert(id)
            return ReleaseActivityToken(barrier: self, id: id)
        }
    }

    fileprivate func validate(_ id: UUID) throws {
        guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
        try lock.withLock {
            guard holders.contains(id) else { throw JournalLeaseError.invalidated }
            try validateLocked()
        }
    }
    fileprivate func release(_ id: UUID) {
        guard getpid() == processID else { return }
        lock.withLock {
            guard holders.remove(id) != nil, holders.isEmpty else { return }
            // Never LOCK_UN: a fork or dup shares the same open file description.
            _ = Darwin.close(active); active = -1; mode = nil
        }
    }
    private func validateLocked() throws {
        guard !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            try directory.withDirectory { parent in
                try Self.inspect(baseline, parent: parent, owner: owner)
                if active >= 0 { try Self.inspect(active, parent: parent, owner: owner, matching: baseline) }
            }
        } catch {
            // Keep an existing kernel lock until its real owners finish cleanup, even after retirement.
            retired = true; throw error
        }
    }
    private static func inspect(_ fd: Int32, parent: Int32, owner: uid_t, matching: Int32? = nil) throws {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, fileName, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_size == 0 else {
            throw JournalLeaseError.identityChanged
        }
        if let matching {
            var original = stat()
            guard fstat(matching, &original) == 0 else { throw JournalLeaseError.system(errno) }
            guard original.st_dev == held.st_dev, original.st_ino == held.st_ino else { throw JournalLeaseError.identityChanged }
        }
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, flags & FD_CLOEXEC != 0 else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
    }
}

/// One independently releasable activity reference. Closing a token twice cannot release another owner.
final class ReleaseActivityToken: Sendable {
    private let barrier: ReleaseActivityBarrier
    private let id: UUID
    fileprivate init(barrier: ReleaseActivityBarrier, id: UUID) { self.barrier = barrier; self.id = id }
    func validate() throws { try barrier.validate(id) }
    func close() { barrier.release(id) }
    deinit { close() }
}
