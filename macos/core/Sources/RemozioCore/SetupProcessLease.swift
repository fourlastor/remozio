import Darwin
import Foundation

/// Holds one Setup process until its work and cleanup have joined. This lease grants no mutation authority.
final class SetupProcessLease: @unchecked Sendable {
    static let fileName = "setup-process.lock"
    static let directoryPath = URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).deletingLastPathComponent().path
    private let lock = NSLock(), processID = getpid()
    private let directory: ReleaseDestinationLease
    private let owner: uid_t
    private var descriptor: Int32 = -1
    private var retired = false

    /// The service calls this after it validates its fixed Setup identity, before opening the machine store.
    static func acquire() throws -> SetupProcessLease {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try .init(directory: ReleaseDestinationLease.acquire(path: directoryPath), owner: 0)
    }
    static func openOwned(directory: ReleaseDestinationLease) throws -> SetupProcessLease {
        try RuntimeMaintenanceOwnedControl.require()
        return try .init(directory: directory, owner: getuid())
    }
    private init(directory: ReleaseDestinationLease, owner: uid_t) throws {
        self.directory = directory; self.owner = owner
        var opened: Int32 = -1
        do {
            descriptor = try directory.withDirectory { parent in
                guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
                let flags = O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
                var fd = openat(parent, Self.fileName, flags | O_CREAT | O_EXCL, 0o600)
                if fd < 0, errno == EEXIST { fd = openat(parent, Self.fileName, flags) }
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                opened = fd
                try Self.inspect(fd, parent: parent, owner: owner)
                guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                    if errno == EWOULDBLOCK { throw JournalLeaseError.busy }
                    throw JournalLeaseError.system(errno)
                }
                try Self.inspect(fd, parent: parent, owner: owner)
                return fd
            }
        } catch {
            if opened >= 0 { _ = Darwin.close(opened) }
            directory.close(); throw error
        }
    }
    func validate() throws {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            guard !retired, descriptor >= 0 else { throw JournalLeaseError.invalidated }
            do {
                guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
                try directory.withDirectory { try Self.inspect(descriptor, parent: $0, owner: owner) }
            } catch { retired = true; throw error }
        }
    }
    func close() {
        guard getpid() == processID else { return }
        lock.withLock {
            guard descriptor >= 0 else { return }
            // Close only this description. LOCK_UN would also unlock an inherited or duplicated description.
            _ = Darwin.close(descriptor); descriptor = -1; retired = true; directory.close()
        }
    }
    deinit { close() }
    private static func inspect(_ fd: Int32, parent: Int32, owner: uid_t) throws {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, fileName, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
        guard held.st_size == 0 else { throw JournalLeaseError.unsafeMetadata }
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, flags & FD_CLOEXEC != 0 else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
    }
}
