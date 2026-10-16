import Darwin
import Foundation

public enum SetupDatabaseKind: Sendable {
    case journal, continuity, installation
    var fileName: String {
        switch self {
        case .journal: "journal.sqlite"
        case .continuity: "continuity.sqlite"
        case .installation: "installation.sqlite"
        }
    }
}

/// Observed provisioning only. This result grants no initialization, recovery or action authority.
public struct SetupDatabaseFiles: Sendable, CustomStringConvertible {
    public let kind: SetupDatabaseKind
    public let createdFileNames: Set<String>
    public var description: String { "SetupDatabaseFiles(redacted)" }
}

/// Typed Root storage preparation for an administrator-authorized setup host.
/// Preserve every existing file; storage readers must independently check its scope and schema.
public enum SetupDatabaseFileProvisioning {
    public static func prepare(directoryPath: String, kind: SetupDatabaseKind) throws -> SetupDatabaseFiles {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try validatePathBudget(directoryPath, kind: kind)
        let directory = try ProtectedSetupDirectory.createOrOpen(path: directoryPath)
        defer { directory.close() }
        return try prepare(directory: directory, kind: kind, owner: 0)
    }

    enum Stage: Equatable { case prepared(String), published(String) }
    // Ordinary-owner fixture seam. Production fixes Root ownership and exposes no fault callback.
    static func prepare(directory: ProtectedSetupDirectory, kind: SetupDatabaseKind, owner: uid_t,
                        didStage: (Stage) throws -> Void = { _ in }) throws -> SetupDatabaseFiles {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        try validatePathBudget(directory.path, kind: kind)
        return try directory.withPrivateDirectory { parent in
            var created = Set<String>()
            let lock = try openOrCreate(parent: parent, name: "writer.lock", owner: owner,
                validateDirectory: directory.validate, didStage: didStage)
            defer { _ = Darwin.close(lock.fd) }
            if lock.created { created.insert("writer.lock") }
            guard flock(lock.fd, LOCK_EX | LOCK_NB) == 0 else {
                throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno)
            }
            _ = try inspect(lock.fd, parent: parent, name: "writer.lock", owner: owner)
            try directory.validate()
            if kind == .installation {
                var existing = stat()
                let databaseExists = fstatat(parent, kind.fileName, &existing, AT_SYMLINK_NOFOLLOW) == 0
                if !databaseExists, errno != ENOENT { throw JournalLeaseError.system(errno) }
                // Publish before the database. A restart can retain it, but cannot recreate a lost live inode.
                let activity = try openOrCreate(parent: parent, name: ReleaseActivityBarrier.fileName, owner: owner,
                    validateDirectory: directory.validate, didStage: didStage, createIfMissing: !databaseExists)
                defer { _ = Darwin.close(activity.fd) }
                guard try inspect(activity.fd, parent: parent, name: ReleaseActivityBarrier.fileName, owner: owner).st_size == 0 else {
                    throw JournalLeaseError.identityChanged
                }
                if activity.created { created.insert(ReleaseActivityBarrier.fileName) }
            }
            let database = try openOrCreate(parent: parent, name: kind.fileName, owner: owner,
                validateDirectory: directory.validate, didStage: didStage)
            defer { _ = Darwin.close(database.fd) }
            if database.created { created.insert(kind.fileName) }
            _ = try inspect(lock.fd, parent: parent, name: "writer.lock", owner: owner)
            _ = try inspect(database.fd, parent: parent, name: kind.fileName, owner: owner)
            try directory.validate()
            return SetupDatabaseFiles(kind: kind, createdFileNames: created)
        }
    }

    private static func validatePathBudget(_ directoryPath: String, kind: SetupDatabaseKind) throws {
        guard directoryPath.utf8.count + 1 + kind.fileName.utf8.count < Int(PATH_MAX) else { throw JournalLeaseError.invalidPath }
    }
    private static func inspect(_ fd: Int32, parent: Int32, name: String, owner: uid_t) throws -> stat {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
        return held
    }
    private static func synchronize(_ fd: Int32) throws {
        guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
    }
    private static func openOrCreate(parent: Int32, name: String, owner: uid_t,
        validateDirectory: () throws -> Void, didStage: (Stage) throws -> Void,
        createIfMissing: Bool = true) throws -> (fd: Int32, created: Bool) {
        try validateDirectory()
        let existing = openat(parent, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if existing >= 0 {
            do {
                _ = try inspect(existing, parent: parent, name: name, owner: owner)
                try synchronize(parent); try validateDirectory()
                return (existing, false)
            } catch { _ = Darwin.close(existing); throw error }
        }
        guard errno == ENOENT, createIfMissing else { throw JournalLeaseError.system(errno) }
        let staging = ".remozio-file-" + UUID().uuidString
        let fd = openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        do {
            var held = stat(), named = stat()
            guard fstat(fd, &held) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            guard held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_uid == owner,
                  held.st_mode & S_IFMT == S_IFREG, held.st_nlink == 1, held.st_size == 0 else {
                throw JournalLeaseError.identityChanged
            }
            try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
            guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            guard acl_set_fd(fd, acl) == 0, fchmod(fd, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            _ = try inspect(fd, parent: parent, name: staging, owner: owner)
            try synchronize(fd); try synchronize(parent); try validateDirectory()
            try didStage(.prepared(name)); try validateDirectory()
            guard try inspect(fd, parent: parent, name: staging, owner: owner).st_size == 0 else {
                throw JournalLeaseError.identityChanged
            }
            guard renameatx_np(parent, staging, parent, name, UInt32(RENAME_EXCL)) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            try didStage(.published(name)); try validateDirectory(); try synchronize(parent); try validateDirectory()
            _ = try inspect(fd, parent: parent, name: name, owner: owner)
            return (fd, true)
        } catch { _ = Darwin.close(fd); throw error }
    }
}
