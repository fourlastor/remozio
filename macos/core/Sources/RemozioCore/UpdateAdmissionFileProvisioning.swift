import Darwin
import Foundation

/// Provisions empty lock files during an existing idle boundary. This result grants no activation or admission authority.
/// The setup owner must retain the exact identities before publishing runtime metadata.
enum UpdateAdmissionFileProvisioning {
    enum Mode { case createIfAbsent, requireExisting }
    enum Stage { case staged(UpdateAdmissionScope), published(UpdateAdmissionScope) }
    struct Result: Equatable, Sendable {
        let identities: [UpdateAdmissionScope: PreparationFileIdentity]
        let createdScopes: Set<UpdateAdmissionScope>
    }

    static func prepare(machineDirectory: String, accountID: Data, activity: ReleaseActivityToken,
        mode: Mode, expected: [UpdateAdmissionScope: PreparationFileIdentity]?,
        verifyCurrent: @escaping () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let directory = try ReleaseDestinationLease.acquire(path: machineDirectory)
        defer { directory.close() }
        return try prepare(directory: directory, owner: 0, accountID: accountID, activity: activity,
            mode: mode, expected: expected, verifyCurrent: verifyCurrent)
    }

    // Same-owner fixtures exercise the actual files. They cannot grant Root installation authority.
    static func prepare(directory: ReleaseDestinationLease, owner: uid_t, accountID: Data, activity: ReleaseActivityToken,
        mode: Mode, expected: [UpdateAdmissionScope: PreparationFileIdentity]?,
        verifyCurrent: @escaping () throws -> Void, didStage: (Stage) throws -> Void = { _ in }) throws -> Result {
        let scopes: [UpdateAdmissionScope] = [.machine, .account(accountID)]
        let names = try Dictionary(uniqueKeysWithValues: scopes.map { ($0, try $0.fileName) })
        guard getuid() == owner, geteuid() == owner,
              expected == nil || Set(expected!.keys).isSubset(of: Set(scopes)) else {
            throw UpdateAdmissionProvisioningError.invalidScope
        }
        let processID = getpid()
        func verify() throws {
            guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            // The caller check runs first, so a token it closes is detected before the next side effect.
            try verifyCurrent(); try activity.validateExclusive(in: directory); try directory.validate()
        }
        try verify()
        // The loan keeps the exclusive lock through publication even if the token closes concurrently.
        return try activity.withExclusiveLoan(in: directory) { try directory.withDirectory { parent in
            var identities: [UpdateAdmissionScope: PreparationFileIdentity] = [:], created = Set<UpdateAdmissionScope>()
            for scope in scopes {
                let name = names[scope]!
                let fd = openat(parent, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                if fd >= 0 {
                    defer { _ = Darwin.close(fd) }
                    let identity = try inspect(fd, parent: parent, name: name, owner: owner)
                    if let pinned = expected?[scope] {
                        guard pinned == identity else { throw JournalLeaseError.identityChanged }
                    } else {
                        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                            throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno)
                        }
                    }
                    try verify(); try synchronize(fd); try synchronize(parent)
                    guard try inspect(fd, parent: parent, name: name, owner: owner) == identity else { throw JournalLeaseError.identityChanged }
                    identities[scope] = identity; continue
                }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                guard mode == .createIfAbsent, expected?[scope] == nil else { throw UpdateAdmissionProvisioningError.missingFile }
                let staging = ".remozio-update-admission-" + UUID().uuidString
                let staged = openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
                guard staged >= 0 else { throw JournalLeaseError.system(errno) }
                var published = false
                defer {
                    if !published {
                        var held = stat(), named = stat()
                        if fstat(staged, &held) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0,
                           held.st_dev == named.st_dev, held.st_ino == named.st_ino { _ = unlinkat(parent, staging, 0) }
                    }
                    _ = Darwin.close(staged)
                }
                guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
                defer { acl_free(UnsafeMutableRawPointer(acl)) }
                guard acl_set_fd(staged, acl) == 0 else { throw JournalLeaseError.system(errno) }
                let identity = try inspect(staged, parent: parent, name: staging, owner: owner)
                guard flock(staged, LOCK_EX | LOCK_NB) == 0 else { throw JournalLeaseError.system(errno) }
                try synchronize(staged); try verify(); try didStage(.staged(scope)); try verify()
                guard try inspect(staged, parent: parent, name: staging, owner: owner) == identity else { throw JournalLeaseError.identityChanged }
                guard renameatx_np(parent, staging, parent, name, UInt32(RENAME_EXCL)) == 0 else { throw JournalLeaseError.system(errno) }
                published = true; try synchronize(parent); try didStage(.published(scope)); try verify()
                guard try inspect(staged, parent: parent, name: name, owner: owner) == identity else { throw JournalLeaseError.identityChanged }
                identities[scope] = identity; created.insert(scope)
            }
            for scope in scopes {
                let name = names[scope]!, fd = openat(parent, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                defer { _ = Darwin.close(fd) }
                guard try inspect(fd, parent: parent, name: name, owner: owner) == identities[scope] else {
                    throw JournalLeaseError.identityChanged
                }
            }
            guard identities[.machine] != identities[.account(accountID)] else { throw JournalLeaseError.identityChanged }
            try verify(); return .init(identities: identities, createdScopes: created)
        } }
    }

    private static func inspect(_ fd: Int32, parent: Int32, name: String, owner: uid_t) throws -> PreparationFileIdentity {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino, held.st_size == 0,
              held.st_mode & 0o7777 == 0o600 else { throw JournalLeaseError.unsafeMetadata }
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, flags & FD_CLOEXEC != 0 else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
        return .init(device: UInt32(bitPattern: held.st_dev), inode: held.st_ino)
    }
    private static func synchronize(_ fd: Int32) throws { guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) } }
}
