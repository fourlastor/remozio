import Darwin
import Foundation

/// Creates only missing, unactivated role locks. The setup owner retains their identities before publishing host metadata.
/// Existing files are never rewritten or repaired. Known active readers do not block validation of retained identities.
enum ServiceReleaseActivityFileProvisioning {
    enum Mode { case createIfAbsent, requireExisting }
    enum Stage { case staged(ServiceAccountRole), published(ServiceAccountRole) }
    struct Result: Equatable {
        let identities: [ServiceAccountRole: PreparationFileIdentity]
        let createdRoles: Set<ServiceAccountRole>
    }
    static func prepare(account: AccountPreparationIntent, services: ServiceAccountPlan, mode: Mode,
                        expected: [ServiceAccountRole: PreparationFileIdentity]?,
                        verifyCurrent: @escaping () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let directory = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
        func verify() throws {
            try verifyCurrent(); try services.validate(account: account)
            for claim in services.claims { try directory.validateGroup(claim); try directory.validateUser(claim, ownerUID: account.ownerUID) }
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let parent = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { parent.close() }
        let groups = Dictionary(uniqueKeysWithValues: services.claims.map { ($0.role, $0.number) })
        return try prepare(parent: parent, owner: 0, groups: groups, mode: mode, expected: expected, verifyCurrent: verify)
    }
    // Same-owner fixtures prove publication mechanics, not Root ownership transfer or dedicated-group access.
    static func prepare(parent: ProtectedSetupDirectory, owner: uid_t, groups: [ServiceAccountRole: gid_t], mode: Mode,
                        expected: [ServiceAccountRole: PreparationFileIdentity]?, verifyCurrent: @escaping () throws -> Void,
                        didStage: (Stage) throws -> Void = { _ in }) throws -> Result {
        guard getuid() == owner, geteuid() == owner, Set(groups.keys) == Set(ServiceAccountPlan.roles),
              groups.values.allSatisfy({ $0 > 0 && $0 < UInt32.max && $0 != 80 }),
              expected == nil || Set(expected!.keys) == Set(ServiceAccountPlan.roles) else { throw GatewayPreparationError.invalidRecord }
        let processID = getpid()
        func verify() throws {
            guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            try verifyCurrent(); try parent.validate()
        }
        return try parent.withSharedDirectory { parentFD in
            try verify()
            var identities: [ServiceAccountRole: PreparationFileIdentity] = [:], created = Set<ServiceAccountRole>()
            for role in ServiceAccountPlan.roles {
                let group = groups[role]!, name = ServiceReleaseActivityBarrier.fileName(role)
                let fd = openat(parentFD, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                if fd >= 0 {
                    defer { _ = Darwin.close(fd) }
                    let identity = try inspect(fd, parent: parentFD, name: name, owner: owner, group: group)
                    if let pinned = expected?[role] {
                        guard identity == pinned else { throw JournalLeaseError.identityChanged }
                    } else {
                        // Unknown initial files cannot be adopted while another process holds a scope.
                        try exclusive(fd)
                    }
                    try verify(); try synchronize(fd); try synchronize(parentFD)
                    guard try inspect(fd, parent: parentFD, name: name, owner: owner, group: group) == identity else {
                        throw JournalLeaseError.identityChanged
                    }
                    identities[role] = identity; continue
                }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                guard mode == .createIfAbsent, expected == nil else { throw GatewayPreparationError.missingMaterial }
                let staging = ".remozio-service-activity-" + UUID().uuidString
                let staged = openat(parentFD, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
                guard staged >= 0 else { throw JournalLeaseError.system(errno) }
                var published = false
                defer {
                    if !published {
                        var held = stat(), named = stat()
                        if fstat(staged, &held) == 0, fstatat(parentFD, staging, &named, AT_SYMLINK_NOFOLLOW) == 0,
                           held.st_dev == named.st_dev, held.st_ino == named.st_ino { _ = unlinkat(parentFD, staging, 0) }
                    }
                    _ = Darwin.close(staged)
                }
                var initial = stat()
                guard fstat(staged, &initial) == 0 else { throw JournalLeaseError.system(errno) }
                try ProtectedStorageMetadata.validate(staged, initial, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
                guard initial.st_size == 0 else { throw JournalLeaseError.identityChanged }
                guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
                defer { acl_free(UnsafeMutableRawPointer(acl)) }
                guard acl_set_fd(staged, acl) == 0 else { throw JournalLeaseError.system(errno) }
                if initial.st_gid != group { guard fchown(staged, owner, group) == 0 else { throw JournalLeaseError.system(errno) } }
                guard fchmod(staged, 0o440) == 0 else { throw JournalLeaseError.system(errno) }
                let identity = try inspect(staged, parent: parentFD, name: staging, owner: owner, group: group)
                try exclusive(staged); try synchronize(staged); try verify(); try didStage(.staged(role)); try verify()
                guard try inspect(staged, parent: parentFD, name: staging, owner: owner, group: group) == identity else {
                    throw JournalLeaseError.identityChanged
                }
                guard renameatx_np(parentFD, staging, parentFD, name, UInt32(RENAME_EXCL)) == 0 else { throw JournalLeaseError.system(errno) }
                published = true; try didStage(.published(role)); try verify(); try synchronize(parentFD)
                guard try inspect(staged, parent: parentFD, name: name, owner: owner, group: group) == identity else {
                    throw JournalLeaseError.identityChanged
                }
                identities[role] = identity; created.insert(role)
            }
            try verify()
            // Recheck the complete selection after the second role, including an earlier published role.
            for role in ServiceAccountPlan.roles {
                let fd = openat(parentFD, ServiceReleaseActivityBarrier.fileName(role), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                defer { _ = Darwin.close(fd) }
                guard try inspect(fd, parent: parentFD, name: ServiceReleaseActivityBarrier.fileName(role), owner: owner,
                                  group: groups[role]!) == identities[role] else { throw JournalLeaseError.identityChanged }
            }
            try verify(); return .init(identities: identities, createdRoles: created)
        }
    }
    private static func inspect(_ fd: Int32, parent: Int32, name: String, owner: uid_t, group: gid_t) throws -> PreparationFileIdentity {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
        guard held.st_gid == group, held.st_mode & 0o7777 == 0o440, held.st_size == 0 else { throw JournalLeaseError.unsafeMetadata }
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0, flags & FD_CLOEXEC != 0 else { throw JournalLeaseError.unsafeMetadata }
        try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
        return .init(device: UInt32(bitPattern: held.st_dev), inode: held.st_ino)
    }
    private static func exclusive(_ fd: Int32) throws {
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno) }
    }
    private static func synchronize(_ fd: Int32) throws { guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) } }
}
