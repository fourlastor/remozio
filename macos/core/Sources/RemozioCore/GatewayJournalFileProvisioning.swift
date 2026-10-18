import Darwin
import Foundation

/// File identities only. This value does not prove journal schema, initialization or current gateway health.
struct GatewayJournalFileIdentity: Equatable {
    let directory: ProtectedStorageLease.DirectoryIdentity
    let writer: ProtectedStorageLease.DirectoryIdentity
    let database: ProtectedStorageLease.DirectoryIdentity
}

/// Publishes an empty gateway directory as one unit. Only the gateway process may subsequently open its SQLite journal.
/// The setup host must retain these identities before initialization and must authorize creation through protected setup state.
enum GatewayJournalFileProvisioning {
    enum Mode { case createIfAbsent, requireExisting }
    enum Stage { case staged, published }
    struct Result: Equatable { let identity: GatewayJournalFileIdentity; let created: Bool }
    private static let directoryName = "Gateway"
    private static let writerName = "writer.lock"
    private static let databaseName = "gateway.sqlite"

    static func prepare(account: AccountPreparationIntent, services: ServiceAccountPlan, mode: Mode,
                        expected: GatewayJournalFileIdentity?, verifyCurrent: () throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try services.validate(account: account); try verifyCurrent()
        guard let claim = services.claims.first(where: { $0.role == .gateway }) else { throw GatewayPreparationError.incomplete }
        let accounts = try NativeServiceAccountDirectory(accountID: account.accountID, ownerUID: account.ownerUID)
        func verify() throws {
            try verifyCurrent(); try services.validate(account: account)
            try accounts.validateGroup(claim); try accounts.validateUser(claim, ownerUID: account.ownerUID)
        }
        try verify()
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        let parent = try ProtectedSetupDirectory(anchor: "/", relativePath: String(paths.serviceDirectory.dropFirst()),
            owner: 0, visibility: .sharedMetadata, createIfMissing: false)
        defer { parent.close() }
        return try prepare(parent: parent, processOwner: 0, serviceUID: claim.number, serviceGID: claim.number,
            mode: mode, expected: expected, verifyCurrent: verify)
    }

    // Ordinary-owner fixtures prove file mechanics, not Root ownership transfer or native service account isolation.
    static func prepare(parent: ProtectedSetupDirectory, processOwner: uid_t, serviceUID: uid_t, serviceGID: gid_t,
                        mode: Mode, expected: GatewayJournalFileIdentity?, verifyCurrent: () throws -> Void,
                        didStage: (Stage) throws -> Void = { _ in }) throws -> Result {
        guard getuid() == processOwner, geteuid() == processOwner,
              serviceUID > 0, serviceUID < UInt32.max, serviceGID > 0, serviceGID < UInt32.max,
              parent.path.utf8.count + directoryName.utf8.count + databaseName.utf8.count + 3 < Int(PATH_MAX) else {
            throw JournalLeaseError.unsafeMetadata
        }
        let processID = getpid()
        func verify() throws {
            guard getpid() == processID, getuid() == processOwner, geteuid() == processOwner else { throw JournalLeaseError.unsafeMetadata }
            try verifyCurrent(); try parent.validate()
        }
        return try parent.withSharedDirectory { parentFD in
            try verify()
            let retained = openat(parentFD, directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if retained >= 0 {
                defer { _ = Darwin.close(retained) }
                return try inspectExisting(parent: parentFD, directory: retained, serviceUID: serviceUID, serviceGID: serviceGID,
                    processOwner: processOwner, expected: expected, verify: verify)
            }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            guard mode == .createIfAbsent, expected == nil else { throw GatewayPreparationError.missingMaterial }
            let staging = ".remozio-gateway-" + UUID().uuidString
            guard mkdirat(parentFD, staging, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            let directory = openat(parentFD, staging, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else { throw JournalLeaseError.system(errno) }
            defer { _ = Darwin.close(directory) }
            // Retain interrupted stages intact. Only newly created objects receive ownership or permission changes.
            var initial = stat()
            guard fstat(directory, &initial) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(directory, initial, directory: true, privateObject: false,
                owner: processOwner, ancestorOwner: processOwner)
            try clearACL(directory); guard fchmod(directory, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            let writer = try createFile(parent: directory, name: writerName, serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner)
            defer { _ = Darwin.close(writer) }
            try lock(writer)
            let database = try createFile(parent: directory, name: databaseName, serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner)
            defer { _ = Darwin.close(database) }
            try setOwner(directory, uid: serviceUID, gid: serviceGID)
            guard fchmod(directory, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            let identity = try inspect(parent: parentFD, name: staging, directory: directory, writer: writer, database: database,
                serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner, requireEmpty: true)
            try synchronize(directory); try synchronize(parentFD); try verify()
            try didStage(.staged); try verify()
            guard try inspect(parent: parentFD, name: staging, directory: directory, writer: writer, database: database,
                serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner, requireEmpty: true) == identity else {
                throw JournalLeaseError.identityChanged
            }
            guard renameatx_np(parentFD, staging, parentFD, directoryName, UInt32(RENAME_EXCL)) == 0 else { throw JournalLeaseError.system(errno) }
            try didStage(.published); try verify(); try synchronize(parentFD)
            guard try inspect(parent: parentFD, name: directoryName, directory: directory, writer: writer, database: database,
                serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner, requireEmpty: true) == identity else {
                throw JournalLeaseError.identityChanged
            }
            try verify(); return Result(identity: identity, created: true)
        }
    }
    private static func inspectExisting(parent: Int32, directory: Int32, serviceUID: uid_t, serviceGID: gid_t,
                                        processOwner: uid_t, expected: GatewayJournalFileIdentity?, verify: () throws -> Void) throws -> Result {
        _ = try metadata(directory, parent: parent, name: directoryName, directory: true, owner: serviceUID, group: serviceGID, ancestor: processOwner)
        let writer = openat(directory, writerName, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard writer >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(writer) }
        _ = try metadata(writer, parent: directory, name: writerName, directory: false, owner: serviceUID, group: serviceGID, ancestor: processOwner)
        try lock(writer)
        let database = openat(directory, databaseName, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard database >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(database) }
        let identity = try inspect(parent: parent, name: directoryName, directory: directory, writer: writer, database: database,
            serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner, requireEmpty: false)
        if let expected { guard identity == expected else { throw JournalLeaseError.identityChanged } }
        try verify(); try synchronize(directory); try synchronize(parent); try verify()
        guard try inspect(parent: parent, name: directoryName, directory: directory, writer: writer, database: database,
            serviceUID: serviceUID, serviceGID: serviceGID, processOwner: processOwner, requireEmpty: false) == identity else {
            throw JournalLeaseError.identityChanged
        }
        return Result(identity: identity, created: false)
    }
    private static func inspect(parent: Int32, name: String, directory: Int32, writer: Int32, database: Int32,
                                serviceUID: uid_t, serviceGID: gid_t, processOwner: uid_t, requireEmpty: Bool) throws -> GatewayJournalFileIdentity {
        let d = try metadata(directory, parent: parent, name: name, directory: true, owner: serviceUID, group: serviceGID, ancestor: processOwner)
        let w = try metadata(writer, parent: directory, name: writerName, directory: false, owner: serviceUID, group: serviceGID, ancestor: processOwner)
        let b = try metadata(database, parent: directory, name: databaseName, directory: false, owner: serviceUID, group: serviceGID, ancestor: processOwner)
        guard w.st_size == 0, !requireEmpty || b.st_size == 0 else { throw JournalLeaseError.identityChanged }
        return .init(directory: .init(device: d.st_dev, inode: d.st_ino), writer: .init(device: w.st_dev, inode: w.st_ino),
            database: .init(device: b.st_dev, inode: b.st_ino))
    }
    private static func metadata(_ fd: Int32, parent: Int32, name: String, directory: Bool,
                                 owner: uid_t, group: gid_t, ancestor: uid_t) throws -> stat {
        var held = stat(), named = stat()
        guard fstat(fd, &held) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
        guard held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.identityChanged }
        try ProtectedStorageMetadata.validate(fd, held, directory: directory, privateObject: true, owner: owner, ancestorOwner: ancestor)
        guard held.st_gid == group else { throw JournalLeaseError.unsafeMetadata }
        return held
    }
    private static func createFile(parent: Int32, name: String, serviceUID: uid_t, serviceGID: gid_t, processOwner: uid_t) throws -> Int32 {
        let fd = openat(parent, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        do {
            var initial = stat()
            guard fstat(fd, &initial) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(fd, initial, directory: false, privateObject: false, owner: processOwner, ancestorOwner: processOwner)
            guard initial.st_size == 0 else { throw JournalLeaseError.identityChanged }
            try clearACL(fd); try setOwner(fd, uid: serviceUID, gid: serviceGID)
            guard fchmod(fd, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            _ = try metadata(fd, parent: parent, name: name, directory: false, owner: serviceUID, group: serviceGID, ancestor: processOwner)
            try synchronize(fd); return fd
        } catch { _ = Darwin.close(fd); throw error }
    }
    private static func setOwner(_ fd: Int32, uid: uid_t, gid: gid_t) throws {
        var info = stat(); guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
        if info.st_uid != uid || info.st_gid != gid {
            guard fchown(fd, uid, gid) == 0 else { throw JournalLeaseError.system(errno) }
        }
    }
    private static func clearACL(_ fd: Int32) throws {
        guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_set_fd(fd, acl) == 0 else { throw JournalLeaseError.system(errno) }
    }
    private static func synchronize(_ fd: Int32) throws { guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) } }
    private static func lock(_ fd: Int32) throws {
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno) }
    }
}
