import Darwin
import Foundation

public enum AdministrativeSetupPublicationError: Error, Equatable {
    case conflictingConfiguration, changedInventory
}

/// Publication evidence only. It proves no service registration, account enrollment or runtime health.
public enum AdministrativeSetupPublicationResult: Equatable, Sendable { case created, retained }

/// Publishes the fixed private setup file after checking the retained inventory and protected signed release.
public enum AdministrativeSetupPublication {
    public static func publish(_ configuration: AdministrativeSetupConfiguration) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let store = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
        defer { try? store.close() }
        guard let inventory = try store.loadInventory() else { throw AdministrativeSetupPublicationError.changedInventory }
        let bundle = URL(fileURLWithPath: inventory.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        guard let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw AdministrativeSetupServiceError.invalidConfiguration
        }
        func verify() throws {
            guard try store.loadInventory() == inventory else { throw AdministrativeSetupPublicationError.changedInventory }
            _ = try placement.inspectCopiedTree(name: bundle.lastPathComponent)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try configuration.validate(inventory: inventory, release: release)
            try placement.validate()
        }
        try verify()
        let parent = URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).deletingLastPathComponent().path
        let directory = try ProtectedSetupDirectory.createOrOpen(path: parent, visibility: .sharedMetadata)
        defer { directory.close() }
        return try publish(configuration, directory: directory, owner: 0, verify: verify)
    }

    enum Stage { case staged, published }
    // Ordinary-owner fixtures exercise real file operations without claiming Root or native signing evidence.
    static func publish(_ configuration: AdministrativeSetupConfiguration, directory: ProtectedSetupDirectory, owner: uid_t,
                        verify: () throws -> Void = {}, didStage: (Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try publish(configuration.canonicalBytes, file: .startup, directory: directory, owner: owner,
                    verify: verify, didStage: didStage)
    }

    enum File {
        case startup, bootstrapIntent, bootstrapCompletion
        var name: String {
            switch self {
            case .startup: URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).lastPathComponent
            case .bootstrapIntent: "bootstrap-intent.cbor"
            case .bootstrapCompletion: "bootstrap-complete.cbor"
            }
        }
    }
    // Only typed setup operations select these fixed names. No public arbitrary-file publisher exists.
    static func publish(_ bytes: Data, file: File, directory: ProtectedSetupDirectory, owner: uid_t,
                        verify: () throws -> Void = {}, didStage: (Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        guard getuid() == owner, geteuid() == owner, !bytes.isEmpty,
              bytes.count <= ProtectedServiceConfiguration.maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        let name = file.name
        return try directory.withDirectory { parent in
            try verify()
            var existing = stat()
            if fstatat(parent, name, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
                try match(bytes, name: name, directory: directory, owner: owner)
                try synchronizeRetained(parent: parent, name: name, bytes: bytes, owner: owner)
                guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
                try match(bytes, name: name, directory: directory, owner: owner)
                try verify(); try directory.validate()
                return .retained
            }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            let staging = ".remozio-setup-" + UUID().uuidString
            let fd = openat(parent, staging, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            var published = false
            defer {
                if !published {
                    var held = stat(), named = stat()
                    if fstat(fd, &held) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0,
                       held.st_dev == named.st_dev, held.st_ino == named.st_ino {
                        _ = unlinkat(parent, staging, 0)
                    }
                }
                _ = Darwin.close(fd)
            }
            var initial = stat()
            guard fstat(fd, &initial) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(fd, initial, directory: false, privateObject: false, owner: owner, ancestorOwner: owner)
            guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            guard acl_set_fd(fd, acl) == 0, fchmod(fd, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
            var offset = 0
            while offset < bytes.count {
                let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw JournalLeaseError.system(count == 0 ? EIO : errno) }
                offset += count
            }
            guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
            var staged = stat(), named = stat()
            guard fstat(fd, &staged) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            guard staged.st_dev == named.st_dev, staged.st_ino == named.st_ino,
                  staged.st_size == bytes.count else { throw JournalLeaseError.identityChanged }
            try ProtectedStorageMetadata.validate(fd, staged, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
            try directory.validate(); try didStage(.staged); try verify(); try directory.validate()
            try validateNamedFile(fd: fd, parent: parent, name: staging, bytes: bytes, owner: owner)
            guard renameatx_np(parent, staging, parent, name, UInt32(RENAME_EXCL)) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            published = true
            try didStage(.published)
            guard fsync(parent) == 0 else { throw JournalLeaseError.system(errno) }
            try match(bytes, name: name, directory: directory, owner: owner)
            try verify(); try directory.validate()
            return .created
        }
    }

    private static func synchronizeRetained(parent: Int32, name: String, bytes: Data, owner: uid_t) throws {
        let fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(fd) }
        try validateNamedFile(fd: fd, parent: parent, name: name, bytes: bytes, owner: owner)
        guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
        try validateNamedFile(fd: fd, parent: parent, name: name, bytes: bytes, owner: owner)
    }

    private static func validateNamedFile(fd: Int32, parent: Int32, name: String, bytes: Data, owner: uid_t) throws {
        var before = stat(), named = stat()
        guard fstat(fd, &before) == 0, fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        guard before.st_dev == named.st_dev, before.st_ino == named.st_ino,
              before.st_size == bytes.count else { throw JournalLeaseError.identityChanged }
        try ProtectedStorageMetadata.validate(fd, before, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
        var retained = Data(count: bytes.count), offset = 0
        while offset < retained.count {
            let count = retained.withUnsafeMutableBytes { pread(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset, off_t(offset)) }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw JournalLeaseError.identityChanged }
            offset += count
        }
        var after = stat()
        guard retained == bytes, fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw JournalLeaseError.identityChanged
        }
        guard fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == after.st_dev, named.st_ino == after.st_ino else { throw JournalLeaseError.identityChanged }
        try ProtectedStorageMetadata.validate(fd, after, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
    }

    private static func match(_ bytes: Data, name: String, directory: ProtectedSetupDirectory, owner: uid_t) throws {
        try directory.validate()
        let retained = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: name, owner: owner)
        guard retained == bytes else { throw AdministrativeSetupPublicationError.conflictingConfiguration }
        try directory.validate()
    }
}
