import Darwin
import Foundation

public enum PackageBootstrapError: Error, Equatable {
    case invalidProfile, existingApplication, retainedState, wrongRelease, invalidState, shortcutConflict
}

/// Public package pins. The builder obtains these from the verified app, not an installed candidate.
public struct PackageBootstrapProfile: Equatable, Sendable {
    public let teamID: String
    public let setupHash: Data
    public let releaseDigest: Data
    public init(teamID: String, setupHash: Data, releaseDigest: Data) throws {
        guard teamID.utf8.count == 10, teamID.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) }),
              setupHash.count == 20, releaseDigest.count == 32 else { throw PackageBootstrapError.invalidProfile }
        self.teamID = teamID; self.setupHash = setupHash; self.releaseDigest = releaseDigest
    }
    public init(argument: String) throws {
        let parts = argument.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, argument.utf8.count == 116 else { throw PackageBootstrapError.invalidProfile }
        func bytes(_ text: Substring, count: Int) throws -> Data {
            let values = Array(text.utf8)
            guard values.count == count * 2, values.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw PackageBootstrapError.invalidProfile
            }
            func digit(_ value: UInt8) -> UInt8 { value <= 57 ? value - 48 : value - 87 }
            return Data(stride(from: 0, to: values.count, by: 2).map { digit(values[$0]) * 16 + digit(values[$0 + 1]) })
        }
        try self.init(teamID: String(parts[0]), setupHash: bytes(parts[1], count: 20), releaseDigest: bytes(parts[2], count: 32))
    }
    public var argument: String {
        func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
        return teamID + ":" + hex(setupHash) + ":" + hex(releaseDigest)
    }
    func validate(_ release: SignedReleaseEvidence) throws {
        guard try InstallationInventory.digest(release) == releaseDigest,
              release.codeDirectoryHashes[.setupController] == setupHash else { throw PackageBootstrapError.wrongRelease }
    }
}

/// Explicit package operations only. They grant no enrollment, execution or service registration.
public enum PackageBootstrap {
    public enum Plan: String, Equatable, Sendable { case bootstrap, retained }
    private static var sharedPath: String {
        URL(fileURLWithPath: AdministrativeSetupConfiguration.startupPath).deletingLastPathComponent().path
    }
    private static func verifyCaller(_ profile: PackageBootstrapProfile) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let requirement = try XPCPeerPolicy(teamID: profile.teamID, componentIdentifier: "dev.remozio.setup-controller",
            approvedCodeDirectoryHashes: [profile.setupHash], expectedUserID: 0).requirement
        try DynamicCodeValidation.validateSelf(requirement: requirement)
    }
    /// The native package authorization covers this temporary helper and its pinned profile.
    /// This mode does not relax the installed service's protected-path startup checks.
    public static func preparePayload(_ profile: PackageBootstrapProfile) throws {
        try verifyCaller(profile)
        try inspectEntry(parent: "/Applications", owner: 0)
        let shared = try ProtectedSetupDirectory.createOrOpen(path: sharedPath, visibility: .sharedMetadata)
        defer { shared.close() }
        try requireFreshState(shared)
        let appsPath = URL(fileURLWithPath: MachineBootstrap.bundlePath).deletingLastPathComponent().path
        let applications = try ProtectedSetupDirectory.createOrOpen(path: appsPath, visibility: .sharedMetadata)
        defer { applications.close() }
        try preparePayload(shared: shared, applications: applications)
    }
    static func requireFreshState(_ shared: ProtectedSetupDirectory) throws {
        try shared.withDirectory { fd in
            for name in ["Machine", AdministrativeSetupPublication.File.startup.name,
                         AdministrativeSetupPublication.File.bootstrapIntent.name, AdministrativeSetupPublication.File.bootstrapCompletion.name] {
                var info = stat()
                if fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { throw PackageBootstrapError.retainedState }
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            }
        }
    }
    static func preparePayload(shared: ProtectedSetupDirectory, applications: ProtectedSetupDirectory) throws {
        try requireFreshState(shared)
        try applications.withDirectory { fd in
            var info = stat()
            if fstatat(fd, "Remozio.app", &info, AT_SYMLINK_NOFOLLOW) == 0 { throw PackageBootstrapError.existingApplication }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            try shared.validate()
        }
    }
    public static func inspectInstalled(_ profile: PackageBootstrapProfile) throws -> Plan {
        try verifyCaller(profile)
        try inspectEntry(parent: "/Applications", owner: 0)
        return try withInstalled(profile) { shared, release, _ in
            try inspectState(shared: shared, owner: 0, bundlePath: MachineBootstrap.bundlePath,
                machinePath: MachineBootstrap.machineDirectory, release: release)
        }
    }
    private static func withInstalled<T>(_ profile: PackageBootstrapProfile,
                                        body: (ProtectedSetupDirectory, SignedReleaseEvidence, ReleaseDestinationLease) throws -> T) throws -> T {
        let bundle = URL(fileURLWithPath: MachineBootstrap.bundlePath)
        let placement = try ReleaseDestinationLease.acquire(path: bundle.deletingLastPathComponent().path)
        defer { placement.close() }
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        let release = try SignedReleaseInspection.inspect(bundle, teamID: profile.teamID, appIdentifier: "dev.remozio.mac")
        try profile.validate(release)
        let shared = try ProtectedSetupDirectory(anchor: "/", relativePath: String(sharedPath.dropFirst()), owner: 0,
            visibility: .sharedMetadata, createIfMissing: false)
        defer { shared.close() }
        let value = try body(shared, release, placement)
        try shared.validate(); try placement.validate()
        _ = try placement.inspectInstalledApplication(name: bundle.lastPathComponent)
        try profile.validate(SignedReleaseInspection.inspect(bundle, teamID: profile.teamID, appIdentifier: "dev.remozio.mac"))
        return value
    }
    // Ordinary-owner fixtures inspect real private state. They do not establish package authorization or signatures.
    static func inspectState(shared: ProtectedSetupDirectory, owner: uid_t, bundlePath: String,
                             machinePath: String, release: SignedReleaseEvidence) throws -> Plan {
        let intent = try MachineBootstrap.read(.bootstrapIntent, directory: shared, owner: owner)
        let completion = try MachineBootstrap.read(.bootstrapCompletion, directory: shared, owner: owner)
        let startup = try MachineBootstrap.read(.startup, directory: shared, owner: owner)
        guard let intent else {
            guard completion == nil, startup == nil else { throw PackageBootstrapError.invalidState }
            try requireFreshState(shared); return .bootstrap
        }
        let seed = try MachineBootstrap.Seed.decode(intent)
        guard seed.inventory.bundlePath == bundlePath, seed.configuration.machineDirectory == machinePath,
              completion == nil || completion == intent, completion != nil || startup == nil else { throw PackageBootstrapError.invalidState }
        try seed.configuration.validate(inventory: seed.inventory, release: release)
        guard let startup else { return .bootstrap }
        let configuration = try AdministrativeSetupConfiguration.decode(startup)
        guard configuration.machineDirectory == machinePath, configuration.macID == seed.configuration.macID,
              configuration.installationID == seed.configuration.installationID,
              configuration.releaseDigest == seed.configuration.releaseDigest else { throw PackageBootstrapError.invalidState }
        try configuration.validate(release: release)
        let anchor = shared.path
        let relative = String(machinePath.dropFirst(anchor.count + 1))
        guard machinePath.hasPrefix(anchor + "/"), relative == "Machine" else { throw PackageBootstrapError.invalidState }
        let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: owner, createIfMissing: false)
        defer { directory.close() }
        try requireExistingDatabase(directory, owner: owner)
        return .retained
    }
    private static func requireExistingDatabase(_ directory: ProtectedSetupDirectory, owner: uid_t) throws {
        try directory.withPrivateDirectory { parent in
            let fd = openat(parent, "installation.sqlite", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            defer { _ = Darwin.close(fd) }
            var held = stat(), named = stat()
            guard fstat(fd, &held) == 0, fstatat(parent, "installation.sqlite", &named, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            guard held.st_size > 0, held.st_dev == named.st_dev, held.st_ino == named.st_ino else {
                throw PackageBootstrapError.invalidState
            }
            try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: true, owner: owner, ancestorOwner: owner)
        }
    }

    /// Creates a non-authoritative Applications shortcut without replacing any existing entry.
    public static func ensureApplicationEntry(_ profile: PackageBootstrapProfile) throws {
        try verifyCaller(profile)
        try withInstalled(profile) { shared, release, placement in
            guard try inspectState(shared: shared, owner: 0, bundlePath: MachineBootstrap.bundlePath,
                machinePath: MachineBootstrap.machineDirectory, release: release) == .retained else { throw PackageBootstrapError.invalidState }
            try publishEntry(parent: "/Applications", owner: 0, staging: placement)
        }
    }
    // Ordinary-owner fixtures use their protected destination as the staging directory.
    static func publishEntry(parent: String, owner: uid_t) throws {
        guard owner > 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let destination = URL(fileURLWithPath: parent)
        let staging = try ReleaseDestinationLease(anchor: destination.deletingLastPathComponent().path,
            relativeDirectory: destination.lastPathComponent, owner: owner)
        defer { staging.close() }
        try publishEntry(parent: parent, owner: owner, staging: staging)
    }
    static func publishEntry(parent: String, owner: uid_t, staging: ReleaseDestinationLease) throws {
        try applicationEntry(parent: parent, owner: owner, createIfMissing: true, staging: staging)
    }
    static func inspectEntry(parent: String, owner: uid_t) throws {
        try applicationEntry(parent: parent, owner: owner, createIfMissing: false)
    }
    // The UI entry conveys no authority. Its destination can permit administrator-group writes.
    private static func applicationEntry(parent: String, owner: uid_t, createIfMissing: Bool,
                                         staging: ReleaseDestinationLease? = nil) throws {
        guard getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        let fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { _ = Darwin.close(fd) }
        func validate() throws {
            var held = stat(), named = stat(), mount = statfs()
            guard fstat(fd, &held) == 0, lstat(parent, &named) == 0, fstatfs(fd, &mount) == 0 else { throw JournalLeaseError.system(errno) }
            guard held.st_uid == owner, held.st_mode & S_IFMT == S_IFDIR, held.st_mode & 0o7002 == 0,
                  held.st_dev == named.st_dev, held.st_ino == named.st_ino else { throw JournalLeaseError.unsafeMetadata }
            try ProtectedStorageMetadata.validateMount(mount)
        }
        func matches() throws {
            var info = stat()
            guard fstatat(fd, "Remozio.app", &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                if !createIfMissing, errno == ENOENT { return }
                throw JournalLeaseError.system(errno)
            }
            guard info.st_mode & S_IFMT == S_IFLNK else { throw PackageBootstrapError.shortcutConflict }
            var bytes = [UInt8](repeating: 0, count: Int(PATH_MAX))
            let count = readlinkat(fd, "Remozio.app", &bytes, bytes.count)
            guard count >= 0 else { throw JournalLeaseError.system(errno) }
            guard Data(bytes.prefix(Int(count))) == Data(MachineBootstrap.bundlePath.utf8) else { throw PackageBootstrapError.shortcutConflict }
        }
        try validate()
        if createIfMissing {
            var existing = stat()
            if fstatat(fd, "Remozio.app", &existing, AT_SYMLINK_NOFOLLOW) == 0 {
                try matches(); try validate(); try matches(); return
            }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            guard let staging else { throw PackageBootstrapError.invalidState }
            try staging.withDirectory { source in
                let temporary = ".remozio-app-entry-" + UUID().uuidString
                guard symlinkat(MachineBootstrap.bundlePath, source, temporary) == 0 else { throw JournalLeaseError.system(errno) }
                var created = stat()
                guard fstatat(source, temporary, &created, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
                guard created.st_mode & S_IFMT == S_IFLNK, created.st_uid == owner, created.st_nlink == 1 else {
                    throw JournalLeaseError.unsafeMetadata
                }
                defer {
                    var current = stat()
                    if fstatat(source, temporary, &current, AT_SYMLINK_NOFOLLOW) == 0,
                       current.st_dev == created.st_dev, current.st_ino == created.st_ino {
                        _ = unlinkat(source, temporary, 0)
                    }
                }
                let link = openat(source, temporary, O_RDONLY | O_SYMLINK | O_CLOEXEC)
                guard link >= 0 else { throw JournalLeaseError.system(errno) }
                defer { _ = Darwin.close(link) }
                var held = stat(), named = stat()
                guard fstat(link, &held) == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == created.st_dev, held.st_ino == created.st_ino else { throw JournalLeaseError.identityChanged }
                guard fchmod(link, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
                try validate()
                if renameatx_np(source, temporary, fd, "Remozio.app", UInt32(RENAME_EXCL)) != 0 {
                    guard errno == EEXIST else { throw JournalLeaseError.system(errno) }
                } else {
                    guard fstatat(fd, "Remozio.app", &named, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
                    guard named.st_dev == held.st_dev, named.st_ino == held.st_ino,
                          named.st_mode & 0o777 == 0o755 else { throw JournalLeaseError.identityChanged }
                    guard fsync(source) == 0 else { throw JournalLeaseError.system(errno) }
                }
            }
        }
        try matches()
        if createIfMissing {
            guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
        }
        try validate(); try matches()
    }
}
