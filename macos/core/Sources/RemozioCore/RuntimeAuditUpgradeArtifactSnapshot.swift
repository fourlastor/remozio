import CryptoKit
import Darwin
import Foundation

/// An observation of source leaves only. No snapshot is a quiescence, publication or activation permit.
struct RuntimeAuditUpgradeArtifactSnapshot: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    struct Metadata: Equatable {
        let device: dev_t
        let inode: ino_t
        let size: off_t
        let uid: uid_t
        let gid: gid_t
        let mode: mode_t
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int
        let bornSeconds: Int
        let bornNanoseconds: Int
        let generation: UInt32
        init(_ value: stat) {
            device = value.st_dev; inode = value.st_ino; size = value.st_size
            uid = value.st_uid; gid = value.st_gid; mode = value.st_mode
            modifiedSeconds = value.st_mtimespec.tv_sec; modifiedNanoseconds = value.st_mtimespec.tv_nsec
            changedSeconds = value.st_ctimespec.tv_sec; changedNanoseconds = value.st_ctimespec.tv_nsec
            bornSeconds = value.st_birthtimespec.tv_sec; bornNanoseconds = value.st_birthtimespec.tv_nsec; generation = value.st_gen
        }
    }
    struct Leaf {
        let entry: RuntimeAuditUpgradeArtifactPlan.Entry
        let metadata: Metadata?
        let source: Data?
        let target: Data?
        var sourceDigest: Data? { source.map { Data(SHA256.hash(data: $0)) } }
        var targetDigest: Data? { target.map { Data(SHA256.hash(data: $0)) } }
    }
    struct ParentIdentity: Equatable {
        let path: String
        let device: dev_t
        let inode: ino_t
        let missingChild: Bool
    }
    struct MissingImports {
        private let machine: ProtectedSetupDirectory
        private init(machine: ProtectedSetupDirectory) { self.machine = machine }
        static func observe(machine: ProtectedSetupDirectory, owner: uid_t, ownership: Ownership,
                            verifyCurrent: () throws -> Void) throws -> Self {
            try checkOwner(owner, ownership)
            let value = Self(machine: machine)
            _ = try value.validate(owner: owner, ownership: ownership, verifyCurrent: verifyCurrent)
            return value
        }
        fileprivate func validate(owner: uid_t, ownership: Ownership, verifyCurrent: () throws -> Void) throws -> ParentIdentity {
            try checkOwner(owner, ownership); try verifyCurrent()
            if ownership == .native, machine.path != MachineBootstrap.machineDirectory { throw RuntimePreparationError.changedScope }
            return try machine.withPrivateDirectory { parent in
                var missing = stat(), held = stat()
                guard fstatat(parent, "SharedSetupImport", &missing, AT_SYMLINK_NOFOLLOW) < 0, errno == ENOENT else {
                    throw RuntimePreparationError.changedScope
                }
                guard fstat(parent, &held) == 0 else { throw JournalLeaseError.system(errno) }
                try verifyCurrent()
                guard fstatat(parent, "SharedSetupImport", &missing, AT_SYMLINK_NOFOLLOW) < 0, errno == ENOENT else {
                    throw RuntimePreparationError.changedScope
                }
                return .init(path: machine.path + "/SharedSetupImport", device: held.st_dev, inode: held.st_ino, missingChild: true)
            }
        }
    }
    let plan: RuntimeAuditUpgradeArtifactPlan
    let leaves: [Leaf]
    let ownership: Ownership
    var retainedParents: [RuntimeAuditUpgradeArtifactPlan.Directory: ParentIdentity] { parents }
    private let parents: [RuntimeAuditUpgradeArtifactPlan.Directory: ParentIdentity]
    var description: String { "RuntimeAuditUpgradeArtifactSnapshot(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    private init(plan: RuntimeAuditUpgradeArtifactPlan, leaves: [Leaf], parents: [RuntimeAuditUpgradeArtifactPlan.Directory: ParentIdentity], ownership: Ownership) {
        self.plan = plan; self.leaves = leaves; self.parents = parents; self.ownership = ownership
    }

    // Historical decoded observations still need validate() before any claim about current files.
    static func restore(plan: RuntimeAuditUpgradeArtifactPlan, leaves: [Leaf],
                        parents: [RuntimeAuditUpgradeArtifactPlan.Directory: ParentIdentity], ownership: Ownership) throws -> Self {
        guard Set(parents.keys) == Set(RuntimeAuditUpgradeArtifactPlan.Directory.allCases),
              Set(leaves.map { $0.entry.key }) == Set(plan.entries.map(\.key)), leaves.count == plan.entries.count else {
            throw RuntimePreparationError.invalidRecord
        }
        for leaf in leaves {
            guard let entry = plan.entries.first(where: { $0.key == leaf.entry.key }),
                  entry.variants.contains(where: { $0.source == leaf.source && $0.target == leaf.target }),
                  (leaf.source == nil) == (leaf.metadata == nil),
                  leaf.source.map({ off_t($0.count) == (leaf.metadata?.size ?? -1) }) ?? true else { throw RuntimePreparationError.invalidRecord }
            if let expected = entry.expectedIdentity {
                guard leaf.metadata?.device == expected.device, leaf.metadata?.inode == expected.inode else { throw JournalLeaseError.identityChanged }
            }
        }
        return .init(plan: plan, leaves: leaves, parents: parents, ownership: ownership)
    }

    enum Ownership: Equatable {
        case native
        case ordinaryOwnerFixture
    }
    /// The native owner supplies fixed protected directories and independently verifies all journal and machine scope.
    /// Fixture ownership never substitutes for service ownership in a Root process.
    static func capture(_ plan: RuntimeAuditUpgradeArtifactPlan,
                        directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory], owner: uid_t,
                        ownership: Ownership, missingImports: MissingImports? = nil,
                        verifyCurrent: () throws -> Void) throws -> Self {
        try checkOwner(owner, ownership)
        try verifyCurrent()
        let parents = try captureParents(plan, directories: directories, missingImports: missingImports,
            owner: owner, ownership: ownership, verifyCurrent: verifyCurrent)
        let leaves = try plan.entries.map { entry -> Leaf in
            let result = try read(entry, directories: directories, owner: owner, ownership: ownership, missingImports: missingImports, verifyCurrent: verifyCurrent)
            guard let variant = entry.variants.first(where: { $0.source == result.1 }) else { throw RuntimePreparationError.changedScope }
            if let expected = entry.expectedIdentity {
                guard result.0?.device == expected.device, result.0?.inode == expected.inode else { throw JournalLeaseError.identityChanged }
            }
            return .init(entry: entry, metadata: result.0, source: result.1, target: variant.target)
        }
        let snapshot = Self(plan: plan, leaves: leaves, parents: parents, ownership: ownership)
        try snapshot.validate(directories: directories, owner: owner, ownership: ownership, missingImports: missingImports, verifyCurrent: verifyCurrent)
        return snapshot
    }
    func validate(directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory], owner: uid_t,
                  ownership: Ownership, missingImports: MissingImports? = nil, verifyCurrent: () throws -> Void) throws {
        try Self.checkOwner(owner, ownership)
        try verifyCurrent()
        guard try Self.captureParents(plan, directories: directories, missingImports: missingImports,
            owner: owner, ownership: ownership, verifyCurrent: verifyCurrent) == parents else { throw RuntimePreparationError.changedScope }
        for leaf in leaves {
            let current = try Self.read(leaf.entry, directories: directories, owner: owner, ownership: ownership, missingImports: missingImports, verifyCurrent: verifyCurrent)
            guard current.0 == leaf.metadata, current.1 == leaf.source else { throw RuntimePreparationError.changedScope }
        }
        try verifyCurrent()
        for directory in directories.values { try directory.validate() }
        guard try Self.captureParents(plan, directories: directories, missingImports: missingImports,
            owner: owner, ownership: ownership, verifyCurrent: verifyCurrent) == parents else { throw RuntimePreparationError.changedScope }
    }
    static func captureParents(_ plan: RuntimeAuditUpgradeArtifactPlan,
        directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory], missingImports: MissingImports?,
        owner: uid_t, ownership: Ownership, verifyCurrent: () throws -> Void) throws -> [RuntimeAuditUpgradeArtifactPlan.Directory: ParentIdentity] {
        var expected = Set(RuntimeAuditUpgradeArtifactPlan.Directory.allCases)
        if missingImports != nil { expected.remove(.imports) }
        guard Set(directories.keys) == expected else { throw RuntimePreparationError.incomplete }
        let paths = try RuntimePreparationPaths(accountID: plan.preparation.source.accountID)
        let nativePaths: [RuntimeAuditUpgradeArtifactPlan.Directory: String] = [.runtime: paths.privateDirectory,
            .services: paths.serviceDirectory, .clients: RuntimePreparationPaths.sharedDirectory,
            .jobs: InstalledAccountJobManifest.directory, .imports: MachineBootstrap.machineDirectory + "/SharedSetupImport"]
        var values: [RuntimeAuditUpgradeArtifactPlan.Directory: ParentIdentity] = [:]
        for (area, directory) in directories {
            if ownership == .native, directory.path != nativePaths[area] { throw RuntimePreparationError.changedScope }
            try verifyCurrent()
            values[area] = try directory.withDirectory { parent in
                var info = stat(); guard fstat(parent, &info) == 0 else { throw JournalLeaseError.system(errno) }
                return .init(path: directory.path, device: info.st_dev, inode: info.st_ino, missingChild: false)
            }
        }
        if let missingImports { values[.imports] = try missingImports.validate(owner: owner, ownership: ownership, verifyCurrent: verifyCurrent) }
        return values
    }
    private static func checkOwner(_ owner: uid_t, _ ownership: Ownership) throws {
        switch ownership {
        case .native:
            guard owner == 0, getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        case .ordinaryOwnerFixture:
            guard owner > 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        }
    }
    static func read(_ entry: RuntimeAuditUpgradeArtifactPlan.Entry,
                             directories: [RuntimeAuditUpgradeArtifactPlan.Directory: ProtectedSetupDirectory], owner: uid_t,
                             ownership: Ownership, missingImports: MissingImports?,
                             verifyCurrent: () throws -> Void) throws -> (Metadata?, Data?) {
        guard let directory = directories[entry.directory] else {
            guard entry.directory == .imports, let missingImports else { throw RuntimePreparationError.incomplete }
            _ = try missingImports.validate(owner: owner, ownership: ownership, verifyCurrent: verifyCurrent)
            return (nil, nil)
        }
        try entry.file.validate(); try verifyCurrent(); try directory.validate()
        let file = entry.file
        if file.requiresSharedDirectory { try directory.withSharedDirectory { _ in } }
        let result: (Metadata?, Data?) = try directory.withDirectory { parent in
            let fd = openat(parent, file.name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            if fd < 0 {
                guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                var absent = stat()
                guard fstatat(parent, file.name, &absent, AT_SYMLINK_NOFOLLOW) < 0, errno == ENOENT else {
                    throw JournalLeaseError.identityChanged
                }
                return (nil, nil)
            }
            defer { _ = Darwin.close(fd) }
            let fileOwner = ownership == .native ? file.fileOwner(processOwner: owner) : owner
            let group = ownership == .native ? file.groupID : file.groupID.map { _ in getgid() }
            func inspect() throws -> Metadata {
                var held = stat(), named = stat()
                guard fstat(fd, &held) == 0, fstatat(parent, file.name, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
                    throw JournalLeaseError.system(errno)
                }
                guard held.st_dev == named.st_dev, held.st_ino == named.st_ino,
                      named.st_mode & S_IFMT == S_IFREG, held.st_mode & 0o7777 == file.mode,
                      held.st_size > 0, held.st_size <= ProtectedServiceConfiguration.maximumBytes,
                      group == nil || held.st_gid == group else { throw JournalLeaseError.unsafeMetadata }
                try ProtectedStorageMetadata.validate(fd, held, directory: false, privateObject: file.mode == 0o600,
                    owner: fileOwner, ancestorOwner: owner)
                return Metadata(held)
            }
            let before = try inspect()
            var bytes = Data(count: Int(before.size)), offset = 0
            while offset < bytes.count {
                let n = bytes.withUnsafeMutableBytes { pread(fd, $0.baseAddress!.advanced(by: offset), $0.count - offset, off_t(offset)) }
                if n < 0, errno == EINTR { continue }
                guard n > 0 else { throw JournalLeaseError.identityChanged }; offset += n
            }
            guard try inspect() == before else { throw JournalLeaseError.identityChanged }
            return (before, bytes)
        }
        try verifyCurrent(); try directory.validate(); return result
    }
}
