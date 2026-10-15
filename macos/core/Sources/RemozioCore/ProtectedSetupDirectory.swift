import Darwin
import Foundation

/// Creates one protected directory. Administrator authorization and operation scope belong to the setup host.
/// Parents must already exist. Existing objects are checked without permission changes or replacement.
public final class ProtectedSetupDirectory: CustomStringConvertible {
    public enum Visibility: Sendable { case privateState, sharedMetadata }
    enum Stage { case prepared, published }
    private struct Node {
        let fd: Int32, parent: Int32?, name: String, final: Bool
        let device: dev_t, inode: ino_t
    }
    private var nodes: [Node] = []
    private let owner: uid_t
    private let processID = getpid()
    private let visibility: Visibility
    private var closed = false
    private var retired = false
    public let path: String
    public private(set) var created = false
    public var description: String { "ProtectedSetupDirectory(redacted)" }
    private var mode: mode_t { visibility == .privateState ? 0o700 : 0o755 }

    public static func createOrOpen(path: String, visibility: Visibility = .privateState) throws -> ProtectedSetupDirectory {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try .init(anchor: "/", relativePath: String(path.dropFirst()), owner: 0, visibility: visibility)
    }

    // Same-owner fixture seam. Product callers cannot change the owner, anchor or fault hooks.
    init(anchor: String, relativePath: String, owner: uid_t, visibility: Visibility = .privateState,
         createIfMissing: Bool = true, didStage: (Stage) throws -> Void = { _ in }) throws {
        let parts = relativePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        path = (anchor == "/" ? "" : anchor) + "/" + relativePath
        guard getuid() == owner, geteuid() == owner, !anchor.utf8.contains(0),
              path.utf8.count + 1 < Int(PATH_MAX), !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw JournalLeaseError.invalidPath
        }
        self.owner = owner; self.visibility = visibility
        do {
            try retain(open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: anchor, final: false)
            for part in parts.dropLast() {
                let parent = nodes.last!.fd
                try retain(openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
                    parent: parent, name: part, final: false)
            }
            try validate()
            let parent = nodes.last!.fd, name = parts.last!
            let existing = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if existing >= 0 {
                try retain(existing, parent: parent, name: name, final: true)
                try validate(); try synchronize(existing); try synchronize(parent); try validate(); return
            }
            guard errno == ENOENT, createIfMissing else { throw JournalLeaseError.system(errno) }
            let staging = ".remozio-directory-" + UUID().uuidString
            guard mkdirat(parent, staging, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            let fd = openat(parent, staging, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            do {
                var held = stat(), named = stat()
                guard fstat(fd, &held) == 0, fstatat(parent, staging, &named, AT_SYMLINK_NOFOLLOW) == 0 else {
                    throw JournalLeaseError.system(errno)
                }
                guard held.st_dev == named.st_dev, held.st_ino == named.st_ino,
                      held.st_uid == owner, held.st_mode & S_IFMT == S_IFDIR else { throw JournalLeaseError.identityChanged }
                try ProtectedStorageMetadata.validate(fd, held, directory: true, privateObject: false, owner: owner, ancestorOwner: owner)
                // Normalize only this new, empty staging directory. Never alter an existing destination.
                guard let acl = acl_init(0) else { throw JournalLeaseError.system(errno) }
                defer { acl_free(UnsafeMutableRawPointer(acl)) }
                guard acl_set_fd(fd, acl) == 0, fchmod(fd, mode) == 0 else { throw JournalLeaseError.system(errno) }
            } catch { _ = Darwin.close(fd); throw error }
            try retain(fd, parent: parent, name: staging, final: true)
            try validate(); try synchronize(fd); try synchronize(parent)
            try didStage(.prepared); try validate()
            guard renameatx_np(parent, staging, parent, name, UInt32(RENAME_EXCL)) == 0 else {
                throw JournalLeaseError.system(errno)
            }
            let last = nodes.removeLast()
            nodes.append(Node(fd: last.fd, parent: last.parent, name: name, final: true, device: last.device, inode: last.inode))
            created = true
            try didStage(.published); try validate(); try synchronize(parent); try validate()
        } catch { close(); throw error }
    }
    deinit { close() }

    private func synchronize(_ fd: Int32) throws {
        guard fsync(fd) == 0 else { throw JournalLeaseError.system(errno) }
    }
    private func retain(_ fd: Int32, parent: Int32?, name: String, final: Bool) throws {
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        do {
            var info = stat(); guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
            try inspect(fd, info: info, final: final)
            nodes.append(Node(fd: fd, parent: parent, name: name, final: final, device: info.st_dev, inode: info.st_ino))
        } catch { _ = Darwin.close(fd); throw error }
    }
    private func inspect(_ fd: Int32, info: stat, final: Bool) throws {
        try ProtectedStorageMetadata.validate(fd, info, directory: true,
            privateObject: final && visibility == .privateState, owner: owner, ancestorOwner: owner)
        if visibility == .sharedMetadata { try ProtectedStorageMetadata.validatePublicDirectoryAccess(fd, info) }
        if final { guard info.st_mode & 0o777 == mode else { throw JournalLeaseError.unsafeMetadata } }
    }
    public func validate() throws {
        guard !closed else { throw JournalLeaseError.closed }
        guard !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let result = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard result == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.device, held.st_ino == node.inode,
                      named.st_dev == node.device, named.st_ino == node.inode else { throw JournalLeaseError.identityChanged }
                try inspect(node.fd, info: held, final: node.final)
            }
        } catch { retired = true; throw error }
    }
    // Typed account setup compares actual ancestry without exposing descriptors.
    func directoryIdentities() throws -> [ProtectedStorageLease.DirectoryIdentity] {
        guard visibility == .privateState else { throw JournalLeaseError.unsafeMetadata }
        try validate()
        return nodes.map { .init(device: $0.device, inode: $0.inode) }
    }
    // Borrowed only by typed setup storage operations. No descriptor escapes through a public API.
    func withPrivateDirectory<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        guard visibility == .privateState else { throw JournalLeaseError.unsafeMetadata }
        return try withDirectory(body)
    }
    // Service-readable artifacts require traversable ancestors, not only a readable final file.
    func withSharedDirectory<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        guard visibility == .sharedMetadata else { throw JournalLeaseError.unsafeMetadata }
        return try withDirectory(body)
    }
    // Internal typed publication can borrow shared metadata directories. No descriptor becomes public.
    func withDirectory<Value>(_ body: (Int32) throws -> Value) throws -> Value {
        try validate()
        let result: Value
        do { result = try body(nodes.last!.fd) }
        catch { try validate(); throw error }
        try validate(); return result
    }
    public func close() {
        guard !closed else { return }; closed = true
        for node in nodes.reversed() { _ = Darwin.close(node.fd) }; nodes.removeAll()
    }
}
