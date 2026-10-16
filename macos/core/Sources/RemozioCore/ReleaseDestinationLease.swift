import Darwin
import Foundation

/// Retains protected destination ancestry. This lease grants no installation or activation authority.
public final class ReleaseDestinationLease {
    private struct Node {
        let fd: Int32
        let parent: Int32?
        let name: String
        let identity: stat
    }
    private var nodes: [Node] = []
    private let owner: uid_t
    private let readerUID: uid_t
    private let processID = getpid()
    private var closed = false
    public let path: String

    public static func acquire(path: String) throws -> ReleaseDestinationLease {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try .init(anchor: "/", relativeDirectory: String(path.dropFirst()), owner: 0)
    }
    /// Ordinary app registration reads Root-owned placement. This does not authorize any file mutation.
    static func readForServiceRegistration(path: String) throws -> ReleaseDestinationLease {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try .init(anchor: "/", relativeDirectory: String(path.dropFirst()), owner: 0, readerUID: getuid())
    }
    // Internal ordinary-account seam. Production walks from / with fixed Root ownership.
    init(anchor: String, relativeDirectory: String, owner: uid_t, readerUID: uid_t? = nil) throws {
        self.owner = owner; self.readerUID = readerUID ?? owner
        path = (anchor == "/" ? "" : anchor) + "/" + relativeDirectory
        let parts = relativeDirectory.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !anchor.utf8.contains(0), path.utf8.count < Int(PATH_MAX), !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw JournalLeaseError.invalidPath
        }
        do {
            try retain(open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: anchor)
            for part in parts {
                let parent = nodes.last!.fd
                try retain(openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: parent, name: part)
            }
            try validate()
        } catch { close(); throw error }
    }
    deinit { close() }

    public func validate() throws {
        guard !closed else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, getuid() == readerUID, geteuid() == readerUID else { throw JournalLeaseError.unsafeMetadata }
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let rc = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard rc == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.identity.st_dev, held.st_ino == node.identity.st_ino,
                      named.st_dev == held.st_dev, named.st_ino == held.st_ino,
                      named.st_mode & S_IFMT == S_IFDIR else { throw JournalLeaseError.identityChanged }
                try ProtectedStorageMetadata.validate(node.fd, held, directory: true, privateObject: false,
                    owner: owner, ancestorOwner: owner)
            }
        } catch { close(); throw error }
    }
    // Only the bounded copier will borrow this descriptor. No raw descriptor escapes as public API.
    func withDirectory<T>(_ body: (Int32) throws -> T) throws -> T {
        try validate()
        let value: T
        do { value = try body(nodes.last!.fd) }
        catch {
            try validate()
            throw error
        }
        try validate()
        return value
    }
    public func close() {
        guard !closed else { return }
        closed = true
        for node in nodes.reversed() { Darwin.close(node.fd) }
        nodes.removeAll()
    }
    func inspectCopiedTree(name: String, limits: ReleaseCopyLimits = try! .init()) throws -> ReleaseCopyCounts {
        try withDirectory { try ProtectedReleaseTreeInspection.inspect(parent: $0, name: name, owner: owner, limits: limits) }
    }
    func inspectInstalledApplication(name: String, limits: ReleaseCopyLimits = try! .init()) throws -> ReleaseCopyCounts {
        guard name.hasSuffix(".app") else { throw ReleaseCopyError.invalidInput }
        return try withDirectory {
            try ProtectedReleaseTreeInspection.inspect(parent: $0, name: name, owner: owner, limits: limits, installedApplication: true)
        }
    }
    func preparationAncestry() throws -> [PreparationFileIdentity] {
        try validate()
        return nodes.map { .init(device: UInt32(bitPattern: $0.identity.st_dev), inode: $0.identity.st_ino) }
    }
    func preparationCopyExists(name: String) throws -> Bool {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
              !name.utf8.contains(0), name.utf8.count <= 255 else { throw ReleaseCopyError.invalidInput }
        return try withDirectory { parent in
            var info = stat()
            if fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
            guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
            return false
        }
    }
    func preparationCopyIdentity(name: String) throws -> PreparationFileIdentity {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
              !name.utf8.contains(0), name.utf8.count <= 255 else { throw ReleaseCopyError.invalidInput }
        return try withDirectory { parent in
            var info = stat()
            guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
            guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == owner else { throw JournalLeaseError.unsafeMetadata }
            return .init(device: UInt32(bitPattern: info.st_dev), inode: info.st_ino)
        }
    }
    private func retain(_ fd: Int32, parent: Int32?, name: String) throws {
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
            try ProtectedStorageMetadata.validate(fd, info, directory: true, privateObject: false,
                owner: owner, ancestorOwner: owner)
            nodes.append(Node(fd: fd, parent: parent, name: name, identity: info))
        } catch { Darwin.close(fd); throw error }
    }
}
