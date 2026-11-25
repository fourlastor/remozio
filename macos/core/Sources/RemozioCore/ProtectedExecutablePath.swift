import Darwin
import Foundation

/// Retains a protected launch path while installation validates code and prepares activation.
/// This checks placement, not the signature, release generation, or launch authorization.
public final class ProtectedExecutablePath {
    private struct Node {
        let fd: Int32
        let parent: Int32?
        let name: String
        let initial: stat
        let directory: Bool
    }
    private var nodes: [Node] = []
    private let owner: uid_t
    private let processID = getpid()
    private var retired = false
    public let path: String

    public static func acquire(path: String) throws -> ProtectedExecutablePath {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try ProtectedExecutablePath(anchor: "/", relativePath: String(path.dropFirst()), owner: 0)
    }

    init(anchor: String, relativePath: String, owner: uid_t) throws {
        self.owner = owner
        path = (anchor == "/" ? "" : anchor) + "/" + relativePath
        let components = relativePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !anchor.utf8.contains(0), path.utf8.count < Int(PATH_MAX), !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw JournalLeaseError.invalidPath
        }
        do {
            let fd = open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            try retain(fd, parent: nil, name: anchor, directory: true)
            var parent = fd
            for (index, name) in components.enumerated() {
                let directory = index != components.count - 1
                let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY | (directory ? O_DIRECTORY : 0)
                let next = openat(parent, name, flags)
                guard next >= 0 else { throw JournalLeaseError.system(errno) }
                try retain(next, parent: parent, name: name, directory: directory)
                parent = next
            }
            try validate()
        } catch { close(); throw error }
    }
    deinit { close() }

    /// Recheck before and after code inspection, and immediately before activation.
    public func validate() throws {
        guard !retired else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let rc = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard rc == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.initial.st_dev, held.st_ino == node.initial.st_ino,
                      named.st_dev == held.st_dev, named.st_ino == held.st_ino,
                      named.st_mode & S_IFMT == (node.directory ? S_IFDIR : S_IFREG) else { throw JournalLeaseError.identityChanged }
                try metadata(node.fd, held, directory: node.directory)
                if !node.directory {
                    guard held.st_size == node.initial.st_size,
                          held.st_mtimespec.tv_sec == node.initial.st_mtimespec.tv_sec,
                          held.st_mtimespec.tv_nsec == node.initial.st_mtimespec.tv_nsec,
                          held.st_ctimespec.tv_sec == node.initial.st_ctimespec.tv_sec,
                          held.st_ctimespec.tv_nsec == node.initial.st_ctimespec.tv_nsec else { throw JournalLeaseError.identityChanged }
                }
            }
        } catch { close(); throw error }
    }
    /// Reuse the protected walk for commands that already have an approved file identity.
    func commandExecutableInfo() throws -> stat {
        try validate()
        guard let executable = nodes.last else { throw JournalLeaseError.invalidated }
        var system = statfs(), data = statfs()
        guard statfs("/", &system) == 0, statfs("/System/Volumes/Data", &data) == 0 else {
            throw JournalLeaseError.system(errno)
        }
        for node in nodes {
            var mount = statfs()
            guard fstatfs(node.fd, &mount) == 0 else { throw JournalLeaseError.system(errno) }
            try Self.validateLaunchMount(mount, system: system.f_fsid, data: data.f_fsid)
        }
        return executable.initial
    }

    static func validateLaunchMount(_ mount: statfs, system: fsid_t, data: fsid_t) throws {
        try ProtectedStorageMetadata.validateMount(mount)
        let identity = mount.f_fsid
        guard mount.f_flags & UInt32(MNT_IGNORE_OWNERSHIP) == 0,
              (identity.val.0 == system.val.0 && identity.val.1 == system.val.1) ||
              (identity.val.0 == data.val.0 && identity.val.1 == data.val.1) else {
            throw JournalLeaseError.unsafeMetadata
        }
    }

    public func close() {
        guard !retired else { return }
        retired = true
        for node in nodes.reversed() { _ = Darwin.close(node.fd) }
        nodes.removeAll()
    }
    private func retain(_ fd: Int32, parent: Int32?, name: String, directory: Bool) throws {
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
            try metadata(fd, info, directory: directory)
            nodes.append(Node(fd: fd, parent: parent, name: name, initial: info, directory: directory))
        } catch { _ = Darwin.close(fd); throw error }
    }
    private func metadata(_ fd: Int32, _ info: stat, directory: Bool) throws {
        try ProtectedStorageMetadata.validate(fd, info, directory: directory, privateObject: false,
            owner: owner, ancestorOwner: owner)
        guard directory || (info.st_mode & 0o100 != 0 && info.st_size > 0) else { throw JournalLeaseError.unsafeMetadata }
    }
}
