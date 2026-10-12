import Darwin
import Foundation

/// Internal path and lock mechanics. Public wrappers fix the production ownership policy and file name.
final class ProtectedStorageLease {
    struct DirectoryIdentity: Equatable {
        let device: dev_t
        let inode: ino_t
    }

    func directoryIdentities() throws -> [DirectoryIdentity] {
        try validate()
        return nodes.filter(\.directory).map { DirectoryIdentity(device: $0.device, inode: $0.inode) }
    }

    let databasePath: String
    private struct Node {
        let fd: Int32
        let parent: Int32?
        let name: String
        let device: dev_t
        let inode: ino_t
        let directory: Bool
        let privateObject: Bool
    }
    private var nodes: [Node] = []
    private let owner: uid_t
    private let ancestorOwner: uid_t
    private let processID = getpid()
    private var invalidated = false
    private var isClosed = false

    init(anchor: String, relativeDirectory: String, owner: uid_t, ancestorOwner: uid_t, databaseName: String,
         excludingDirectory: DirectoryIdentity? = nil) throws {
        let components = relativeDirectory.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty, !anchor.utf8.contains(0),
              ["journal.sqlite", "gateway.sqlite", "continuity.sqlite", "installation.sqlite"].contains(databaseName),
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw JournalLeaseError.invalidPath
        }
        self.owner = owner
        self.ancestorOwner = ancestorOwner
        databasePath = (anchor == "/" ? "" : anchor) + "/" + relativeDirectory + "/" + databaseName
        guard databasePath.utf8.count < Int(PATH_MAX) else { throw JournalLeaseError.invalidPath }
        do {
            let anchorFD = open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard anchorFD >= 0 else { throw JournalLeaseError.system(errno) }
            try add(anchorFD, parent: nil, name: anchor, directory: true, privateObject: false)
            var parent = anchorFD
            for (index, component) in components.enumerated() {
                let fd = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                try add(fd, parent: parent, name: component, directory: true, privateObject: index == components.count - 1)
                parent = fd
            }
            if let excludingDirectory, let directory = nodes.last,
               excludingDirectory == DirectoryIdentity(device: directory.device, inode: directory.inode) {
                throw JournalLeaseError.invalidPath
            }
            let lock = try openFile("writer.lock", parent: parent)
            guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
                throw errno == EWOULDBLOCK ? JournalLeaseError.busy : JournalLeaseError.system(errno)
            }
            _ = try openFile(databaseName, parent: parent)
            try validate()
        } catch {
            close()
            throw error
        }
    }

    deinit { close() }

    /// Call before opening SQLite and at storage commit/recovery boundaries. Any failed check retires this lease.
    func validate() throws {
        guard !isClosed else { throw JournalLeaseError.closed }
        guard !invalidated else { throw JournalLeaseError.invalidated }
        do {
            guard getpid() == processID, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let rc = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard rc == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.device, held.st_ino == node.inode,
                      named.st_dev == node.device, named.st_ino == node.inode,
                      (named.st_mode & S_IFMT) == (node.directory ? S_IFDIR : S_IFREG) else { throw JournalLeaseError.identityChanged }
                try metadata(node.fd, held, directory: node.directory, privateObject: node.privateObject)
            }
        } catch {
            invalidated = true
            throw error
        }
    }

    /// Close SQLite before releasing the lease. This releases ownership, not files or persisted recovery state.
    func close() {
        guard !isClosed else { return }
        isClosed = true
        for node in nodes.reversed() { _ = Darwin.close(node.fd) }
        nodes.removeAll()
    }

    private func openFile(_ name: String, parent: Int32) throws -> Int32 {
        // Nonblocking prevents a substituted FIFO from hanging acquisition before its type is checked.
        let fd = openat(parent, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        try add(fd, parent: parent, name: name, directory: false, privateObject: true)
        return fd
    }
    private func add(_ fd: Int32, parent: Int32?, name: String, directory: Bool, privateObject: Bool) throws {
        do {
            var info = stat()
            guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
            try metadata(fd, info, directory: directory, privateObject: privateObject)
            nodes.append(Node(fd: fd, parent: parent, name: name, device: info.st_dev, inode: info.st_ino,
                              directory: directory, privateObject: privateObject))
        } catch { _ = Darwin.close(fd); throw error }
    }
    private func metadata(_ fd: Int32, _ info: stat, directory: Bool, privateObject: Bool) throws {
        try ProtectedStorageMetadata.validate(fd, info, directory: directory, privateObject: privateObject,
            owner: owner, ancestorOwner: ancestorOwner)
    }
}
