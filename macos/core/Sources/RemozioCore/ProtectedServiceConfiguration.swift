import Darwin
import Foundation

/// Reads immutable startup metadata. Provisioning and activation must establish its contents separately.
public enum ProtectedServiceConfiguration {
    public static let maximumBytes = 65_536

    /// Requires root-owned local ancestors and one private regular file. No environment or working-directory lookup occurs.
    public static func read(path: String) throws -> Data {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try read(anchor: "/", relativePath: String(path.dropFirst()), owner: 0)
    }

    /// Public metadata permits read access while retaining protected ownership, ancestry, ACL and identity checks.
    static func readPublic(path: String) throws -> Data {
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try read(anchor: "/", relativePath: String(path.dropFirst()), owner: 0, privateFile: false)
    }

    /// Only a missing leaf is optional. Missing or changed ancestors remain an error.
    static func readOptionalPublic(path: String) throws -> Data? {
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try readOptional(anchor: "/", relativePath: String(path.dropFirst()), owner: 0)
    }
    static func readOptional(anchor: String, relativePath: String, owner: uid_t) throws -> Data? {
        try readRecord(anchor: anchor, relativePath: relativePath, owner: owner,
            privateFile: false, ancestorOwner: nil, allowMissingLeaf: true)
    }
    /// Reads a service-owned private file under Root-owned ancestors. The interactive account cannot select an anchor.
    static func readServicePrivate(path: String, serviceUID: uid_t) throws -> Data {
        guard serviceUID > 0, serviceUID < UInt32.max, getuid() == serviceUID, geteuid() == serviceUID else {
            throw ApprovalTransportStartupError.wrongAccount
        }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try read(anchor: "/", relativePath: String(path.dropFirst()), owner: serviceUID, ancestorOwner: 0)
    }

    /// Root validates a service-owned leaf without adopting the service account's identity.
    static func readServicePrivateAsRoot(path: String, serviceUID: uid_t) throws -> Data {
        guard geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard serviceUID > 0, serviceUID < UInt32.max else { throw ApprovalTransportStartupError.wrongAccount }
        guard path.hasPrefix("/") else { throw JournalLeaseError.invalidPath }
        return try read(anchor: "/", relativePath: String(path.dropFirst()), owner: serviceUID, ancestorOwner: 0)
    }

    /// Fixture entry point. Production always walks from the filesystem root with Root-owned ancestors.
    static func read(anchor: String, relativePath: String, owner: uid_t, privateFile: Bool = true,
                     ancestorOwner: uid_t? = nil) throws -> Data {
        guard let bytes = try readRecord(anchor: anchor, relativePath: relativePath, owner: owner,
            privateFile: privateFile, ancestorOwner: ancestorOwner, allowMissingLeaf: false) else { throw JournalLeaseError.system(ENOENT) }
        return bytes
    }
    private static func readRecord(anchor: String, relativePath: String, owner: uid_t, privateFile: Bool,
                                   ancestorOwner: uid_t?, allowMissingLeaf: Bool) throws -> Data? {
        let parts = relativePath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, !anchor.utf8.contains(0),
              anchor.utf8.count + relativePath.utf8.count + 1 < Int(PATH_MAX),
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) && $0.utf8.count <= 255 }) else {
            throw JournalLeaseError.invalidPath
        }
        struct Node { let fd: Int32; let parent: Int32?; let name: String; let info: stat; let directory: Bool }
        var nodes: [Node] = []
        defer { for node in nodes.reversed() { _ = Darwin.close(node.fd) } }
        func retain(_ fd: Int32, parent: Int32?, name: String, directory: Bool) throws {
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }
            do {
                var info = stat()
                guard fstat(fd, &info) == 0 else { throw JournalLeaseError.system(errno) }
                try ProtectedStorageMetadata.validate(fd, info, directory: directory, privateObject: !directory && privateFile,
                    owner: owner, ancestorOwner: ancestorOwner ?? owner)
                nodes.append(Node(fd: fd, parent: parent, name: name, info: info, directory: directory))
            } catch { _ = Darwin.close(fd); throw error }
        }
        func validateNodes() throws {
            for node in nodes {
                var held = stat(), named = stat()
                guard fstat(node.fd, &held) == 0 else { throw JournalLeaseError.system(errno) }
                let rc = node.parent.map { fstatat($0, node.name, &named, AT_SYMLINK_NOFOLLOW) } ?? lstat(node.name, &named)
                guard rc == 0 else { throw JournalLeaseError.system(errno) }
                guard held.st_dev == node.info.st_dev, held.st_ino == node.info.st_ino,
                      named.st_dev == held.st_dev, named.st_ino == held.st_ino,
                      (named.st_mode & S_IFMT) == (node.directory ? S_IFDIR : S_IFREG) else { throw JournalLeaseError.identityChanged }
                try ProtectedStorageMetadata.validate(node.fd, held, directory: node.directory, privateObject: !node.directory && privateFile,
                    owner: owner, ancestorOwner: ancestorOwner ?? owner)
                if !node.directory {
                    guard held.st_size == node.info.st_size,
                          held.st_mtimespec.tv_sec == node.info.st_mtimespec.tv_sec,
                          held.st_mtimespec.tv_nsec == node.info.st_mtimespec.tv_nsec,
                          held.st_ctimespec.tv_sec == node.info.st_ctimespec.tv_sec,
                          held.st_ctimespec.tv_nsec == node.info.st_ctimespec.tv_nsec else { throw JournalLeaseError.identityChanged }
                }
            }
        }
        try retain(open(anchor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC), parent: nil, name: anchor, directory: true)
        for (index, part) in parts.enumerated() {
            let parent = nodes.last!.fd, directory = index < parts.count - 1
            let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (directory ? O_DIRECTORY : 0)
            let descriptor = openat(parent, part, flags)
            if descriptor < 0, !directory, allowMissingLeaf, errno == ENOENT {
                try validateNodes()
                var named = stat()
                guard fstatat(parent, part, &named, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw JournalLeaseError.identityChanged }
                try validateNodes(); return nil
            }
            try retain(descriptor, parent: parent, name: part, directory: directory)
        }
        let file = nodes.last!
        guard file.info.st_size > 0, file.info.st_size <= maximumBytes else { throw JournalLeaseError.unsafeMetadata }
        var result = Data(count: Int(file.info.st_size)), offset = 0
        while offset < result.count {
            let count = result.withUnsafeMutableBytes {
                Darwin.read(file.fd, $0.baseAddress!.advanced(by: offset), $0.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw count == 0 ? JournalLeaseError.identityChanged : JournalLeaseError.system(errno) }
            offset += count
        }
        try validateNodes()
        return result
    }
}
