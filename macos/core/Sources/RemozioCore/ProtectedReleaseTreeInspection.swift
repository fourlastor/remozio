import Darwin
import Foundation

/// Checks every copied object. This check grants no installation or activation authority.
enum ProtectedReleaseTreeInspection {
    static func inspect(parent: Int32, name: String, owner: uid_t, limits: ReleaseCopyLimits) throws -> ReleaseCopyCounts {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
              !name.utf8.contains(0), name.utf8.count <= 255 else { throw ReleaseCopyError.invalidInput }
        let before = try named(parent, name)
        let root = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw JournalLeaseError.system(errno) }
        defer { Darwin.close(root) }
        let walker = Walker(owner: owner, limits: limits)
        try walker.inspect(fd: root, before: before, directory: true, depth: 0)
        guard stable(before, try named(parent, name)) else { throw JournalLeaseError.identityChanged }
        return walker.counts
    }

    private final class Walker {
        let owner: uid_t
        let limits: ReleaseCopyLimits
        var counts = ReleaseCopyCounts()
        init(owner: uid_t, limits: ReleaseCopyLimits) { self.owner = owner; self.limits = limits }

        func inspect(fd: Int32, before: stat, directory: Bool, depth: Int) throws {
            guard depth <= limits.depth else { throw ReleaseCopyError.limit }
            let held = try status(fd)
            guard stable(before, held) else { throw JournalLeaseError.identityChanged }
            try ProtectedStorageMetadata.validate(fd, held, directory: directory, privateObject: false,
                owner: owner, ancestorOwner: owner)
            try CopiedReleaseMetadata.validate(fd, try status(fd))
            if directory {
                let duplicate = dup(fd)
                guard duplicate >= 0 else { throw JournalLeaseError.system(errno) }
                guard let stream = fdopendir(duplicate) else {
                    Darwin.close(duplicate); throw JournalLeaseError.system(errno)
                }
                defer { closedir(stream) }
                while true {
                    errno = 0
                    guard let entry = readdir(stream) else {
                        guard errno == 0 else { throw JournalLeaseError.system(errno) }
                        break
                    }
                    let name = withUnsafePointer(to: &entry.pointee.d_name) {
                        $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(validatingCString: $0) }
                    }
                    guard let name else { throw JournalLeaseError.unsafeMetadata }
                    if name == "." || name == ".." { continue }
                    counts.entries += 1
                    guard counts.entries <= limits.entries else { throw ReleaseCopyError.limit }
                    let child = try named(fd, name)
                    let type = child.st_mode & S_IFMT
                    if type == S_IFLNK {
                        // The protected parent controls link replacement. Targets are checked by the copier and signature reader.
                        guard child.st_uid == owner, child.st_nlink == 1, child.st_mode & 0o7000 == 0 else {
                            throw JournalLeaseError.unsafeMetadata
                        }
                        let linkFD = openat(fd, name, O_RDONLY | O_SYMLINK | O_CLOEXEC)
                        guard linkFD >= 0 else { throw JournalLeaseError.system(errno) }
                        defer { Darwin.close(linkFD) }
                        let held = try status(linkFD)
                        guard stable(child, held) else { throw JournalLeaseError.identityChanged }
                        try CopiedReleaseMetadata.validate(linkFD, held)
                        guard stable(held, try status(linkFD)) else { throw JournalLeaseError.identityChanged }
                        counts.links += 1
                    } else {
                        guard type == S_IFDIR || type == S_IFREG else { throw JournalLeaseError.unsafeMetadata }
                        let isDirectory = type == S_IFDIR
                        let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (isDirectory ? O_DIRECTORY : 0)
                        let next = openat(fd, name, flags)
                        guard next >= 0 else { throw JournalLeaseError.system(errno) }
                        do {
                            try inspect(fd: next, before: child, directory: isDirectory, depth: depth + (isDirectory ? 1 : 0))
                        } catch { Darwin.close(next); throw error }
                        Darwin.close(next)
                    }
                    guard stable(child, try named(fd, name)) else { throw JournalLeaseError.identityChanged }
                }
            } else {
                guard held.st_size >= 0, UInt64(held.st_size) <= limits.bytes - counts.bytes else { throw ReleaseCopyError.limit }
                counts.bytes += UInt64(held.st_size); counts.files += 1
            }
            guard stable(held, try status(fd)) else { throw JournalLeaseError.identityChanged }
            try ProtectedStorageMetadata.validate(fd, try status(fd), directory: directory, privateObject: false,
                owner: owner, ancestorOwner: owner)
            try CopiedReleaseMetadata.validate(fd, try status(fd))
        }
    }

    private static func named(_ parent: Int32, _ name: String) throws -> stat {
        var value = stat()
        guard fstatat(parent, name, &value, AT_SYMLINK_NOFOLLOW) == 0 else { throw JournalLeaseError.system(errno) }
        return value
    }
    private static func status(_ fd: Int32) throws -> stat {
        var value = stat(); guard fstat(fd, &value) == 0 else { throw JournalLeaseError.system(errno) }; return value
    }
    private static func stable(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink
            && a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_size == b.st_size && a.st_flags == b.st_flags
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
}
