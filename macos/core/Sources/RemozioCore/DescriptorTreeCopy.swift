import Darwin
import Foundation

public enum ReleaseCopyError: Error, Equatable {
    case invalidInput, unsafeSource, unsafeDestination, changedSource, changedDestination, limit, system(Int32)
}
public struct ReleaseCopyCleanupFailure: Error {
    public let original: Error
    public let cleanup: Error
}
public struct ReleaseCopyCounts: Codable, Equatable, Sendable {
    public internal(set) var entries = 0
    public internal(set) var files = 0
    public internal(set) var links = 0
    public internal(set) var bytes: UInt64 = 0
}
public struct ReleaseCopyLimits: Sendable {
    let entries: Int, depth: Int, bytes: UInt64
    public init(entries: Int = 8192, depth: Int = 16, bytes: UInt64 = 1 << 30) throws {
        guard (1...8192).contains(entries), (0...16).contains(depth), (1...(1 << 30)).contains(bytes) else {
            throw ReleaseCopyError.invalidInput
        }
        self.entries = entries; self.depth = depth; self.bytes = bytes
    }
}

/// Copies into new inodes. Production preparation uses a protected destination lease.
enum DescriptorTreeCopy {
    static func copy(source: URL, parent: URL, name: String = "Fixture.app",
                            limits: ReleaseCopyLimits = try! .init(), checkCancellation: @escaping () throws -> Void = {}) throws -> ReleaseCopyCounts {
        try copy(source: source, parent: parent, name: name, limits: limits,
                 checkCancellation: checkCancellation, openedFile: { _, _, _ in })
    }

    static func copy(source: URL, parent: URL, name: String, limits: ReleaseCopyLimits,
                     checkCancellation: @escaping () throws -> Void = {}, borrowedParent: Int32? = nil,
                     validateCopy: (ReleaseCopyCounts) throws -> Void = { _ in },
                     openOutput: @escaping (Int32, String, Int32) -> Int32 = { openat($0, $1, $2) },
                     outputStatus: @escaping (Int32) throws -> stat = { try status($0) },
                     outputNameStatus: @escaping (Int32, String) throws -> stat = { try named($0, $1) },
                     openedFile: @escaping (Int32, String, Int32) throws -> Void) throws -> ReleaseCopyCounts {
        guard source.isFileURL, parent.isFileURL, validName(name) else { throw ReleaseCopyError.invalidInput }
        let sourcePath = try canonical(source), parentPath = try canonical(parent)
        guard parentPath != sourcePath, !parentPath.hasPrefix(sourcePath + "/") else { throw ReleaseCopyError.invalidInput }
        let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        let src = try opened(Darwin.open(source.path, flags))
        defer { Darwin.close(src) }
        let dstParent = try borrowedParent ?? opened(Darwin.open(parent.path, flags))
        defer { if borrowedParent == nil { Darwin.close(dstParent) } }
        let sourceInfo = try status(src), parentInfo = try status(dstParent)
        guard parentInfo.st_uid == geteuid(), parentInfo.st_mode & 0o022 == 0 else { throw ReleaseCopyError.unsafeDestination }
        try checkCancellation()
        guard mkdirat(dstParent, name, 0o700) == 0 else { throw ReleaseCopyError.system(errno) }
        var dst: Int32 = -1
        var initialOutputInfo: stat?
        defer { if dst >= 0 { Darwin.close(dst) } }
        let walker = Walker(limits: limits, checkCancellation: checkCancellation, openedFile: openedFile,
            openOutput: openOutput, outputStatus: outputStatus, outputNameStatus: outputNameStatus)
        do {
            let outputInfo = try named(dstParent, name)
            initialOutputInfo = outputInfo
            dst = try opened(openOutput(dstParent, name, flags))
            guard sameNode(outputInfo, try outputStatus(dst)) else { throw ReleaseCopyError.changedDestination }
            try walker.directory(source: src, destination: dst, depth: 0, path: [])
            try walker.validateLinks(root: dst)
            guard fchmod(dst, 0o755) == 0, fsync(dst) == 0, fsync(dstParent) == 0 else { throw ReleaseCopyError.system(errno) }
            guard stable(sourceInfo, try status(src)), stable(sourceInfo, try named(source.path)),
                  sameNode(parentInfo, try status(dstParent)), sameNode(parentInfo, try named(parent.path)),
                  sameNode(outputInfo, try named(dstParent, name)) else { throw ReleaseCopyError.changedDestination }
            try validateCopy(walker.counts)
            try checkCancellation()
            guard sameNode(outputInfo, try named(dstParent, name)) else { throw ReleaseCopyError.changedDestination }
        } catch {
            let original = error
            do {
                if dst >= 0 { try walker.cleanup(root: dst) }
                guard let outputInfo = initialOutputInfo else { throw ReleaseCopyError.changedDestination }
                guard sameNode(outputInfo, try named(dstParent, name)) else { throw ReleaseCopyError.changedDestination }
                guard unlinkat(dstParent, name, AT_REMOVEDIR) == 0, fsync(dstParent) == 0 else { throw ReleaseCopyError.system(errno) }
            } catch { throw ReleaseCopyCleanupFailure(original: original, cleanup: error) }
            throw original
        }
        return walker.counts
    }

    // Internal preparation composition. Public production setup must acquire the fixed-Root lease first.
    static func copy(source: URL, destination: ReleaseDestinationLease, name: String = "Fixture.app",
                     limits: ReleaseCopyLimits = try! .init(), checkCancellation: @escaping () throws -> Void = {}) throws -> ReleaseCopyCounts {
        try destination.withDirectory { descriptor in
            try copy(source: source, parent: URL(fileURLWithPath: destination.path), name: name, limits: limits,
                checkCancellation: checkCancellation, borrowedParent: descriptor, openedFile: { _, _, _ in })
        }
    }

    private final class Walker {
        struct Created {
            let path: [String]
            let identity: stat
        }
        let limits: ReleaseCopyLimits
        let checkCancellation: () throws -> Void
        let openedFile: (Int32, String, Int32) throws -> Void
        let openOutput: (Int32, String, Int32) -> Int32
        let outputStatus: (Int32) throws -> stat
        let outputNameStatus: (Int32, String) throws -> stat
        var counts = ReleaseCopyCounts()
        var created: [Created] = []
        var identities: [[String]: stat] = [:]
        func record(_ path: [String], _ identity: stat) {
            created.append(Created(path: path, identity: identity))
            identities[path] = identity
        }
        init(limits: ReleaseCopyLimits, checkCancellation: @escaping () throws -> Void,
             openedFile: @escaping (Int32, String, Int32) throws -> Void,
             openOutput: @escaping (Int32, String, Int32) -> Int32, outputStatus: @escaping (Int32) throws -> stat,
             outputNameStatus: @escaping (Int32, String) throws -> stat) {
            self.limits = limits; self.checkCancellation = checkCancellation; self.openedFile = openedFile
            self.openOutput = openOutput; self.outputStatus = outputStatus
            self.outputNameStatus = outputNameStatus
        }
        func directory(source: Int32, destination: Int32, depth: Int, path: [String]) throws {
            guard depth <= limits.depth else { throw ReleaseCopyError.limit }
            try checkCancellation()
            let before = try status(source)
            let duplicate = try opened(dup(source))
            guard let stream = fdopendir(duplicate) else { Darwin.close(duplicate); throw ReleaseCopyError.system(errno) }
            defer { closedir(stream) }
            while true {
                errno = 0
                guard let entry = readdir(stream) else {
                    guard errno == 0 else { throw ReleaseCopyError.system(errno) }
                    break
                }
                let name = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(validatingCString: $0) }
                }
                guard let name else { throw ReleaseCopyError.unsafeSource }
                if name == "." || name == ".." { continue }
                guard validName(name) else { throw ReleaseCopyError.unsafeSource }
                counts.entries += 1
                guard counts.entries <= limits.entries else { throw ReleaseCopyError.limit }
                try checkCancellation()
                let info = try named(source, name)
                switch info.st_mode & S_IFMT {
                case S_IFDIR:
                    try subdirectory(source: source, destination: destination, name: name, before: info, depth: depth + 1, path: path)
                case S_IFREG:
                    try file(source: source, destination: destination, name: name, before: info, path: path)
                case S_IFLNK:
                    try link(source: source, destination: destination, name: name, path: path)
                default: throw ReleaseCopyError.unsafeSource
                }
                guard stable(info, try named(source, name)) else { throw ReleaseCopyError.changedSource }
            }
            guard stable(before, try status(source)) else { throw ReleaseCopyError.changedSource }
        }
        func subdirectory(source: Int32, destination: Int32, name: String, before: stat, depth: Int, path: [String]) throws {
            let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            let src = try opened(openat(source, name, flags))
            defer { Darwin.close(src) }
            guard stable(before, try status(src)) else { throw ReleaseCopyError.changedSource }
            guard mkdirat(destination, name, 0o700) == 0 else { throw ReleaseCopyError.system(errno) }
            let outputInfo = try named(destination, name)
            record(path + [name], outputInfo)
            let dst = try opened(openOutput(destination, name, flags))
            defer { Darwin.close(dst) }
            guard sameNode(outputInfo, try outputStatus(dst)) else { throw ReleaseCopyError.changedDestination }
            try directory(source: src, destination: dst, depth: depth, path: path + [name])
            guard fchmod(dst, 0o755) == 0, fsync(dst) == 0 else { throw ReleaseCopyError.system(errno) }
        }
        func file(source: Int32, destination: Int32, name: String, before: stat, path: [String]) throws {
            let src = try opened(openat(source, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
            defer { Darwin.close(src) }
            guard before.st_nlink == 1, before.st_size >= 0, stable(before, try status(src)) else { throw ReleaseCopyError.unsafeSource }
            let dst = try opened(openat(destination, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600))
            defer { Darwin.close(dst) }
            let outputInfo = try status(dst)
            record(path + [name], outputInfo)
            guard sameNode(outputInfo, try outputNameStatus(destination, name)),
                  sameNode(outputInfo, try outputStatus(dst)) else { throw ReleaseCopyError.changedDestination }
            try openedFile(source, name, src)
            var buffer = [UInt8](repeating: 0, count: 65_536), copied: UInt64 = 0
            while true {
                try checkCancellation()
                let amount = buffer.withUnsafeMutableBytes { Darwin.read(src, $0.baseAddress!, $0.count) }
                if amount < 0, errno == EINTR { continue }
                guard amount >= 0 else { throw ReleaseCopyError.system(errno) }
                if amount == 0 { break }
                copied += UInt64(amount)
                guard copied <= UInt64(before.st_size), UInt64(amount) <= limits.bytes - counts.bytes else { throw ReleaseCopyError.limit }
                counts.bytes += UInt64(amount)
                var offset = 0
                while offset < amount {
                    let written = buffer.withUnsafeBytes { Darwin.write(dst, $0.baseAddress!.advanced(by: offset), amount - offset) }
                    if written < 0, errno == EINTR { continue }
                    guard written > 0 else { throw ReleaseCopyError.system(errno) }
                    offset += written
                }
            }
            guard copied == UInt64(before.st_size), stable(before, try status(src)) else { throw ReleaseCopyError.changedSource }
            guard fchmod(dst, before.st_mode & 0o111 == 0 ? 0o644 : 0o755) == 0, fsync(dst) == 0 else { throw ReleaseCopyError.system(errno) }
            counts.files += 1
        }
        func link(source: Int32, destination: Int32, name: String, path: [String]) throws {
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
            let amount = buffer.withUnsafeMutableBufferPointer { readlinkat(source, name, $0.baseAddress!, Int(PATH_MAX)) }
            guard amount > 0, amount < PATH_MAX else { throw ReleaseCopyError.unsafeSource }
            buffer[amount] = 0
            guard let target = String(validatingCString: buffer), !target.hasPrefix("/") else { throw ReleaseCopyError.unsafeSource }
            guard symlinkat(target, destination, name) == 0 else { throw ReleaseCopyError.system(errno) }
            record(path + [name], try named(destination, name))
            counts.links += 1
        }
        // Remove recorded creations only. Unknown entries and replacement inodes remain untouched.
        func cleanup(root: Int32) throws {
            for item in created.reversed() {
                let parent = try opened(dup(root))
                var descriptor = parent
                defer { Darwin.close(descriptor) }
                for (index, component) in item.path.dropLast().enumerated() {
                    let prefix = Array(item.path.prefix(index + 1))
                    guard let expected = identities[prefix],
                          sameNode(expected, try named(descriptor, component)) else {
                        throw ReleaseCopyError.changedDestination
                    }
                    let next = try opened(openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
                    guard sameNode(expected, try status(next)) else {
                        Darwin.close(next); throw ReleaseCopyError.changedDestination
                    }
                    Darwin.close(descriptor); descriptor = next
                }
                let name = item.path.last!
                guard sameNode(item.identity, try named(descriptor, name)) else { throw ReleaseCopyError.changedDestination }
                let flags = item.identity.st_mode & S_IFMT == S_IFDIR ? AT_REMOVEDIR : 0
                guard unlinkat(descriptor, name, flags) == 0 else { throw ReleaseCopyError.system(errno) }
            }
        }
        // Resolve copied links through retained descriptors without opening a path outside the copy.
        func validateLinks(root: Int32) throws {
            for item in created where item.identity.st_mode & S_IFMT == S_IFLNK {
                var descriptors = [try opened(dup(root))]
                defer { for descriptor in descriptors { Darwin.close(descriptor) } }
                var components = item.path
                var expansions = 0
                while !components.isEmpty {
                    try checkCancellation()
                    let component = components.removeFirst()
                    if component == "." || component.isEmpty { continue }
                    if component == ".." {
                        guard descriptors.count > 1 else { throw ReleaseCopyError.unsafeSource }
                        Darwin.close(descriptors.removeLast())
                        continue
                    }
                    guard validName(component) else { throw ReleaseCopyError.unsafeSource }
                    let parent = descriptors.last!
                    let info = try named(parent, component)
                    if info.st_mode & S_IFMT == S_IFLNK {
                        expansions += 1
                        guard expansions <= 40 else { throw ReleaseCopyError.unsafeSource }
                        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
                        let length = buffer.withUnsafeMutableBufferPointer { readlinkat(parent, component, $0.baseAddress!, Int(PATH_MAX)) }
                        guard length > 0, length < PATH_MAX else { throw ReleaseCopyError.unsafeSource }
                        buffer[length] = 0
                        guard let target = String(validatingCString: buffer), !target.hasPrefix("/") else { throw ReleaseCopyError.unsafeSource }
                        components = target.split(separator: "/", omittingEmptySubsequences: false).map(String.init) + components
                        guard components.count <= 256 else { throw ReleaseCopyError.limit }
                    } else if info.st_mode & S_IFMT == S_IFDIR {
                        guard descriptors.count <= limits.depth else { throw ReleaseCopyError.limit }
                        let next = try opened(openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC))
                        guard sameNode(info, try status(next)) else {
                            Darwin.close(next); throw ReleaseCopyError.changedDestination
                        }
                        descriptors.append(next)
                    } else {
                        guard components.isEmpty, info.st_mode & S_IFMT == S_IFREG else { throw ReleaseCopyError.unsafeSource }
                    }
                }
            }
        }
    }
    private static func validName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.utf8.contains(0) && !name.contains("/") && name.utf8.count <= 255
    }
    private static func opened(_ fd: Int32) throws -> Int32 {
        guard fd >= 0 else { throw ReleaseCopyError.system(errno) }; return fd
    }
    private static func status(_ fd: Int32) throws -> stat {
        var info = stat(); guard fstat(fd, &info) == 0 else { throw ReleaseCopyError.system(errno) }; return info
    }
    private static func named(_ parent: Int32, _ name: String) throws -> stat {
        var info = stat(); guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw ReleaseCopyError.system(errno) }; return info
    }
    private static func named(_ path: String) throws -> stat {
        var info = stat(); guard lstat(path, &info) == 0 else { throw ReleaseCopyError.system(errno) }; return info
    }
    private static func sameNode(_ a: stat, _ b: stat) -> Bool { a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode & S_IFMT == b.st_mode & S_IFMT }
    private static func stable(_ a: stat, _ b: stat) -> Bool {
        sameNode(a, b) && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_size == b.st_size && a.st_uid == b.st_uid && a.st_gid == b.st_gid
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    private static func canonical(_ url: URL) throws -> String {
        guard let value = realpath(url.path, nil) else { throw ReleaseCopyError.system(errno) }
        defer { free(value) }; return String(cString: value)
    }
}
