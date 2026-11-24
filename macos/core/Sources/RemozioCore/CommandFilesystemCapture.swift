import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum CommandFilesystemCaptureError: Error, Equatable {
    case invalidPath, invalidExecutable, invalidDirectory, changed, closed, timedOut
    case credentialUnavailable
    case system(Int32)
}

/// Authenticated effective credentials from the Mach audit token.
struct CommandFilesystemCaller: Sendable {
    // Match KAUTH_UID_NONE and KAUTH_GID_NONE from sys/kauth.h.
    static let kauthUIDNone = uid_t.max &- 100
    static let kauthGIDNone = gid_t.max &- 100
    let userID: uid_t
    let groupID: gid_t

    static func requireProcessIdentity() throws {
        var user: uid_t = 0, group: gid_t = 0
        guard pthread_getugid_np(&user, &group) == -1, errno == ESRCH else {
            throw CommandFilesystemCaptureError.credentialUnavailable
        }
    }

    func withIdentity<Result>(_ body: () throws -> Result) throws -> Result {
        try Self.requireProcessIdentity()
        if geteuid() != 0, userID == geteuid(), groupID == getegid() {
            return try body()
        }
        guard userID != Self.kauthUIDNone, groupID != Self.kauthGIDNone,
              pthread_setugid_np(userID, groupID) == 0 else {
            throw CommandFilesystemCaptureError.credentialUnavailable
        }
        defer {
            // A worker must never return to the pool with assumed credentials.
            if pthread_setugid_np(Self.kauthUIDNone, Self.kauthGIDNone) != 0 {
                fatalError("Cannot restore the command filesystem thread identity")
            }
        }
        return try body()
    }
}

/// Captures filesystem facts in the calling process. This does not authorize or execute a command.
/// The owner must serialize access and close the capture when its request retires.
public final class CommandFilesystemCapture {
    static let maximumExecutableBytes: off_t = 512 * 1024 * 1024
    static let phaseTimeout: Duration = .seconds(5)
    public let executable: CapturedExecutable
    public let directory: CapturedDirectory
    let resolvedExecutablePath: Data
    private let captureID = UUID()
    private let caller: CommandFilesystemCaller
    // The SDK defines O_SEARCH as O_EXEC | O_DIRECTORY.
    private static let searchDirectoryFlags = O_EXEC | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK
    private let resolvedDirectories: [ResolvedDirectory]
    private let resolvedName: Data
    private var executableFD: Int32
    private var executableParentFD: Int32
    private var directoryFD: Int32

    public convenience init(executablePath: Data, directoryPath: Data, caller: RetainedCommandCaller,
                            checkCancellation: () throws -> Void = {}) throws {
        guard caller.retainedAuditBinding != nil else { throw CommandFilesystemCaptureError.credentialUnavailable }
        try self.init(executablePath: executablePath, directoryPath: directoryPath,
            deadline: ContinuousClock.now + Self.phaseTimeout, caller: caller.filesystemCaller, checkCancellation: checkCancellation)
    }

    init(executablePath: Data, directoryPath: Data, deadline: ContinuousClock.Instant,
         caller: CommandFilesystemCaller, checkProbe: () throws -> Void = {},
         checkCancellation: () throws -> Void = {}) throws {
        try Self.validatePath(executablePath)
        try Self.validatePath(directoryPath)
        try Self.checkDeadline(deadline, checkProbe: checkProbe)
        try checkCancellation()
        let cwd = try caller.withIdentity {
            try Self.openPath(directoryPath, flags: Self.searchDirectoryFlags)
        }
        var file: Int32 = -1
        var parent: Int32 = -1
        do {
            let cwdInfo = try Self.directoryInfo(cwd)
            let resolved = try caller.withIdentity {
                try Self.resolveExecutable(executablePath, deadline: deadline, checkProbe: checkProbe)
            }
            parent = resolved.parent
            try Self.checkDeadline(deadline, checkProbe: checkProbe)
            file = try Self.openComponent(parent, resolved.name,
                flags: O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY)
            let fileInfo = try Self.executableInfo(file)
            guard Self.stable(resolved.info, fileInfo) else { throw CommandFilesystemCaptureError.changed }
            let digest = try Self.digest(file, initial: fileInfo, deadline: deadline, checkProbe: checkProbe,
                checkCancellation: checkCancellation)
            try caller.withIdentity {
                try Self.checkNamedExecutable(executablePath, held: fileInfo)
                try Self.checkNamedExecutable(resolved.path, held: fileInfo, followLink: false)
                try Self.checkDirectory(cwd, path: directoryPath, identity: Self.identity(cwdInfo))
            }
            try Self.checkDeadline(deadline, checkProbe: checkProbe)
            try checkCancellation()
            self.caller = caller
            executable = CapturedExecutable(path: executablePath, identity: Self.identity(fileInfo), sha256: digest)
            directory = CapturedDirectory(path: directoryPath, identity: Self.identity(cwdInfo))
            resolvedExecutablePath = resolved.path
            resolvedDirectories = resolved.directories
            resolvedName = resolved.name
            executableFD = file
            executableParentFD = parent
            directoryFD = cwd
        } catch {
            if file >= 0 { _ = Darwin.close(file) }
            if parent >= 0 { _ = Darwin.close(parent) }
            _ = Darwin.close(cwd)
            throw error
        }
    }

    deinit { close() }

    /// Call immediately before dispatch. Pathname execution still has the accepted race after this check.
    /// A failed check retires this capture; approval must never authorize a replacement capture.
    public func recheck(checkCancellation: () throws -> Void = {}) throws {
        guard executableFD >= 0, directoryFD >= 0 else { throw CommandFilesystemCaptureError.closed }
        do {
            _ = try Self.recheck(executableFD: executableFD, directoryFD: directoryFD, executable: executable, directory: directory,
                resolvedPath: resolvedExecutablePath, caller: caller, deadline: ContinuousClock.now + Self.phaseTimeout,
                checkCancellation: checkCancellation)
        } catch { close(); throw error }
    }

    /// The worker gets duplicate descriptors. Retiring the request cannot invalidate or reuse them.
    func makeRecheck() throws -> Recheck {
        guard executableFD >= 0, directoryFD >= 0 else { throw CommandFilesystemCaptureError.closed }
        let file = fcntl(executableFD, F_DUPFD_CLOEXEC, 0)
        guard file >= 0 else { throw CommandFilesystemCaptureError.system(errno) }
        let cwd = fcntl(directoryFD, F_DUPFD_CLOEXEC, 0)
        guard cwd >= 0 else {
            let error = errno
            _ = Darwin.close(file)
            throw CommandFilesystemCaptureError.system(error)
        }
        return Recheck(captureID: captureID, executableFD: file, directoryFD: cwd, executable: executable,
            directory: directory, resolvedPath: resolvedExecutablePath, caller: caller)
    }

    final class Recheck: Sendable {
        private let captureID: UUID
        private let executableFD: Int32
        private let directoryFD: Int32
        private let executable: CapturedExecutable
        private let directory: CapturedDirectory
        private let resolvedPath: Data
        private let caller: CommandFilesystemCaller

        fileprivate init(captureID: UUID, executableFD: Int32, directoryFD: Int32, executable: CapturedExecutable,
                         directory: CapturedDirectory, resolvedPath: Data, caller: CommandFilesystemCaller) {
            self.captureID = captureID; self.executableFD = executableFD; self.directoryFD = directoryFD
            self.executable = executable; self.directory = directory; self.resolvedPath = resolvedPath
            self.caller = caller
        }

        func run(deadline: ContinuousClock.Instant, checkProbe: () throws -> Void) throws -> MetadataProof {
            let observed = try CommandFilesystemCapture.recheck(executableFD: executableFD, directoryFD: directoryFD,
                executable: executable, directory: directory, resolvedPath: resolvedPath, caller: caller, deadline: deadline,
                checkProbe: checkProbe, checkCancellation: {})
            return MetadataProof(captureID: captureID, observed: observed)
        }

        deinit {
            _ = Darwin.close(executableFD)
            _ = Darwin.close(directoryFD)
        }
    }

    struct MetadataProof: Sendable {
        fileprivate let captureID: UUID
        fileprivate let observed: stat
    }

    /// Compare the final metadata with the completed hash probe without reading the file again.
    /// The serialized owner compares the previously proved identity before durable admission or dispatch.
    /// Keep the Authority credentials here. Caller lookups run on the worker before this check.
    func verifyMetadata(_ proof: MetadataProof) throws {
        guard executableFD >= 0, executableParentFD >= 0, directoryFD >= 0 else { throw CommandFilesystemCaptureError.closed }
        guard proof.captureID == captureID else { throw CommandFilesystemCaptureError.changed }
        try Self.checkDirectory(directoryFD, path: directory.path, identity: directory.identity)
        try Self.checkNamedExecutable(executable.path, held: proof.observed)
        for component in resolvedDirectories {
            let named = try Self.namedInfo(AT_FDCWD, component.path, flags: AT_SYMLINK_NOFOLLOW)
            guard named.st_mode & S_IFMT == S_IFDIR, Self.identity(named) == component.identity else {
                throw CommandFilesystemCaptureError.changed
            }
        }
        guard Self.identity(try Self.directoryInfo(executableParentFD)) == resolvedDirectories.last?.identity,
              Self.stable(proof.observed, try Self.namedInfo(executableParentFD, resolvedName, flags: AT_SYMLINK_NOFOLLOW)),
              Self.stable(proof.observed, try Self.executableInfo(executableFD)) else {
            throw CommandFilesystemCaptureError.changed
        }
        try Self.checkNamedExecutable(resolvedExecutablePath, held: proof.observed, followLink: false)
    }

    private static func recheck(executableFD: Int32, directoryFD: Int32, executable: CapturedExecutable,
                                directory: CapturedDirectory, resolvedPath: Data, caller: CommandFilesystemCaller,
                                deadline: ContinuousClock.Instant,
                                checkProbe: () throws -> Void = {},
                                checkCancellation: () throws -> Void) throws -> stat {
        try checkDeadline(deadline, checkProbe: checkProbe)
        try checkCancellation()
        let info = try executableInfo(executableFD)
        guard identity(info) == executable.identity else { throw CommandFilesystemCaptureError.changed }
        func checkNames() throws {
            try caller.withIdentity {
                try checkDirectory(directoryFD, path: directory.path, identity: directory.identity)
                try checkNamedExecutable(executable.path, held: info)
                try checkNamedExecutable(resolvedPath, held: info, followLink: false)
            }
        }
        try checkNames()
        let observed = try digest(executableFD, initial: info, deadline: deadline, checkProbe: checkProbe,
            checkCancellation: checkCancellation)
        guard observed == executable.sha256 else { throw CommandFilesystemCaptureError.changed }
        try checkCancellation()
        try checkNames()
        try checkDeadline(deadline, checkProbe: checkProbe)
        return info
    }

    /// Borrow the retained directory only for this call. Do not close, retain, or pass the descriptor to another thread.
    public func withBorrowedDirectoryDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard executableFD >= 0, directoryFD >= 0 else { throw CommandFilesystemCaptureError.closed }
        return try body(directoryFD)
    }

    public func close() {
        if executableFD >= 0 { _ = Darwin.close(executableFD); executableFD = -1 }
        if executableParentFD >= 0 { _ = Darwin.close(executableParentFD); executableParentFD = -1 }
        if directoryFD >= 0 { _ = Darwin.close(directoryFD); directoryFD = -1 }
    }

    private static func validatePath(_ path: Data) throws {
        guard path.first == 0x2f, !path.contains(0), path.count < Int(PATH_MAX) else {
            throw CommandFilesystemCaptureError.invalidPath
        }
    }

    private static func withPath<T>(_ path: Data, _ body: (UnsafePointer<CChar>) throws -> T) rethrows -> T {
        var terminated = path
        terminated.append(0)
        return try terminated.withUnsafeBytes { bytes in
            try body(bytes.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
    }

    private static func openPath(_ path: Data, flags: Int32) throws -> Int32 {
        let fd = withPath(path) { Darwin.open($0, flags) }
        guard fd >= 0 else { throw CommandFilesystemCaptureError.system(errno) }
        return fd
    }

    private struct ResolvedDirectory {
        let path: Data
        let identity: CapturedFileIdentity
    }

    private struct ResolvedExecutable {
        let info: stat
        let parent: Int32
        let name: Data
        let path: Data
        let directories: [ResolvedDirectory]
    }

    /// Retain each parent across lookup. Keep their identities and the final parent descriptor.
    private static func resolveExecutable(_ requested: Data, deadline: ContinuousClock.Instant,
                                          checkProbe: () throws -> Void) throws -> ResolvedExecutable {
        let directoryFlags = searchDirectoryFlags | O_NOFOLLOW
        var parents = [try openPath(Data([0x2f]), flags: directoryFlags)]
        defer { for parent in parents { _ = Darwin.close(parent) } }
        let root = ResolvedDirectory(path: Data([0x2f]), identity: identity(try directoryInfo(parents[0])))
        var directories = [root]
        var components = requested.dropFirst().split(separator: 0x2f, omittingEmptySubsequences: false).map { Data($0) }
        var linksRemaining = 40
        while !components.isEmpty {
            try checkDeadline(deadline, checkProbe: checkProbe)
            let name = components.removeFirst()
            if name.isEmpty || name == Data([0x2e]) { continue }
            if name == Data([0x2e, 0x2e]) {
                if parents.count > 1 {
                    _ = Darwin.close(parents.removeLast())
                    directories.removeLast()
                }
                continue
            }
            let parent = parents[parents.count - 1]
            let entry = try namedInfo(parent, name, flags: AT_SYMLINK_NOFOLLOW)
            switch entry.st_mode & S_IFMT {
            case S_IFLNK:
                guard linksRemaining > 0 else { throw CommandFilesystemCaptureError.system(ELOOP) }
                linksRemaining -= 1
                var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
                let length = withPath(name) { component in
                    buffer.withUnsafeMutableBufferPointer { readlinkat(parent, component, $0.baseAddress!, $0.count) }
                }
                guard length >= 0 else { throw CommandFilesystemCaptureError.system(errno) }
                guard length > 0, length < buffer.count else { throw CommandFilesystemCaptureError.invalidPath }
                try checkDeadline(deadline, checkProbe: checkProbe)
                guard stable(entry, try namedInfo(parent, name, flags: AT_SYMLINK_NOFOLLOW)) else {
                    throw CommandFilesystemCaptureError.changed
                }
                let target = Data(buffer.prefix(length).map { UInt8(bitPattern: $0) })
                if target.first == 0x2f {
                    while parents.count > 1 { _ = Darwin.close(parents.removeLast()) }
                    directories = [root]
                }
                components = target.split(separator: 0x2f, omittingEmptySubsequences: false).map { Data($0) } + components
                guard components.reduce(0, { $0 + $1.count + 1 }) <= Int(PATH_MAX) else {
                    throw CommandFilesystemCaptureError.system(ENAMETOOLONG)
                }
            case S_IFDIR where !components.isEmpty:
                let descriptor = try openComponent(parent, name, flags: directoryFlags)
                do {
                    guard identity(entry) == identity(try directoryInfo(descriptor)) else {
                        throw CommandFilesystemCaptureError.changed
                    }
                } catch {
                    _ = Darwin.close(descriptor)
                    throw error
                }
                parents.append(descriptor)
                var path = directories[directories.count - 1].path
                if path.count > 1 { path.append(0x2f) }
                path.append(name)
                guard path.count < Int(PATH_MAX) else {
                    throw CommandFilesystemCaptureError.system(ENAMETOOLONG)
                }
                directories.append(.init(path: path, identity: identity(entry)))
            case S_IFREG where components.isEmpty:
                try requireExecutable(entry)
                var path = directories[directories.count - 1].path
                if path.count > 1 { path.append(0x2f) }
                path.append(name)
                try validatePath(path)
                let retainedParent = parents.removeLast()
                return ResolvedExecutable(info: entry, parent: retainedParent, name: name, path: path, directories: directories)
            default:
                throw CommandFilesystemCaptureError.invalidExecutable
            }
        }
        throw CommandFilesystemCaptureError.invalidExecutable
    }

    private static func openComponent(_ parent: Int32, _ name: Data, flags: Int32) throws -> Int32 {
        let fd = withPath(name) { openat(parent, $0, flags) }
        guard fd >= 0 else { throw CommandFilesystemCaptureError.system(errno) }
        return fd
    }

    private static func namedInfo(_ parent: Int32, _ name: Data, flags: Int32) throws -> stat {
        var result = stat()
        guard withPath(name, { fstatat(parent, $0, &result, flags) }) == 0 else {
            throw CommandFilesystemCaptureError.system(errno)
        }
        return result
    }

    private static func info(_ fd: Int32) throws -> stat {
        var result = stat()
        guard fstat(fd, &result) == 0 else { throw CommandFilesystemCaptureError.system(errno) }
        return result
    }

    private static func executableInfo(_ fd: Int32) throws -> stat {
        let result = try info(fd)
        try requireExecutable(result)
        return result
    }

    private static func requireExecutable(_ result: stat) throws {
        guard result.st_mode & S_IFMT == S_IFREG, result.st_mode & 0o111 != 0,
              (0...maximumExecutableBytes).contains(result.st_size) else {
            throw CommandFilesystemCaptureError.invalidExecutable
        }
    }

    private static func directoryInfo(_ fd: Int32) throws -> stat {
        let result = try info(fd)
        guard result.st_mode & S_IFMT == S_IFDIR else { throw CommandFilesystemCaptureError.invalidDirectory }
        return result
    }

    private static func identity(_ info: stat) -> CapturedFileIdentity {
        CapturedFileIdentity(device: UInt64(UInt32(bitPattern: info.st_dev)), inode: info.st_ino)
    }

    private static func checkNamedExecutable(_ path: Data, held: stat, followLink: Bool = true) throws {
        guard stable(held, try namedInfo(AT_FDCWD, path, flags: followLink ? 0 : AT_SYMLINK_NOFOLLOW)) else {
            throw CommandFilesystemCaptureError.changed
        }
    }

    private static func checkDirectory(_ fd: Int32, path: Data, identity expected: CapturedFileIdentity) throws {
        let held = try directoryInfo(fd)
        var named = stat()
        guard withPath(path, { fstatat(AT_FDCWD, $0, &named, 0) }) == 0 else { throw CommandFilesystemCaptureError.system(errno) }
        guard identity(held) == expected, identity(named) == expected, named.st_mode & S_IFMT == S_IFDIR else {
            throw CommandFilesystemCaptureError.changed
        }
    }

    private static func stable(_ before: stat, _ after: stat) -> Bool {
        before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_mode == after.st_mode &&
            before.st_uid == after.st_uid && before.st_gid == after.st_gid && before.st_size == after.st_size &&
            before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
            before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
    }

    private static func checkDeadline(_ deadline: ContinuousClock.Instant, checkProbe: () throws -> Void) throws {
        try checkProbe()
        guard ContinuousClock.now < deadline else { throw CommandFilesystemCaptureError.timedOut }
    }

    private static func digest(_ fd: Int32, initial: stat, deadline: ContinuousClock.Instant,
                               checkProbe: () throws -> Void,
                               checkCancellation: () throws -> Void) throws -> Data {
        var hash = SHA256()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while offset < initial.st_size {
            try checkDeadline(deadline, checkProbe: checkProbe)
            try checkCancellation()
            let length = Int(min(off_t(buffer.count), initial.st_size - offset))
            let count = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, length, offset) }
            if count < 0 {
                if errno == EINTR { continue }
                throw CommandFilesystemCaptureError.system(errno)
            }
            guard count > 0 else { throw CommandFilesystemCaptureError.changed }
            hash.update(data: Data(buffer.prefix(count)))
            offset += off_t(count)
        }
        try checkDeadline(deadline, checkProbe: checkProbe)
        try checkCancellation()
        guard stable(initial, try executableInfo(fd)) else { throw CommandFilesystemCaptureError.changed }
        return Data(hash.finalize())
    }
}
