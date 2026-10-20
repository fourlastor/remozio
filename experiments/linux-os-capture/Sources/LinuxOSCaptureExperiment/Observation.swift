import Crypto
import Foundation
import Glibc
import RemozioProtocol

enum ObservationError: String, Error {
    case unavailable, malformedCredentials, unsupportedCredentials, invalidPath, unsupportedObject
    case changedObject, changedCredentials, invalidDescriptor, unsupportedFlags, changedStream, captureMismatch, retired
}

func requireObservation(_ condition: Bool, _ error: ObservationError) throws {
    guard condition else { throw error }
}

// Paths are bytes throughout: no lossy UTF-8 conversion or URL normalization.
func withPath<T>(_ path: Data, _ body: (UnsafePointer<CChar>) throws -> T) throws -> T {
    try requireObservation(path.first == 47 && path.count <= 4096 && !path.contains(0), .invalidPath)
    return try (Array(path) + [0]).withUnsafeBytes { try body($0.bindMemory(to: CChar.self).baseAddress!) }
}

final class OwnedFD {
    let value: Int32
    init(_ value: Int32) throws {
        try requireObservation(value >= 0, .invalidDescriptor)
        self.value = value
    }
    deinit { _ = close(value) }
}

struct FileObservation: Equatable {
    let identity: CapturedFileIdentity
    let mode: mode_t
    let uid: uid_t
    let gid: gid_t
    let size: off_t
    let modifiedSeconds: Int
    let modifiedNanoseconds: Int
    let changedSeconds: Int
    let changedNanoseconds: Int

    init(_ fd: Int32) throws {
        var info = stat()
        try requireObservation(fstat(fd, &info) == 0, .unavailable)
        identity = .init(device: UInt64(info.st_dev), inode: UInt64(info.st_ino))
        mode = info.st_mode; uid = info.st_uid; gid = info.st_gid; size = info.st_size
        modifiedSeconds = info.st_mtim.tv_sec; modifiedNanoseconds = info.st_mtim.tv_nsec
        changedSeconds = info.st_ctim.tv_sec; changedNanoseconds = info.st_ctim.tv_nsec
    }

    // Directory contents can change; this comparison retains object identity and access metadata.
    func sameDirectory(_ other: Self) -> Bool {
        identity == other.identity && mode == other.mode && uid == other.uid && gid == other.gid
    }
}

func hashFile(_ fd: Int32) throws -> Data {
    let before = try FileObservation(fd)
    try requireObservation(before.mode & S_IFMT == S_IFREG && before.size >= 0 && before.size <= 67_108_864,
                           .unsupportedObject)
    var hash = SHA256(), offset: off_t = 0
    var buffer = [UInt8](repeating: 0, count: 32768)
    while offset < before.size {
        let count = pread(fd, &buffer, min(buffer.count, Int(before.size - offset)), offset)
        if count < 0 && errno == EINTR { continue }
        try requireObservation(count > 0, .changedObject)
        hash.update(data: Data(buffer.prefix(count)))
        offset += off_t(count)
    }
    try requireObservation(try FileObservation(fd) == before, .changedObject)
    return Data(hash.finalize())
}

final class RetainedExecutable {
    let descriptor: OwnedFD
    let observation: FileObservation
    let capture: CapturedExecutable

    init(path: Data, retainedDescriptor: OwnedFD? = nil) throws {
        descriptor = try retainedDescriptor ?? OwnedFD(withPath(path) { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) })
        observation = try FileObservation(descriptor.value)
        try requireObservation(observation.mode & S_IFMT == S_IFREG && observation.mode & 0o111 != 0, .unsupportedObject)
        capture = try .init(path: path, identity: observation.identity, sha256: hashFile(descriptor.value))
        try requireObservation(try FileObservation(descriptor.value) == observation, .changedObject)
        try checkNamedObject()
    }

    func recheck(afterNamedHashForTesting: (() throws -> Void)? = nil) throws {
        try requireObservation(try FileObservation(descriptor.value) == observation && hashFile(descriptor.value) == capture.sha256,
                               .changedObject)
        let current = try RetainedExecutable(path: capture.path)
        try requireObservation(current.observation == observation && current.capture == capture, .changedObject)
        // A deterministic fixture hook exercises pathname replacement during the hash interval.
        try afterNamedHashForTesting?()
        try checkNamedObject()
        try requireObservation(try FileObservation(descriptor.value) == observation, .changedObject)
    }

    private func checkNamedObject() throws {
        let named = try OwnedFD(withPath(capture.path) { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) })
        try requireObservation(try FileObservation(named.value) == observation, .changedObject)
    }
}

final class RetainedDirectory {
    let descriptor: OwnedFD
    let observation: FileObservation
    let capture: CapturedDirectory
    init(path: Data) throws {
        descriptor = try OwnedFD(withPath(path) { open($0, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW) })
        observation = try FileObservation(descriptor.value)
        capture = .init(path: path, identity: observation.identity)
    }
    func recheck() throws {
        try requireObservation(try observation.sameDirectory(FileObservation(descriptor.value)), .changedObject)
        let current = try RetainedDirectory(path: capture.path)
        try requireObservation(observation.sameDirectory(current.observation), .changedObject)
    }
}

struct CredentialObservation: Equatable {
    let credentials: CapturedLinuxCredentials
    let observedSupplementaryGroups: [UInt32]

    static func parse(_ bytes: Data) throws -> Self {
        try requireObservation(bytes.count <= 65536, .malformedCredentials)
        // The kernel task name can contain arbitrary bytes. Only these ASCII numeric rows are parsed.
        var fields = [Data: [UInt32]]()
        let wanted = [Data("Uid:".utf8), Data("Gid:".utf8), Data("Groups:".utf8)]
        for line in bytes.split(separator: 10) {
            guard let key = wanted.first(where: { line.starts(with: $0) }) else { continue }
            try requireObservation(fields[key] == nil, .malformedCredentials)
            let tokens = line.dropFirst(key.count).split(whereSeparator: { $0 == 32 || $0 == 9 })
            fields[key] = try tokens.map { token in
                try requireObservation(!token.isEmpty && token.allSatisfy { (48...57).contains($0) }, .malformedCredentials)
                guard let value = UInt32(String(decoding: token, as: UTF8.self)) else { throw ObservationError.malformedCredentials }
                return value
            }
        }
        guard let uids = fields[wanted[0]], uids.count == 4, let gids = fields[wanted[1]], gids.count == 4,
              let groups = fields[wanted[2]], groups.count <= 256 else { throw ObservationError.malformedCredentials }
        return Self(credentials: .init(realUID: uids[0], effectiveUID: uids[1], savedUID: uids[2], filesystemUID: uids[3],
            realGID: gids[0], effectiveGID: gids[1], savedGID: gids[2], filesystemGID: gids[3], supplementaryGroups: Set(groups).sorted()),
            observedSupplementaryGroups: groups)
    }

    static func current() throws -> Self {
        let fd = try OwnedFD(open("/proc/thread-self/status", O_RDONLY | O_CLOEXEC | O_NOFOLLOW))
        var data = Data(), chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(fd.value, &chunk, chunk.count)
            if count < 0 && errno == EINTR { continue }
            try requireObservation(count >= 0, .unavailable)
            if count == 0 { break }
            data.append(contentsOf: chunk.prefix(count))
            try requireObservation(data.count <= 65536, .malformedCredentials)
        }
        let result = try parse(data), c = result.credentials
        let count = getgroups(0, nil)
        try requireObservation(count >= 0 && count <= 256, .unavailable)
        var groups = [gid_t](repeating: 0, count: Int(count))
        try requireObservation(getgroups(count, &groups) == count, .unavailable)
        try requireObservation(c.realUID == getuid() && c.effectiveUID == geteuid() && c.realGID == getgid() &&
            c.effectiveGID == getegid() && result.observedSupplementaryGroups.sorted() == groups.sorted(), .changedCredentials)
        return result
    }

    func requireOrdinaryAccount() throws {
        let c = credentials
        try requireObservation(c.realUID != 0 && c.realUID == c.effectiveUID && c.realUID == c.savedUID &&
            c.realUID == c.filesystemUID && c.realGID == c.effectiveGID && c.realGID == c.savedGID &&
            c.realGID == c.filesystemGID, .unsupportedCredentials)
    }
}

struct StreamObservation: Equatable {
    let identity: CapturedFileIdentity
    let kind: CommandInputKind
    let access: CommandStreamAccess
    let flags: CommandStreamFlags
    let rawFlags: Int32

    init(_ fd: Int32) throws {
        let info = try FileObservation(fd), raw = fcntl(fd, F_GETFL)
        try requireObservation(raw >= 0, .invalidDescriptor)
        switch info.mode & S_IFMT {
        case S_IFIFO: kind = .pipe
        case S_IFREG: kind = .file
        // Other kernel kinds are explicitly unavailable in this experiment; never relabel them as pipes.
        default: throw ObservationError.unsupportedObject
        }
        switch raw & O_ACCMODE {
        case O_RDONLY: access = .readOnly
        case O_WRONLY: access = .writeOnly
        case O_RDWR: access = .readWrite
        default: throw ObservationError.invalidDescriptor
        }
        // O_LARGEFILE is an ABI bit with no stream semantic. Unknown bits fail, including O_PATH/O_DIRECT.
        let known = O_ACCMODE | O_APPEND | O_NONBLOCK | O_ASYNC | O_SYNC | O_DSYNC | Int32(0o100000)
        try requireObservation(raw & ~known == 0, .unsupportedFlags)
        var semantic: CommandStreamFlags = []
        if raw & O_APPEND != 0 { semantic.insert(.append) }
        if raw & O_NONBLOCK != 0 { semantic.insert(.nonblocking) }
        if raw & O_ASYNC != 0 { semantic.insert(.asynchronous) }
        if raw & (O_SYNC | O_DSYNC) != 0 { semantic.insert(.synchronous) }
        identity = info.identity; flags = semantic; rawFlags = raw
    }
}

final class RetainedStream {
    let descriptor: OwnedFD
    let observation: StreamObservation
    let capture: CapturedCommandStream
    init(_ fd: Int32, fixtureBinding: Data) throws {
        descriptor = try OwnedFD(fcntl(fd, F_DUPFD_CLOEXEC, 3))
        observation = try StreamObservation(descriptor.value)
        capture = .init(source: .init(kind: observation.kind, streamBinding: fixtureBinding, observedPath: nil,
            identity: observation.identity), access: observation.access, flags: observation.flags)
    }
    func recheck() throws {
        try requireObservation(try StreamObservation(descriptor.value) == observation &&
            fcntl(descriptor.value, F_GETFD) == FD_CLOEXEC, .changedStream)
    }
}

/// All protected-caller fields are injected fixture data, never inferred from OS observations.
struct SyntheticBindings {
    let process = Data(repeating: 1, count: 16)
    let monitor = Data(repeating: 2, count: 16)
    let policy = Data(SHA256.hash(data: Data("synthetic fixture policy; not trusted code".utf8)))
    let submission = CapturedSubmission(id: Data(repeating: 3, count: 16), nonce: Data(repeating: 4, count: 32),
                                       callerBinding: Data(repeating: 5, count: 16))
}

/// Self-observation component only. No IPC peer, ptrace stop, trusted caller, grants or execution authority.
final class RetainedOSCapture {
    static let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 32, maxItems: 4096)
    let executable: RetainedExecutable
    let requesterExecutable: RetainedExecutable
    let directory: RetainedDirectory
    let streams: [RetainedStream]
    let credentials: CredentialObservation
    let session: pid_t
    let capture: LinuxCommandCapture
    private var retired = false

    init(executablePath: Data, directoryPath: Data, descriptors: [Int32], bindings: SyntheticBindings) throws {
        try requireObservation(descriptors.count == 3, .invalidDescriptor)
        credentials = try .current()
        try credentials.requireOrdinaryAccount()
        executable = try .init(path: executablePath)
        directory = try .init(path: directoryPath)
        var path = [UInt8](repeating: 0, count: 4097)
        let length = readlink("/proc/thread-self/exe", &path, path.count)
        try requireObservation(length > 0 && length <= 4096, .unavailable)
        // Open the kernel's executable object, not just the pathname that readlink returned.
        let liveExecutable = try OwnedFD(open("/proc/thread-self/exe", O_RDONLY | O_CLOEXEC | O_NONBLOCK))
        requesterExecutable = try .init(path: Data(path.prefix(length)), retainedDescriptor: liveExecutable)
        streams = try descriptors.enumerated().map { try RetainedStream($0.element,
            fixtureBinding: Data(repeating: UInt8($0.offset + 6), count: 16)) }
        session = getsid(0)
        try requireObservation(session > 0, .unavailable)
        let c = credentials.credentials
        capture = try .init(executable: executable.capture, arguments: [executablePath], directory: directory.capture,
            target: .init(uid: c.effectiveUID, gid: c.effectiveGID, supplementaryGroups: c.supplementaryGroups, observedName: nil),
            environment: [.init(name: Data("LANG".utf8), value: Data("C".utf8), source: .minimal)],
            input: streams[0].capture.source,
            requester: .init(pid: UInt32(getpid()), processBinding: bindings.process, monitorIncarnation: bindings.monitor,
                execEpoch: 1, executable: requesterExecutable.capture, credentials: c, sessionID: UInt32(session), codePolicyDigest: bindings.policy),
            unverifiedRationale: "OS observation fixture; protected caller bindings and policy are synthetic; trustedCode=false",
            submission: bindings.submission,
            stdioLayout: .init(input: streams[0].capture, output: streams[1].capture, error: streams[2].capture, terminal: nil, ptyMask: 0),
            limits: Self.limits)
        try requireObservation(try CredentialObservation.current() == credentials, .changedCredentials)
    }

    /// A synchronous fixture callback follows rechecks. This is not the stopped-monitor/executor handshake.
    func withRecheckedFixtureHandoff<T>(_ decoded: LinuxCommandCapture, _ body: () throws -> T) throws -> T {
        try requireObservation(!retired, .retired)
        do {
            try requireObservation(decoded == capture, .captureMismatch)
            try executable.recheck(); try requesterExecutable.recheck(); try directory.recheck()
            for stream in streams { try stream.recheck() }
            try requireObservation(try CredentialObservation.current() == credentials && getsid(0) == session, .changedCredentials)
            return try body()
        } catch {
            retired = true
            throw error
        }
    }
}
