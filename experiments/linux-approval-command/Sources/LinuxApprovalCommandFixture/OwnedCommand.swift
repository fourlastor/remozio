import Foundation
import Glibc
import RemozioProtocol

/// Owns only a fixed, unprivileged command and its pipes. Capture claims are fixture data,
/// not a protected Linux requester or executable authentication mechanism.
final class OwnedCommand {
    static let line = Data("remozio-fixture-output\n".utf8)
    static let executable = "/usr/bin/tee"
    let directory: String
    let marker: String
    private var descriptors: [Int32] = []
    private var child: pid_t = 0
    private var reaped = false
    let capture: LinuxCommandCapture

    init(directory: String, submission: CapturedSubmission? = nil) throws {
        self.directory = directory
        marker = directory + "/command.marker"
        var pairs: [Int32] = []
        do {
            for _ in 0..<3 {
                var pair: [Int32] = [-1, -1]
                try require(pipe(&pair) == 0, "pipe")
                pairs += pair
                for fd in pair { try require(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "pipeFlags") }
            }
            let input = try Self.stream(pairs[0])
            let output = try Self.stream(pairs[3])
            let error = try Self.stream(pairs[5])
            let uid = getuid(), gid = getgid()
            try require(uid == geteuid() && gid == getegid(), "ordinaryCredentials")
            let groupCount = getgroups(0, nil)
            try require(groupCount >= 0 && groupCount <= 256, "groups")
            var groups = [gid_t](repeating: 0, count: Int(groupCount))
            try require(getgroups(groupCount, &groups) == groupCount, "groups")
            let sortedGroups = Array(Set(groups)).sorted()
            let credentials = CapturedLinuxCredentials(realUID: uid, effectiveUID: uid, savedUID: uid,
                filesystemUID: uid, realGID: gid, effectiveGID: gid, savedGID: gid, filesystemGID: gid,
                supplementaryGroups: sortedGroups)
            capture = try LinuxCommandCapture(executable: Self.observeExecutable(Self.executable),
                arguments: [Self.executable, "-a", marker].map { Data($0.utf8) },
                directory: .init(path: Data(directory.utf8), identity: Self.identity(directory)),
                target: .init(uid: uid, gid: gid, supplementaryGroups: sortedGroups, observedName: nil),
                environment: [.init(name: Data("LANG".utf8), value: Data("C".utf8), source: .minimal)],
                input: input, requester: .init(pid: UInt32(getpid()), processBinding: randomBytes(16),
                    monitorIncarnation: randomBytes(16), execEpoch: 1,
                    executable: Self.observeExecutable("/proc/self/exe"), credentials: credentials,
                    sessionID: nil, codePolicyDigest: digest(Data("synthetic fixture policy".utf8))),
                unverifiedRationale: "Disposable component fixture; synthetic requester claims",
                submission: submission ?? .init(id: randomBytes(16), nonce: randomBytes(32), callerBinding: randomBytes(16)),
                stdioLayout: .init(input: .init(source: input, access: .readOnly, flags: []),
                    output: .init(source: output, access: .writeOnly, flags: []),
                    error: .init(source: error, access: .writeOnly, flags: []), terminal: nil, ptyMask: 0),
                limits: FixtureProtocol.limits)
            descriptors = pairs
        } catch {
            for fd in pairs { _ = close(fd) }
            throw error
        }
    }

    deinit {
        if child > 0 && !reaped {
            _ = kill(child, SIGKILL)
            var status: Int32 = 0
            while waitpid(child, &status, 0) < 0 && errno == EINTR {}
        }
        for fd in descriptors where fd >= 0 { _ = close(fd) }
    }

    func validate(_ decoded: LinuxCommandCapture) throws {
        try require(decoded == capture, "retainedCaptureMismatch")
        try require(try Self.observeExecutable(Self.executable) == capture.executable, "executableChanged")
        try require(try Self.identity(directory) == capture.directory.identity, "directoryChanged")
        for (index, source) in [(0, capture.stdioLayout.input.source), (3, capture.stdioLayout.output.source),
                                (5, capture.stdioLayout.error.source)] {
            try require(try Self.identity(descriptors[index]) == source.identity, "pipeChanged")
        }
    }

    /// No process-group flags: the child stays in the supervising runner's session/group.
    func run() throws -> (output: Data, exit: Int32) {
        try require(child == 0, "commandAlreadyStarted")
        try validate(capture)
        var actions = posix_spawn_file_actions_t()
        try require(posix_spawn_file_actions_init(&actions) == 0, "spawnActions")
        defer { posix_spawn_file_actions_destroy(&actions) }
        for (index, target) in [(0, Int32(0)), (3, Int32(1)), (5, Int32(2))] {
            try require(posix_spawn_file_actions_adddup2(&actions, descriptors[index], target) == 0, "spawnDup")
        }
        try require(posix_spawn_file_actions_addchdir_np(&actions, directory) == 0, "spawnDirectory")
        let arguments: [String] = [Self.executable, "-a", marker]
        let strings = arguments.map { $0.withCString { strdup($0)! } }
        let environment = [strdup("LANG=C")!]
        defer { for string in strings + environment { free(string) } }
        var argv = strings.map { Optional($0) } + [nil]
        var envp = environment.map { Optional($0) } + [nil]
        var spawned: pid_t = 0
        try require(posix_spawn(&spawned, Self.executable, &actions, nil, &argv, &envp) == 0, "spawn")
        child = spawned
        // This observation also checks that outer process-group cleanup reaches our child.
        try require(getpgid(child) == getpgrp(), "childProcessGroup")
        for index in [0, 3, 5] { closeDescriptor(index) }
        let written = Self.line.withUnsafeBytes { write(descriptors[1], $0.baseAddress, $0.count) }
        try require(written == Self.line.count, "stdinWrite")
        closeDescriptor(1)
        for index in [2, 4] {
            let flags = fcntl(descriptors[index], F_GETFL)
            try require(flags >= 0 && fcntl(descriptors[index], F_SETFL, flags | O_NONBLOCK) == 0, "readFlags")
        }
        let deadline = try Self.milliseconds() + 5_000
        var output = Data(), errors = Data(), status: Int32 = 0
        while !reaped || descriptors[2] >= 0 || descriptors[4] >= 0 {
            try require(try Self.milliseconds() < deadline, "commandTimeout")
            var pollDescriptors = [2, 4].map { pollfd(fd: descriptors[$0], events: Int16(POLLIN | POLLHUP), revents: 0) }
            let result = poll(&pollDescriptors, 2, 20)
            try require(result >= 0 || errno == EINTR, "poll")
            for (position, index) in [2, 4].enumerated() where descriptors[index] >= 0 {
                guard pollDescriptors[position].revents != 0 else { continue }
                var bytes = [UInt8](repeating: 0, count: 1024)
                let count = read(descriptors[index], &bytes, bytes.count)
                if count == 0 { closeDescriptor(index) }
                else if count > 0 {
                    if index == 2 { output.append(contentsOf: bytes.prefix(count)) }
                    else { errors.append(contentsOf: bytes.prefix(count)) }
                    try require(output.count <= 1024 && errors.count <= 1024, "outputLimit")
                } else { try require(errno == EAGAIN || errno == EINTR, "read") }
            }
            if !reaped {
                let observed = waitpid(child, &status, WNOHANG)
                if observed == child { reaped = true }
                else { try require(observed == 0 || errno == EINTR, "wait") }
            }
        }
        try require(status & 0x7f == 0 && errors.isEmpty, "childFailure")
        return (output, (status >> 8) & 0xff)
    }

    private func closeDescriptor(_ index: Int) { _ = close(descriptors[index]); descriptors[index] = -1 }
    private static func milliseconds() throws -> UInt64 {
        var value = timespec()
        try require(clock_gettime(CLOCK_MONOTONIC, &value) == 0, "timeoutClock")
        return UInt64(value.tv_sec) * 1000 + UInt64(value.tv_nsec) / 1_000_000
    }
    private static func identity(_ descriptor: Int32) throws -> CapturedFileIdentity {
        var value = stat()
        try require(fstat(descriptor, &value) == 0, "fstat")
        return .init(device: UInt64(value.st_dev), inode: UInt64(value.st_ino))
    }
    private static func identity(_ path: String) throws -> CapturedFileIdentity {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC)
        try require(descriptor >= 0, "openIdentity")
        defer { close(descriptor) }
        return try identity(descriptor)
    }
    private static func observeExecutable(_ path: String) throws -> CapturedExecutable {
        .init(path: Data(path.utf8), identity: try identity(path), sha256: digest(try Data(contentsOf: URL(fileURLWithPath: path))))
    }
    private static func stream(_ fd: Int32) throws -> CapturedCommandInput {
        .init(kind: .pipe, streamBinding: randomBytes(16), observedPath: nil, identity: try identity(fd))
    }
}
