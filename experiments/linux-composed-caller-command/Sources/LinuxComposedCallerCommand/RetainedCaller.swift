import Foundation
import Glibc
import LinuxApprovalFixtureCore
import LinuxOSObservation
import RemozioProtocol

/// Why the owner refused. Each value names the boundary whose observation failed.
enum Refusal: String, Error {
    case carrier, monitor, caller, observation, grant, target, executor, command, directory, stream, capture, decision
}

func refuse(_ condition: Bool, _ refusal: Refusal) throws {
    guard condition else { throw refusal }
}

/// Reads at most 64 KiB from a file opened relative to a retained directory descriptor.
func readRelative(_ directory: Int32, _ name: String) throws -> Data {
    let fd = try OwnedFD(openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW))
    return try withExtendedLifetime(fd) {
        var data = Data(), chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(fd.value, &chunk, chunk.count)
            if count < 0 && errno == EINTR { continue }
            try requireObservation(count >= 0, .unavailable)
            if count == 0 { return data }
            data.append(contentsOf: chunk.prefix(count))
            try requireObservation(data.count <= 65536, .unavailable)
        }
    }
}

/// Raw link bytes; no lossy String conversion.
func readLinkRelative(_ directory: Int32, _ name: String) throws -> Data {
    var buffer = [UInt8](repeating: 0, count: 4097)
    let length = readlinkat(directory, name, &buffer, buffer.count)
    try requireObservation(length > 0 && length <= 4096, .unavailable)
    return Data(buffer.prefix(length))
}

func pidfdExited(_ pidfd: Int32) -> Bool {
    var ready = pollfd(fd: pidfd, events: Int16(POLLIN), revents: 0)
    return poll(&ready, 1, 0) != 0
}

func pidfdPID(_ pidfd: Int32) throws -> Int32 {
    let info = try readRelative(AT_FDCWD, "/proc/self/fdinfo/\(pidfd)")
    for line in info.split(separator: 10) where line.starts(with: Data("Pid:".utf8)) {
        guard let value = Int32(String(decoding: line.dropFirst(4), as: UTF8.self).trimmingCharacters(in: .whitespaces)) else {
            break
        }
        return value
    }
    throw ObservationError.unavailable
}

/// One snapshot of the fields this fixture binds from a task's procfs `status` and `stat`.
struct TaskObservation: Equatable {
    let pid: Int32
    let state: UInt8
    let tracer: Int32
    let credentials: CredentialObservation
    let capabilities: [String: UInt64]
    let session: UInt32

    init(status: Data, stat: Data) throws {
        var fields = [String: String]()
        for line in status.split(separator: 10) {
            guard let colon = line.firstIndex(of: 58) else { continue }
            let key = String(decoding: line[line.startIndex..<colon], as: UTF8.self)
            if ["Pid", "State", "TracerPid", "CapInh", "CapPrm", "CapEff", "CapAmb"].contains(key) {
                try requireObservation(fields[key] == nil, .malformedCredentials)
                fields[key] = String(decoding: line[line.index(after: colon)...], as: UTF8.self)
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        guard let pid = fields["Pid"].flatMap({ Int32($0) }), let tracer = fields["TracerPid"].flatMap({ Int32($0) }),
              let state = fields["State"]?.utf8.first else { throw ObservationError.malformedCredentials }
        var capabilities = [String: UInt64]()
        for key in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            guard let value = fields[key].flatMap({ UInt64($0, radix: 16) }) else { throw ObservationError.malformedCredentials }
            capabilities[key] = value
        }
        // The command name may contain ')' and spaces; fields resume after its final ')'.
        guard let close = stat.lastIndex(of: 41) else { throw ObservationError.malformedCredentials }
        let rest = stat[stat.index(after: close)...].split(separator: 32)
        guard rest.count > 3, let session = UInt32(String(decoding: rest[3], as: UTF8.self)), session > 0 else {
            throw ObservationError.malformedCredentials
        }
        self.pid = pid; self.state = state; self.tracer = tracer
        self.credentials = try .parse(status); self.capabilities = capabilities; self.session = session
    }

    static func read(_ procDirectory: Int32) throws -> Self {
        try Self(status: readRelative(procDirectory, "status"), stat: readRelative(procDirectory, "stat"))
    }

    /// Permitted, effective and ambient sets must be empty. An inheritable bit alone grants nothing
    /// without ambient or file capabilities; it is recorded, and file capabilities are refused separately.
    var holdsNoCapabilities: Bool { capabilities["CapPrm"] == 0 && capabilities["CapEff"] == 0 && capabilities["CapAmb"] == 0 }
}

/// The monitor-retained caller and its submitted streams, observed independently by this owner.
/// Single-threaded owner state; `@unchecked Sendable` only so policy closures can read it.
final class RetainedCaller: @unchecked Sendable {
    let callerPID: Int32
    let monitorPID: Int32
    let callerPidfd: OwnedFD
    let monitorPidfd: OwnedFD
    let proc: OwnedFD
    let directoryDescriptor: OwnedFD
    let executable: RetainedExecutable
    let directory: RetainedDirectory
    let streams: [RetainedStream]
    let admission: TaskObservation

    /// Bundle order: caller pidfd, monitor pidfd, proc task directory, executable, cwd, stdin, stdout, stderr.
    init(prepare: [String: Any], bundle: [OwnedFD], streamBindings: [Data]) throws {
        try refuse(bundle.count == 8 && streamBindings.count == 3, .carrier)
        guard let caller = prepare["caller"] as? Int, let monitor = prepare["monitor"] as? Int,
              let sender = prepare["sender"] as? [String: Any], let senderPID = sender["pid"] as? Int,
              let senderUID = sender["uid"] as? Int, let senderGID = sender["gid"] as? Int else { throw Refusal.carrier }
        callerPID = Int32(caller); monitorPID = Int32(monitor)
        callerPidfd = bundle[0]; monitorPidfd = bundle[1]; proc = bundle[2]; directoryDescriptor = bundle[4]
        try refuse(try pidfdPID(callerPidfd.value) == callerPID && pidfdPID(monitorPidfd.value) == monitorPID &&
            callerPID != getpid() && monitorPID != getpid(), .monitor)
        admission = try TaskObservation.read(proc.value)
        let c = admission.credentials.credentials
        try refuse(admission.pid == callerPID && senderPID == caller, .caller)
        try refuse(UInt32(senderUID) == c.realUID && UInt32(senderGID) == c.realGID, .carrier)
        try admission.credentials.requireOrdinaryAccount()
        // Raw link bytes name the objects; the retained descriptors from the stopped task must match them.
        executable = try RetainedExecutable(path: readLinkRelative(proc.value, "exe"), retainedDescriptor: bundle[3])
        directory = try RetainedDirectory(path: readLinkRelative(proc.value, "cwd"))
        try refuse(try FileObservation(directoryDescriptor.value).sameDirectory(directory.observation), .directory)
        streams = try (0..<3).map { try RetainedStream(bundle[5 + $0].value, fixtureBinding: streamBindings[$0]) }
        try refuse(streams.map(\.observation.access) == [.readOnly, .writeOnly, .writeOnly], .stream)
        try requireHeld()
    }

    /// Distinct process, executable and directory from this owner: no self-observation can stand in.
    func isRemote() throws -> Bool {
        let own = try RetainedExecutable(path: readLinkRelative(AT_FDCWD, "/proc/self/exe"))
        var cwd = stat()
        try requireObservation(stat(".", &cwd) == 0, .unavailable)
        return callerPID != getpid() && own.observation.identity != executable.observation.identity &&
            CapturedFileIdentity(device: UInt64(cwd.st_dev), inode: UInt64(cwd.st_ino)) != directory.observation.identity
    }

    /// Caller alive in this monitor's ptrace stop, monitor alive and not exited.
    func requireHeld() throws {
        _ = try monitorStatus()
        do {
            try refuse(!pidfdExited(callerPidfd.value), .caller)
            let task = try TaskObservation.read(proc.value)
            try refuse(task.state == UInt8(ascii: "t") && task.tracer == monitorPID, .monitor)
            try refuse(task.pid == callerPID && task.credentials == admission.credentials &&
                task.session == admission.session, .caller)
            try refuse(task.holdsNoCapabilities && task.capabilities == admission.capabilities, .caller)
        } catch is ObservationError { throw Refusal.caller }
    }

    /// Frozen by the supervisor: the monitor cannot release its stop while frozen.
    func requireMonitorFrozen() throws {
        try refuse(try monitorStatus().state == UInt8(ascii: "T"), .monitor)
    }

    /// Opened by numeric PID, accepted only while the retained pidfd stays live across the read.
    private func monitorStatus() throws -> TaskObservation {
        do {
            try refuse(!pidfdExited(monitorPidfd.value), .monitor)
            let directory = try OwnedFD(open("/proc/\(monitorPID)", O_RDONLY | O_DIRECTORY | O_CLOEXEC))
            let status = try withExtendedLifetime(directory) { try TaskObservation.read(directory.value) }
            try refuse(!pidfdExited(monitorPidfd.value) && status.pid == monitorPID, .monitor)
            return status
        } catch is ObservationError { throw Refusal.monitor }
    }

    /// Full independent recheck of the caller, its objects and streams against admission.
    func recheck() throws {
        try requireHeld()
        try requireMonitorFrozen()
        do {
            try refuse(try readLinkRelative(proc.value, "exe") == executable.capture.path, .caller)
            try executable.recheck()
        } catch is ObservationError { throw Refusal.caller }
        do {
            try refuse(try readLinkRelative(proc.value, "cwd") == directory.capture.path, .directory)
            try directory.recheck()
            try refuse(try FileObservation(directoryDescriptor.value).sameDirectory(directory.observation), .directory)
        } catch is ObservationError { throw Refusal.directory }
        do { for stream in streams { try stream.recheck() } } catch is ObservationError { throw Refusal.stream }
    }

    func currentCredentials() throws -> CapturedLinuxCredentials {
        try requireHeld()
        return try TaskObservation.read(proc.value).credentials.credentials
    }

    /// A post-spawn observation only: it can record that the requester was lost, never prevent it.
    func stillHeld() -> Bool { (try? requireHeld()) != nil && (try? requireMonitorFrozen()) != nil }
}
