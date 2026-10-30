import Darwin
import Dispatch
import Foundation

/// Owns one spawned connector. Endpoint discovery remains distinct from edge readiness and approval delivery.
final class RelayConnectorProcess: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    enum Failure: Error, Equatable { case invalidConfiguration, system(Int32), unsupportedReaper }
    enum Termination: Equatable, Sendable {
        case exited(Int32), signaled(Int32), unsettled(Int32)
        var settled: Bool { if case .unsettled = self { return false }; return true }
    }
    enum StopCause: Equatable, Sendable { case requested, metricsTimeout, outputFailure(Int32) }
    struct Completion: Equatable, Sendable {
        let termination: Termination
        let discovery: RelayConnectorDiscovery?
        let stopCause: StopCause?
    }
    enum Event: Sendable { case discovered(RelayConnectorDiscovery), completed(Completion) }
    struct Options: Sendable {
        let gracefulStopMilliseconds: UInt64
        let startupMilliseconds: UInt64
        init(gracefulStopMilliseconds: UInt64 = 1000, startupMilliseconds: UInt64 = 5000) throws {
            guard (10...30_000).contains(gracefulStopMilliseconds), (100...60_000).contains(startupMilliseconds) else {
                throw Failure.invalidConfiguration
            }
            self.gracefulStopMilliseconds = gracefulStopMilliseconds; self.startupMilliseconds = startupMilliseconds
        }
        static let standard = try! Self()
    }
    private let control: Control
    private let completion: Task<Completion, Never>
    var description: String { "RelayConnectorProcess(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }

    static func startNative(scope: GatewaySettingsConsumerNativeScope, reference: RelayRunCredentialReference,
                            options: Options = .standard, verifyCurrent: @Sendable () throws -> Void = {},
                            event: @escaping @Sendable (Event) -> Void) throws -> RelayConnectorProcess {
        let host = scope.configuration
        guard host.role == .transport, reference.runtime == host.runtime else { throw RuntimePreparationError.changedScope }
        try scope.validate(); try verifyCurrent()
        let activity = try scope.acquireChildActivity()
        do {
            let app = host.codePolicy.entries.first { $0.role == .app && $0.active }!
            let bundle = URL(fileURLWithPath: host.bundlePath)
            let release = try SignedReleaseInspection.inspect(bundle, teamID: app.teamID, appIdentifier: app.identifier)
            try host.validateRelease(release)
            let identifier: String
            switch app.identifier {
            case "dev.remozio.mac": identifier = "dev.remozio.cloudflared"
            case "dev.remozio.mac.debug": identifier = "dev.remozio.cloudflared.debug"
            default: throw RuntimePreparationError.changedScope
            }
            let relative = "Contents/Helpers/RemozioCloudflared"
            guard let tool = release.manifest.dependencies.first(where: { $0.executablePath == relative }),
                  tool.kind == .tool, tool.owner == .transport, tool.signaturePath == relative, tool.executableAliases.isEmpty,
                  tool.identifier == identifier, tool.teamID == app.teamID,
                  release.dependencyCodeDirectoryHashes[relative] == tool.codeDirectoryHash else {
                throw RuntimePreparationError.changedScope
            }
            let file = try RelayRunCredentialFile.openNative(scope: scope, reference: reference)
            defer { file.close() }
            let arguments = ["--no-autoupdate", "--config", "/dev/fd/5", "--output", "json", "tunnel",
                "--grace-period", "\(options.gracefulStopMilliseconds)ms", "--metrics", "127.0.0.1:0", "run", "--token-file", "/dev/fd/4"]
            return try spawn(executable: bundle.appendingPathComponent(relative).path, arguments: arguments,
                token: file, activity: activity, options: options, verify: { try scope.validate(); try verifyCurrent(); try Task.checkCancellation() }, event: event)
        } catch { activity.close(); throw error }
    }

    // Ordinary fixtures exercise the process primitive. They cannot prove native code or dedicated-account admission.
    static func startForFixture(executable: String, arguments: [String], token: RelayRunCredentialFile,
                                activity: ServiceReleaseActivityToken, options: Options = .standard,
                                event: @escaping @Sendable (Event) -> Void = { _ in }) throws -> RelayConnectorProcess {
        try spawn(executable: executable, arguments: arguments, token: token, activity: activity, options: options, verify: {}, event: event)
    }
    private static func spawn(executable: String, arguments: [String], token: RelayRunCredentialFile,
                              activity: ServiceReleaseActivityToken, options: Options, verify: () throws -> Void,
                              event: @escaping @Sendable (Event) -> Void) throws -> RelayConnectorProcess {
        var transferred = false
        defer { if !transferred { activity.close() } }
        guard executable.hasPrefix("/"), executable.utf8.count < Int(PATH_MAX), !executable.utf8.contains(0),
              arguments.count <= 32, arguments.allSatisfy({ $0.utf8.count < 4096 && !$0.utf8.contains(0) }) else {
            throw Failure.invalidConfiguration
        }
        var reaper = sigaction()
        guard sigaction(SIGCHLD, nil, &reaper) == 0 else { throw Failure.system(errno) }
        guard reaper.sa_flags & SA_NOCLDWAIT == 0,
              unsafeBitCast(reaper.__sigaction_u.__sa_handler, to: UInt.self) != unsafeBitCast(SIG_IGN, to: UInt.self) else {
            throw Failure.unsupportedReaper
        }
        var output = try pipe(readNonblocking: true)
        defer { for fd in output where fd >= 0 { _ = Darwin.close(fd) } }
        var config = try pipe(readNonblocking: false)
        defer { for fd in config where fd >= 0 { _ = Darwin.close(fd) } }
        let configuration: [UInt8] = Array("{}\n".utf8)
        var offset = 0
        while offset < configuration.count {
            let count = configuration.withUnsafeBytes {
                Darwin.write(config[1], $0.baseAddress!.advanced(by: offset), $0.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw Failure.system(count == 0 ? EIO : errno) }; offset += count
        }
        _ = Darwin.close(config[1]); config[1] = -1
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        let actionStatus = posix_spawn_file_actions_init(&actions)
        guard actionStatus == 0 else { throw Failure.system(actionStatus) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        let attributeStatus = posix_spawnattr_init(&attributes)
        guard attributeStatus == 0 else { throw Failure.system(attributeStatus) }
        defer { posix_spawnattr_destroy(&attributes) }
        var defaults = sigset_t(), mask = sigset_t()
        sigemptyset(&defaults); sigemptyset(&mask)
        for signal in [SIGTERM, SIGINT, SIGHUP, SIGPIPE, SIGCHLD] { sigaddset(&defaults, signal) }
        for status in [posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0),
                       posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO),
                       posix_spawn_file_actions_adddup2(&actions, output[1], STDERR_FILENO),
                       posix_spawn_file_actions_adddup2(&actions, config[0], 5),
                       posix_spawn_file_actions_addchdir(&actions, "/"),
                       posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)),
                       posix_spawnattr_setsigdefault(&attributes, &defaults), posix_spawnattr_setsigmask(&attributes, &mask)] {
            guard status == 0 else { throw Failure.system(status) }
        }
        let environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/empty", "LC_ALL=C", "LANG=C"]
        let argv: [UnsafeMutablePointer<CChar>?] = ([executable] + arguments).map { $0.withCString { strdup($0) } } + [nil]
        let env: [UnsafeMutablePointer<CChar>?] = environment.map { $0.withCString { strdup($0) } } + [nil]
        defer { for pointer in argv { free(pointer) }; for pointer in env { free(pointer) } }
        guard argv.dropLast().allSatisfy({ $0 != nil }), env.dropLast().allSatisfy({ $0 != nil }) else { throw Failure.system(ENOMEM) }
        var pid: pid_t = 0
        try token.withDescriptorForSpawn { tokenFD in
            try activity.withSharedDescriptorForSpawn { activityFD in
                for status in [posix_spawn_file_actions_adddup2(&actions, activityFD, 3),
                               posix_spawn_file_actions_adddup2(&actions, tokenFD, 4)] {
                    guard status == 0 else { throw Failure.system(status) }
                }
                try verify()
                let result = argv.withUnsafeBufferPointer { args in
                    env.withUnsafeBufferPointer { values in
                        posix_spawn(&pid, executable, &actions, &attributes, args.baseAddress!, values.baseAddress!)
                    }
                }
                guard result == 0 else { throw Failure.system(result) }
            }
        }
        precondition(pid > 0)
        _ = Darwin.close(output[1]); output[1] = -1
        let reader = output[0]; output[0] = -1
        let result = RelayConnectorProcess(pid: pid, reader: reader, activity: activity, options: options, event: event)
        transferred = true; return result
    }
    private static func pipe(readNonblocking: Bool) throws -> [Int32] {
        var original: [Int32] = [-1, -1]
        guard Darwin.pipe(&original) == 0 else { throw Failure.system(errno) }
        defer { for fd in original { _ = Darwin.close(fd) } }
        let reader = fcntl(original[0], F_DUPFD_CLOEXEC, 32)
        guard reader >= 0 else { throw Failure.system(errno) }
        let writer = fcntl(original[1], F_DUPFD_CLOEXEC, 32)
        guard writer >= 0 else { let code = errno; _ = Darwin.close(reader); throw Failure.system(code) }
        if readNonblocking, fcntl(reader, F_SETFL, O_NONBLOCK) != 0 {
            let code = errno; _ = Darwin.close(reader); _ = Darwin.close(writer); throw Failure.system(code)
        }
        return [reader, writer]
    }
    private init(pid: pid_t, reader: Int32, activity: ServiceReleaseActivityToken, options: Options,
                 event: @escaping @Sendable (Event) -> Void) {
        let state = Control(pid: pid, reader: reader, activity: activity, options: options, event: event)
        control = state
        completion = Task {
            await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .utility).async { continuation.resume(returning: state.run()) }
            }
        }
    }
    deinit { control.requestStop() }
    func waitForExit() async -> Completion { await completion.value }
    func stopAndWait() async -> Completion { control.requestStop(); return await completion.value }

    private final class Control: @unchecked Sendable {
        private let lock = NSLock()
        private var stopping = false
        private let pid: pid_t
        private let reader: Int32
        private let activity: ServiceReleaseActivityToken
        private let options: Options
        private let event: @Sendable (Event) -> Void
        init(pid: pid_t, reader: Int32, activity: ServiceReleaseActivityToken, options: Options,
             event: @escaping @Sendable (Event) -> Void) {
            self.pid = pid; self.reader = reader; self.activity = activity; self.options = options; self.event = event
        }
        func requestStop() { lock.withLock { stopping = true } }
        func run() -> Completion {
            var parser = RelayConnectorDiagnostics(), cause: StopCause?
            var terminatedAt: UInt64?, killedAt: UInt64?
            let startup = DispatchTime.now().uptimeNanoseconds + options.startupMilliseconds * 1_000_000
            var buffer = [UInt8](repeating: 0, count: 8192), ended = false
            func finish(_ termination: Termination) -> Completion {
                _ = Darwin.close(reader)
                if termination.settled { activity.close() }
                let value = Completion(termination: termination, discovery: parser.discovery, stopCause: cause)
                event(.completed(value)); return value
            }
            while true {
                var status: Int32 = 0
                let waited = waitpid(pid, &status, WNOHANG)
                if waited == pid {
                    let signal = status & 0x7f
                    return finish(signal == 0 ? .exited((status >> 8) & 0xff) : .signaled(signal))
                }
                if waited < 0 {
                    if errno == EINTR { continue }
                    return finish(.unsettled(errno))
                }
                let now = DispatchTime.now().uptimeNanoseconds
                if parser.discovery == nil, now >= startup { if cause == nil { cause = .metricsTimeout }; requestStop() }
                if lock.withLock({ stopping }) {
                    if cause == nil { cause = .requested }
                    if terminatedAt == nil {
                        if kill(pid, SIGTERM) != 0, errno != ESRCH { return finish(.unsettled(errno)) }
                        terminatedAt = now
                    } else if killedAt == nil, now - terminatedAt! >= (options.gracefulStopMilliseconds + 1000) * 1_000_000 {
                        if kill(pid, SIGKILL) != 0, errno != ESRCH { return finish(.unsettled(errno)) }
                        killedAt = now
                    } else if let killedAt, now - killedAt >= 1_000_000_000 { return finish(.unsettled(ETIMEDOUT)) }
                }
                if !ended {
                    for _ in 0..<8 {
                        let count = Darwin.read(reader, &buffer, buffer.count)
                        if count < 0, errno == EINTR { continue }
                        if count < 0, errno == EAGAIN || errno == EWOULDBLOCK { break }
                        if count < 0 { cause = .outputFailure(errno); requestStop(); ended = true; break }
                        if count == 0 { ended = true; break }
                        if let observed = parser.consume(buffer.prefix(count)) { event(.discovered(observed)) }
                    }
                }
                var input = pollfd(fd: ended ? -1 : reader, events: Int16(POLLIN | POLLHUP), revents: 0)
                if Darwin.poll(&input, 1, 25) < 0, errno != EINTR { cause = .outputFailure(errno); requestStop(); ended = true }
            }
        }
    }
}
