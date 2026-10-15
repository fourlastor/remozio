import Darwin
import Foundation

/// Internal process primitive. Administrative callers select fixed executables and typed arguments.
/// Output stays in memory and must not be logged. The child receives no caller environment or descriptors.
enum BoundedNativeCommand {
    enum Failure: Error, Equatable { case invalidConfiguration, system(Int32), timedOut, outputLimit, abnormalExit }
    struct Result { let exitCode: Int32; let output: Data; let errorOutput: Data }
    static func run(executable: String, arguments: [String], timeoutMilliseconds: UInt64 = 10_000,
                    maximumOutputBytes: Int = 65_536) throws -> Result {
        guard executable.hasPrefix("/"), executable.utf8.count < Int(PATH_MAX), !executable.utf8.contains(0),
              arguments.count <= 32, arguments.allSatisfy({ $0.utf8.count < 4096 && !$0.utf8.contains(0) }),
              (10...30_000).contains(timeoutMilliseconds), (1...65_536).contains(maximumOutputBytes) else { throw Failure.invalidConfiguration }
        func pipe() throws -> [Int32] {
            var fds: [Int32] = [-1, -1]
            guard Darwin.pipe(&fds) == 0 else { throw Failure.system(errno) }
            guard fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(fds[1], F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0 else {
                let error = errno; _ = close(fds[0]); _ = close(fds[1]); throw Failure.system(error)
            }
            return fds
        }
        var output = try pipe(); defer { for fd in output where fd >= 0 { _ = close(fd) } }
        var errors = try pipe(); defer { for fd in errors where fd >= 0 { _ = close(fd) } }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        let actionStatus = posix_spawn_file_actions_init(&actions)
        guard actionStatus == 0 else { throw Failure.system(actionStatus) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        let attributeStatus = posix_spawnattr_init(&attributes)
        guard attributeStatus == 0 else { throw Failure.system(attributeStatus) }
        defer { posix_spawnattr_destroy(&attributes) }
        for status in [posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0),
                       posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO),
                       posix_spawn_file_actions_adddup2(&actions, errors[1], STDERR_FILENO),
                       posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))] {
            guard status == 0 else { throw Failure.system(status) }
        }
        let argv: [UnsafeMutablePointer<CChar>?] = ([executable] + arguments).map { value in value.withCString { strdup($0) } } + [nil]
        let environmentStrings: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C"]
        let environment: [UnsafeMutablePointer<CChar>?] = environmentStrings.map { value in value.withCString { strdup($0) } } + [nil]
        defer { for value in argv { free(value) }; for value in environment { free(value) } }
        guard argv.dropLast().allSatisfy({ $0 != nil }), environment.dropLast().allSatisfy({ $0 != nil }) else { throw Failure.system(ENOMEM) }
        var pid: pid_t = 0
        let spawn = argv.withUnsafeBufferPointer { args in
            environment.withUnsafeBufferPointer { env in
                posix_spawn(&pid, executable, &actions, &attributes, args.baseAddress!, env.baseAddress!)
            }
        }
        guard spawn == 0, pid > 0 else { throw Failure.system(spawn == 0 ? ECHILD : spawn) }
        // Keep ownership until waitpid reaps this exact child. A timed-out PID cannot be reused before cleanup.
        var reaped = false, status: Int32 = 0
        defer {
            if !reaped {
                _ = kill(pid, SIGKILL)
                while waitpid(pid, &status, 0) < 0 && errno == EINTR { }
            }
        }
        _ = close(output[1]); output[1] = -1
        _ = close(errors[1]); errors[1] = -1
        let deadline = DispatchTime.now().uptimeNanoseconds + timeoutMilliseconds * 1_000_000
        var stdout = Data(), stderr = Data(), ended = [false, false]
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            for (index, fd) in [output[0], errors[0]].enumerated() where !ended[index] {
                while true {
                    let count = read(fd, &buffer, buffer.count)
                    if count < 0, errno == EINTR { continue }
                    if count < 0, errno == EAGAIN || errno == EWOULDBLOCK { break }
                    guard count >= 0 else { throw Failure.system(errno) }
                    if count == 0 { ended[index] = true; break }
                    guard stdout.count + stderr.count + count <= maximumOutputBytes else { throw Failure.outputLimit }
                    if index == 0 { stdout.append(contentsOf: buffer.prefix(count)) }
                    else { stderr.append(contentsOf: buffer.prefix(count)) }
                }
            }
            if !reaped {
                let result = waitpid(pid, &status, WNOHANG)
                if result == pid { reaped = true }
                else if result < 0, errno != EINTR {
                    let error = errno
                    if error == ECHILD { reaped = true } // Ownership is gone; never signal a reused PID.
                    throw Failure.system(error)
                }
            }
            if reaped && ended.allSatisfy({ $0 }) { break }
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.timedOut }
            var fds = [pollfd(fd: ended[0] ? -1 : output[0], events: Int16(POLLIN | POLLHUP), revents: 0),
                       pollfd(fd: ended[1] ? -1 : errors[0], events: Int16(POLLIN | POLLHUP), revents: 0)]
            let polled = fds.withUnsafeMutableBufferPointer { Darwin.poll($0.baseAddress, nfds_t($0.count), 10) }
            guard polled >= 0 || errno == EINTR else { throw Failure.system(errno) }
        }
        guard status & 0x7f == 0 else { throw Failure.abnormalExit }
        return .init(exitCode: (status >> 8) & 0xff, output: stdout, errorOutput: stderr)
    }
}
