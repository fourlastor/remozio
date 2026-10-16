import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandProcessTests: XCTestCase {
    private var directory: URL!
    private var launcher: URL!
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-process-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        launcher = directory.appendingPathComponent("child")
        let fixture = try XCTUnwrap(Bundle.module.url(forResource: "child", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.appendingPathComponent("include").path,
            fixture.path, native.appendingPathComponent("CommandChildSpecification.c").path, "-o", launcher.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
    }
    override func tearDownWithError() throws { if let directory { try FileManager.default.removeItem(at: directory) } }
    private func frame(mode: String = "output", missing: Bool = false, budget: UInt32 = 5000, large: Bool = false, ioMode: CommandIOMode = .pipes) throws -> Data {
        var environment = [CapturedEnvironmentEntry(name: Data("CWD".utf8), value: Data(directory.path.utf8), source: .minimal),
            .init(name: Data("EMPTY".utf8), value: Data(), source: .requested),
            .init(name: Data("RAW".utf8), value: Data([0xfd]), source: .requested)]
        if large { environment.insert(.init(name: Data("BIG".utf8), value: Data(repeating: 0x61, count: 1_048_576), source: .requested), at: 0) }
        let capture = try CommandCapture(schemaVersion: 1,
            executable: .init(path: Data((missing ? "/nonexistent/remozio-command" : launcher.path).utf8), identity: .init(device: 1, inode: 2), sha256: Data(count: 32)),
            arguments: [Data([0xff]), Data(), Data([0xfe]), Data(mode.utf8)],
            directory: .init(path: Data(directory.path.utf8), identity: .init(device: 1, inode: 3)),
            target: .init(uid: getuid(), gid: getgid(), supplementaryGroups: [], observedName: nil),
            environment: environment,
            input: .init(kind: .pipe, streamBinding: Data(count: 16), observedPath: nil, identity: nil),
            ioMode: ioMode, disconnectBehavior: .terminate,
            requester: .init(executablePath: Data("/fixture/caller".utf8), realUID: getuid(), effectiveUID: getuid(), pid: 10, pidVersion: 11,
                signing: .init(status: .unsigned, identifier: nil, team: nil, cdHash: nil), sessionID: nil, ttyPath: nil),
            ancestry: .init(completeness: .unavailable, entries: [], reason: .unsupported), unverifiedRationale: nil,
            submission: .init(id: Data(count: 16), nonce: Data(count: 32), callerBinding: Data(count: 16)),
            limits: .init(maxBytes: 2_097_152, maxDepth: 16, maxItems: 1024))
        return try CommandChildLaunchSpecification(legacyCapture: capture, preparationMilliseconds: budget, fileCreationMask: 0o022).canonicalBytes
    }
    private final class Resources {
        var input = [Int32](repeating: -1, count: 2), output = [Int32](repeating: -1, count: 2), error = [Int32](repeating: -1, count: 2)
        var cwd: Int32 = -1
        init(directory: URL) throws {
            guard pipe(&input) == 0, pipe(&output) == 0, pipe(&error) == 0 else { throw CocoaError(.fileReadUnknown) }
            cwd = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            guard cwd >= 0 else { throw CocoaError(.fileReadUnknown) }
        }
        deinit { for fd in input + output + error + [cwd] where fd >= 0 { Darwin.close(fd) } }
    }
    private func spawn(_ resources: Resources, frame: Data) throws -> OpaquePointer {
        var process: OpaquePointer?
        XCTAssertEqual(frame.withUnsafeBytes { bytes in
            launcher.path.withCString { path in
                remozio_command_process_spawn(path, bytes.baseAddress, bytes.count, resources.input[0], resources.output[1], resources.error[1], resources.cwd, &process)
            }
        }, 0)
        let owned = try XCTUnwrap(process)
        Darwin.close(resources.output[1]); resources.output[1] = -1
        Darwin.close(resources.error[1]); resources.error[1] = -1
        return owned
    }
    @discardableResult private func until(_ process: OpaquePointer, condition: (remozio_command_process_observation_t) -> Bool) throws -> remozio_command_process_observation_t {
        let deadline = Date().addingTimeInterval(8)
        while true {
            var observation = remozio_command_process_observation_t()
            let error = remozio_command_process_poll(process, &observation)
            if condition(observation) { return observation }
            XCTAssertEqual(error, 0)
            if error != 0 || Date() >= deadline {
                XCTFail("Process observation: pid=\(observation.pid), error=\(error), prepared=\(observation.prepared), exec=\(observation.exec_observed), exit=\(observation.exit_observed), reaped=\(observation.reaped), statusClosed=\(observation.status_closed)")
                throw CocoaError(.executableRuntimeMismatch)
            }
            usleep(1000)
        }
    }
    private func retire(_ process: OpaquePointer) {
        _ = remozio_command_process_cancel(process)
        var observation = remozio_command_process_observation_t()
        for _ in 0..<8000 {
            _ = remozio_command_process_poll(process, &observation)
            if observation.reaped || observation.ownership_lost { break }
            usleep(1000)
        }
        XCTAssertEqual(remozio_command_process_dispose(process), 0)
    }
    func testPreparedChildLeavesStdinUnreadUntilSingleReleaseAndReportsActualProgramExit() throws {
        let resources = try Resources(directory: directory)
        let input = Data("original stream".utf8)
        XCTAssertEqual(input.withUnsafeBytes { write(resources.input[1], $0.baseAddress, $0.count) }, input.count)
        let flags = fcntl(resources.input[0], F_GETFL)
        let process = try spawn(resources, frame: frame()); defer { retire(process) }
        let prepared = try until(process) { $0.prepared }
        XCTAssertFalse(prepared.exec_observed); XCTAssertFalse(prepared.release_attempted)
        XCTAssertEqual(fcntl(resources.input[0], F_GETFL), flags)
        var remaining: Int32 = 0
        // Darwin FIONREAD is _IOR('f', 127, int). Swift cannot import the macro.
        XCTAssertEqual(ioctl(resources.input[0], UInt(0x4004_667f), &remaining), 0); XCTAssertEqual(remaining, Int32(input.count))
        XCTAssertEqual(remozio_command_process_dispose(process), EBUSY)
        XCTAssertEqual(remozio_command_process_release(process), 0)
        XCTAssertEqual(remozio_command_process_release(process), EALREADY)
        let ended = try until(process) { $0.reaped }
        XCTAssertTrue(ended.exec_observed); XCTAssertTrue(ended.exit_observed)
        XCTAssertEqual(ended.wait_status, 7 << 8)
        var output = [UInt8](repeating: 0, count: 64), error = [UInt8](repeating: 0, count: 16)
        let outCount = read(resources.output[0], &output, output.count), errCount = read(resources.error[0], &error, error.count)
        XCTAssertGreaterThanOrEqual(outCount, 0); XCTAssertGreaterThanOrEqual(errCount, 0)
        XCTAssertEqual(Data(output.prefix(max(0, Int(outCount)))), Data("OUT:".utf8) + input)
        XCTAssertEqual(Data(error.prefix(max(0, Int(errCount)))), Data("ERR".utf8))
        XCTAssertEqual(remozio_command_process_signal(process, SIGTERM), ESRCH)
    }
    func testExecFailureDoesNotBecomeACommandExit() throws {
        let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame(missing: true))
        defer { retire(process) }
        try until(process) { $0.prepared }; XCTAssertEqual(remozio_command_process_release(process), 0)
        let ended = try until(process) { $0.reaped }
        XCTAssertFalse(ended.exec_observed); XCTAssertEqual(ended.wait_status, 70 << 8)
    }
    func testCancellationBeforeReleaseNeverExecutesAndCannotReleaseLater() throws {
        let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame())
        defer { retire(process) }
        try until(process) { $0.prepared }
        XCTAssertEqual(remozio_command_process_cancel(process), 0)
        let ended = try until(process) { $0.reaped }
        XCTAssertFalse(ended.release_attempted); XCTAssertFalse(ended.exec_observed)
        XCTAssertTrue(ended.wait_status == 70 << 8 || ended.wait_status & 0x7f == SIGKILL)
        XCTAssertEqual(remozio_command_process_release(process), ECANCELED)
    }
    func testProgramSignalAndProcessGroupForwardingKeepTheOriginalLeaderOwned() throws {
        for mode in ["signal", "wait"] {
            let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame(mode: mode))
            defer { retire(process) }
            try until(process) { $0.prepared }; XCTAssertEqual(remozio_command_process_release(process), 0)
            if mode == "wait" {
                try until(process) { $0.exec_observed }
                XCTAssertEqual(remozio_command_process_signal(process, 0), EINVAL)
                XCTAssertEqual(remozio_command_process_signal(process, NSIG), EINVAL)
                XCTAssertEqual(remozio_command_process_signal(process, SIGTERM), 0)
            }
            let ended = try until(process) { $0.reaped }
            XCTAssertTrue(ended.exec_observed); XCTAssertEqual(ended.wait_status & 0x7f, SIGTERM)
        }
    }
    func testMalformedConfigurationAndMissingLauncherCreateNoChildAndPreserveInput() throws {
        let resources = try Resources(directory: directory)
        var process: OpaquePointer?
        XCTAssertEqual(remozio_command_process_spawn(launcher.path, nil, 0, resources.input[0], resources.output[1], resources.error[1], resources.cwd, &process), EINVAL)
        XCTAssertNil(process)
        let bytes = try frame()
        XCTAssertEqual(bytes.withUnsafeBytes { remozio_command_process_spawn("/nonexistent/remozio-launcher", $0.baseAddress, $0.count,
            resources.input[0], resources.output[1], resources.error[1], resources.cwd, &process) }, ENOENT)
        XCTAssertNil(process); XCTAssertGreaterThanOrEqual(fcntl(resources.input[0], F_GETFD), 0)
    }
    private func useLauncher(_ name: String) throws {
        let next = directory.appendingPathComponent(name)
        try FileManager.default.copyItem(at: launcher, to: next)
        launcher = next
    }
    func testLargeConfigurationMakesBoundedProgressWithoutReadingTheCommandStream() throws {
        let resources = try Resources(directory: directory)
        let bytes = Data("unread".utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { write(resources.input[1], $0.baseAddress, $0.count) }, bytes.count)
        let process = try spawn(resources, frame: frame(large: true)); defer { retire(process) }
        let prepared = try until(process) { $0.prepared }
        XCTAssertTrue(prepared.configured); XCTAssertFalse(prepared.exec_observed)
        XCTAssertEqual(remozio_command_process_cancel(process), 0)
        try until(process) { $0.reaped }
        var actual = [UInt8](repeating: 0, count: bytes.count)
        XCTAssertEqual(read(resources.input[0], &actual, actual.count), bytes.count)
        XCTAssertEqual(Data(actual), bytes)
    }
    func testStalledPreparationExpiresWithoutAuthorizingRelease() throws {
        try useLauncher("stalled-child")
        let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame(budget: 100, large: true))
        defer { retire(process) }
        let deadline = Date().addingTimeInterval(3)
        var observedError: Int32 = 0, observation = remozio_command_process_observation_t()
        repeat {
            observedError = remozio_command_process_poll(process, &observation)
            if observedError != 0 { break }
            usleep(1000)
        } while Date() < deadline
        XCTAssertEqual(observedError, ETIMEDOUT)
        XCTAssertFalse(observation.prepared); XCTAssertFalse(observation.release_attempted); XCTAssertFalse(observation.exec_observed)
        XCTAssertEqual(remozio_command_process_release(process), ETIMEDOUT)
    }
    func testMalformedAndTruncatedPrivateStatusesNeverPermitRelease() throws {
        let original = launcher!
        for name in ["malformed-child", "truncated-child"] {
            launcher = original; try useLauncher(name)
            let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame())
            defer { retire(process) }
            let deadline = Date().addingTimeInterval(3)
            var result: Int32 = 0, state = remozio_command_process_observation_t()
            repeat {
                result = remozio_command_process_poll(process, &state)
                if result != 0 { break }
                usleep(1000)
            } while Date() < deadline
            XCTAssertEqual(result, EPROTO); XCTAssertFalse(state.prepared); XCTAssertFalse(state.release_attempted)
            XCTAssertEqual(remozio_command_process_release(process), EPROTO)
        }
    }
    func testFailedReleaseWriteIsConsumedWithoutChangingParentSignalMask() throws {
        try useLauncher("closed-release-child")
        let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame())
        defer { retire(process) }
        try until(process) { $0.prepared }
        var before: sigset_t = 0, after: sigset_t = 0
        XCTAssertEqual(pthread_sigmask(SIG_BLOCK, nil, &before), 0)
        XCTAssertEqual(remozio_command_process_release(process), EPIPE)
        XCTAssertEqual(remozio_command_process_release(process), EALREADY)
        XCTAssertEqual(pthread_sigmask(SIG_BLOCK, nil, &after), 0)
        XCTAssertEqual(before, after)
    }
    func testUnexpectedExternalReapRetiresPidOwnershipWithoutSignalingAgain() throws {
        let resources = try Resources(directory: directory), process = try spawn(resources, frame: frame(mode: "signal"))
        defer { retire(process) }
        let prepared = try until(process) { $0.prepared }
        XCTAssertEqual(remozio_command_process_release(process), 0)
        var status: Int32 = 0
        XCTAssertEqual(waitpid(prepared.pid, &status, 0), prepared.pid)
        var observed = remozio_command_process_observation_t()
        XCTAssertEqual(remozio_command_process_poll(process, &observed), ECHILD)
        XCTAssertTrue(observed.ownership_lost); XCTAssertFalse(observed.reaped)
        XCTAssertEqual(remozio_command_process_signal(process, SIGTERM), ESRCH)
    }

    func testRetainedPrivatePtyDrainsLargeBinaryOutputAndCancellationBeforeDisposal() throws {
        for cancellation in [false, true] {
            let seed = try RetainedCommandPTY()
            var attributes = termios()
            try seed.withBorrowedSlave { descriptor in
                guard tcgetattr(descriptor, &attributes) == 0 else { throw RetainedCommandPTYError.native(errno) }
            }
            seed.close(); cfmakeraw(&attributes)
            let pty = try RetainedCommandPTY(attributes: attributes)
            defer { pty.close() }
            let resources = try Resources(directory: directory), bytes = try frame(mode: cancellation ? "pty-infinite" : "pty-bulk", ioMode: .pty)
            var handle: OpaquePointer?
            XCTAssertEqual(try pty.withBorrowedSlave { slave in
                bytes.withUnsafeBytes { remozio_command_process_spawn(launcher.path, $0.baseAddress, $0.count,
                    slave, slave, slave, resources.cwd, &handle) }
            }, 0)
            let process = try XCTUnwrap(handle)
            defer { retire(process) }
            pty.sealSlave()
            try until(process) { $0.prepared }; XCTAssertEqual(remozio_command_process_release(process), 0)
            var observation = remozio_command_process_observation_t(), output = Data(), ended = false, cancelled = false
            let deadline = Date().addingTimeInterval(5)
            while !observation.reaped || !ended {
                XCTAssertEqual(remozio_command_process_poll(process, &observation), 0)
                switch try pty.read(maximumBytes: 8192) {
                case .bytes(let bytes):
                    XCTAssertLessThanOrEqual(bytes.count, 8192)
                    let offset = output.count
                    XCTAssertEqual(bytes, Data((offset..<(offset + bytes.count)).map { UInt8($0 % 251) }))
                    output.append(bytes)
                case .end: ended = true
                case .waiting: usleep(1000)
                }
                if cancellation && output.count >= 65_536 && !cancelled {
                    XCTAssertEqual(remozio_command_process_cancel(process), 0); cancelled = true
                }
                if Date() > deadline { throw CocoaError(.executableRuntimeMismatch) }
            }
            XCTAssertTrue(observation.exec_observed)
            XCTAssertEqual(observation.wait_status, cancellation ? SIGKILL : 7 << 8)
            if cancellation { XCTAssertGreaterThanOrEqual(output.count, 65_536) }
            else { XCTAssertEqual(output.count, 1_048_576) }
        }
    }

    func testRetainedPrivatePtySealsParentSlaveAndDrainsBeforeOwnedChildDisposal() throws {
        let pty = try RetainedCommandPTY(size: winsize(ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0))
        defer { pty.close() }
        let resources = try Resources(directory: directory), bytes = try frame(mode: "pty", ioMode: .pty)
        var handle: OpaquePointer?
        let result = try pty.withBorrowedSlave { slave in
            bytes.withUnsafeBytes { remozio_command_process_spawn(launcher.path, $0.baseAddress, $0.count,
                slave, slave, slave, resources.cwd, &handle) }
        }
        XCTAssertEqual(result, 0)
        let process = try XCTUnwrap(handle)
        defer { retire(process) }
        pty.sealSlave()
        try until(process) { $0.prepared }; XCTAssertEqual(remozio_command_process_release(process), 0)
        var observation = remozio_command_process_observation_t(), output = Data(), ended = false
        let deadline = Date().addingTimeInterval(5)
        while !observation.reaped || !ended {
            XCTAssertEqual(remozio_command_process_poll(process, &observation), 0)
            switch try pty.read() {
            case .bytes(let bytes): output.append(bytes)
            case .end: ended = true
            case .waiting: usleep(1000)
            }
            if Date() > deadline { throw CocoaError(.executableRuntimeMismatch) }
        }
        XCTAssertEqual(output, Data("PTY".utf8))
        XCTAssertTrue(observation.exec_observed); XCTAssertEqual(observation.wait_status, 7 << 8)
    }

    func testPtyModeCreatesANewSessionAndAttachesThePrivateSlave() throws {
        var master: Int32 = -1, slave: Int32 = -1
        guard openpty(&master, &slave, nil, nil, nil) == 0 else { throw CocoaError(.fileReadUnknown) }
        defer { Darwin.close(master); Darwin.close(slave) }
        let resources = try Resources(directory: directory), bytes = try frame(mode: "pty", ioMode: .pty)
        var handle: OpaquePointer?
        let result = bytes.withUnsafeBytes { remozio_command_process_spawn(launcher.path, $0.baseAddress, $0.count,
            slave, slave, slave, resources.cwd, &handle) }
        XCTAssertEqual(result, 0)
        let process = try XCTUnwrap(handle); defer { retire(process) }
        try until(process) { $0.prepared }; XCTAssertEqual(remozio_command_process_release(process), 0)
        try until(process) { $0.exec_observed }
        var ready = pollfd(fd: master, events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&ready, 1, 1000), 1)
        guard ready.revents & Int16(POLLIN) != 0 else {
            XCTFail("The private PTY did not provide readable output")
            throw CocoaError(.executableRuntimeMismatch)
        }
        var text = [UInt8](repeating: 0, count: 3)
        XCTAssertEqual(read(master, &text, 3), 3); XCTAssertEqual(Data(text), Data("PTY".utf8))
        let ended = try until(process) { $0.reaped }
        XCTAssertTrue(ended.exec_observed); XCTAssertEqual(ended.wait_status, 7 << 8)
    }

}

extension CommandProcessTests {
    func testObserverFailureReapsOwnedReleasedChildWithoutCancellationOrExecutionInference() throws {
        let source = try XCTUnwrap(Bundle.module.url(forResource: "observer-fault", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), harness = directory.appendingPathComponent("observer-fault")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.path,
            "-I", native.appendingPathComponent("include").path, source.path,
            native.appendingPathComponent("CommandChildSpecification.c").path, "-o", harness.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let file = directory.appendingPathComponent("frame")
        try frame(mode: "short-wait").write(to: file)
        let probe = Process(); probe.executableURL = harness; probe.currentDirectoryURL = directory
        probe.arguments = [launcher.path, file.path]
        try probe.run(); probe.waitUntilExit()
        XCTAssertEqual(probe.terminationStatus, 0)
    }
}

extension CommandProcessTests {
    private func assertCancellationFixture(_ name: String, large: Bool) throws {
        let source = try XCTUnwrap(Bundle.module.url(forResource: "cancel-race", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), harness = directory.appendingPathComponent("cancel-race")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror", "-I", native.path,
            "-I", native.appendingPathComponent("include").path, source.path,
            native.appendingPathComponent("CommandChildSpecification.c").path, "-o", harness.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let file = directory.appendingPathComponent("frame")
        try frame(mode: "wait", large: large).write(to: file)
        let probe = Process(); probe.executableURL = harness; probe.currentDirectoryURL = directory
        probe.arguments = [launcher.path, file.path, name]
        try probe.run(); probe.waitUntilExit()
        XCTAssertEqual(probe.terminationStatus, 0, "Native cancellation fixture: \(name)")
    }
    func testCancellationExitSnapshotRequiresOriginalIdentityAndDoesNotInventAReap() throws { try assertCancellationFixture("exiting_without_reap", large: false) }
    func testCancellationPermissionErrorUsesActualWaitWithoutAnExitEvent() throws { try assertCancellationFixture("prepared_exit_without_event", large: false) }
    func testCancellationAfterPreparedGateExitUsesActualReapAndPreservesInput() throws {
        try assertCancellationFixture("prepared_exit", large: true)
    }
    func testPreparedCancellationPreservesUnreleasedInputWithLargeConfiguration() throws {
        try assertCancellationFixture("normal_prepared", large: true)
    }
    func testLiveCancellationPermissionFailureKeepsOwnershipAndActualError() throws {
        try assertCancellationFixture("live_permission_failure", large: false)
    }
}

extension CommandProcessTests {
    private func assertJobControlFixture(_ name: String) throws {
        let source = try XCTUnwrap(Bundle.module.url(forResource: "job-state", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), harness = directory.appendingPathComponent("job-state")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, source.path,
            native.appendingPathComponent("CommandProcess.c").path,
            native.appendingPathComponent("CommandChildSpecification.c").path, "-o", harness.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let file = directory.appendingPathComponent("frame")
        try frame(mode: name == "sigwait_resume" ? "sigwait" : "wait").write(to: file)
        let probe = Process(); probe.executableURL = harness; probe.currentDirectoryURL = directory
        probe.arguments = [launcher.path, file.path, name]
        try probe.run(); probe.waitUntilExit()
        XCTAssertEqual(probe.terminationStatus, 0, "Native job observation fixture: \(name)")
    }
    func testSynchronousContinueAcceptsActualSenderPidWithoutLosingOwnedChild() throws {
        try assertJobControlFixture("sigwait_resume")
    }
    func testNativeStopContinueObservationsAdvanceOnlyForActualEvents() throws {
        try assertJobControlFixture("resume")
    }
    func testNativeCancellationReapsStoppedChildAndClearsStopObservation() throws {
        try assertJobControlFixture("cancel")
    }
    func testNativeOwnershipLossClearsStopObservationAndPreventsSignals() throws {
        try assertJobControlFixture("ownership_loss")
    }
}

extension CommandProcessTests {
    private func assertSessionFixture(_ name: String, ioMode: CommandIOMode) throws {
        let source = try XCTUnwrap(Bundle.module.url(forResource: "session-context", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), harness = directory.appendingPathComponent("session-context")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.appendingPathComponent("include").path, source.path,
            native.appendingPathComponent("CommandProcess.c").path,
            native.appendingPathComponent("CommandChildSpecification.c").path,
            native.appendingPathComponent("CommandPTY.c").path, "-o", harness.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let file = directory.appendingPathComponent("frame")
        try frame(mode: "wait", ioMode: ioMode).write(to: file)
        let probe = Process(); probe.executableURL = harness; probe.currentDirectoryURL = directory
        probe.arguments = [launcher.path, file.path, name]
        try probe.run(); probe.waitUntilExit()
        XCTAssertEqual(probe.terminationStatus, 0, "Native monitor session fixture: \(name)")
    }
    func testMonitorSessionPreservesPipeInputAndStopsItsOwnedTargetGroup() throws {
        try assertSessionFixture("pipes", ioMode: .pipes)
    }
    func testMonitorSessionPreservesTerminalOwnershipAcrossStopAndResume() throws {
        try assertSessionFixture("terminal_signal", ioMode: .pty)
    }
    func testMonitorSessionTerminalSuspendCharacterStopsOnlyItsTarget() throws {
        try assertSessionFixture("terminal_character", ioMode: .pty)
    }
    func testMonitorSessionCancelsAndReapsItsStoppedTarget() throws {
        try assertSessionFixture("stopped_cancel", ioMode: .pty)
    }
    func testMonitorSessionRejectsAnUnownedTerminalBeforeCreatingAChild() throws {
        try assertSessionFixture("unowned_terminal", ioMode: .pty)
    }
    func testMonitorSessionRejectsAnOrdinaryCallerWithoutConsumingInput() throws {
        try assertSessionFixture("not_session_leader", ioMode: .pipes)
    }
}


extension CommandProcessTests {
    private func assertTracingFixture(_ name: String) throws {
        let source = try XCTUnwrap(Bundle.module.url(forResource: "trace-state", withExtension: "c", subdirectory: "Fixtures/command-process"))
        let core = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let native = core.appendingPathComponent("Sources/RemozioMach"), harness = directory.appendingPathComponent("trace-state")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
            "-I", native.path, "-I", native.appendingPathComponent("include").path, source.path,
            native.appendingPathComponent("CommandChildSpecification.c").path, "-o", harness.path]
        try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        guard compiler.terminationStatus == 0 else { throw CocoaError(.executableNotLoadable) }
        let mode = name.contains("plain") ? "plain_stop" : name.contains("trap") ? "trace_trap" : "trace_stop"
        let file = directory.appendingPathComponent("frame")
        try frame(mode: mode).write(to: file)
        let probe = Process(); probe.executableURL = harness; probe.currentDirectoryURL = directory
        probe.arguments = [launcher.path, file.path, name]
        try probe.run(); probe.waitUntilExit()
        XCTAssertEqual(probe.terminationStatus, 0, "Native tracing snapshot fixture: \(name)")
    }
    func testOrdinaryStopHasAnUntracedSnapshotAndRetainsActualExit() throws {
        try assertTracingFixture("plain_stop")
    }
    func testSelfTracedStopHasATracedSnapshotAndRetainsActualExit() throws {
        try assertTracingFixture("trace_stop")
    }
    func testSelfTracedTrapHasATracedSnapshotAndRetainsActualExit() throws {
        try assertTracingFixture("trace_trap")
    }
    func testUnavailableTracingMetadataKeepsATracedStopUnknown() throws {
        try assertTracingFixture("metadata_traced_stop_unavailable")
    }
    func testUnavailableTracingMetadataKeepsATracedTrapUnknown() throws {
        try assertTracingFixture("metadata_traced_trap_unavailable")
    }
    func testUnavailableTracingMetadataKeepsAnOrdinaryStopUnknown() throws {
        try assertTracingFixture("metadata_plain_stop_unavailable")
    }
    func testTracingSnapshotRejectsMismatchedPid() throws {
        try assertTracingFixture("metadata_traced_stop_mismatch")
    }
    func testTracingSnapshotRejectsRunningMetadata() throws {
        try assertTracingFixture("metadata_traced_stop_not_stopped")
    }
    func testTracingSnapshotRejectsExitInProgress() throws {
        try assertTracingFixture("metadata_traced_stop_in_exit")
    }
    func testTracingSnapshotRejectsPartialMetadata() throws {
        try assertTracingFixture("metadata_traced_stop_partial")
    }
    func testTracingSnapshotRejectsChangedBirthTimestamp() throws {
        try assertTracingFixture("metadata_traced_stop_birth_mismatch")
    }
    func testUnavailableBirthMetadataKeepsTracingUnknownWithoutFailingExecution() throws {
        try assertTracingFixture("metadata_traced_stop_birth_unavailable")
    }
}
