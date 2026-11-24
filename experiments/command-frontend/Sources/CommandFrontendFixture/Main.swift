#if !DEBUG
#error("This owned-process fixture must never be built for release.")
#endif
import CryptoKit
import Darwin
import Foundation
import os
import OwnedTTY
import RemozioMach
import RemozioProtocol
import Security
@testable import RemozioCore

private enum Failure: Error { case assertion(String), connectionFailed }
private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure.assertion(message) }
}
private final class Endpoint {
    let port: mach_port_t
    init() throws {
        var value: mach_port_t = 0
        try require(mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &value) == KERN_SUCCESS, "allocate")
        guard mach_port_insert_right(mach_task_self_, value, value, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
            _ = mach_port_mod_refs(mach_task_self_, value, MACH_PORT_RIGHT_RECEIVE, -1)
            throw Failure.assertion("send right")
        }
        port = value
    }
    deinit {
        _ = mach_port_deallocate(mach_task_self_, port)
        _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
    }
}

/// A deterministic cleanup failure around the real private terminal lease. It changes no foreground group.
private final class InterruptedCleanupTerminal: CommandFrontendTerminalIO {
    let terminal: CommandFrontendTerminal
    private(set) var failures = 0
    private(set) var restorationFailures = 0
    let failureBeforeResult: Bool
    let suspendRetry: Bool
    init(_ terminal: CommandFrontendTerminal, failureBeforeResult: Bool = false, suspendRetry: Bool = false) {
        self.terminal = terminal; self.failureBeforeResult = failureBeforeResult; self.suspendRetry = suspendRetry
    }
    var needsRestore: Bool { terminal.needsRestore }
    func isForeground() throws -> Bool { try terminal.isForeground() }
    func activate() throws { try terminal.activate() }
    func restore() throws {
        if (failureBeforeResult || suspendRetry) && restorationFailures == 0 && terminal.needsRestore {
            restorationFailures += 1
            throw CommandFrontendTerminalError.native(EAGAIN)
        }
        try terminal.restore()
    }
    func read(maximumBytes: Int) throws -> CommandFrontendTerminalRead { try terminal.read(maximumBytes: maximumBytes) }
    func write(_ bytes: Data) throws -> Int { try terminal.write(bytes) }
    func dimensions() throws -> CommandFrontendTerminalSize { try terminal.dimensions() }
    func close() throws {
        if !suspendRetry && failures == 0 {
            try require(terminal.needsRestore, "cleanup must retain real raw settings")
            failures += 1
            try require(pthread_kill(pthread_self(), SIGINT) == 0, "cleanup interrupt")
            throw CommandFrontendTerminalError.native(EAGAIN)
        }
        try terminal.close()
    }
    func closeReportingFailure() { terminal.closeReportingFailure() }
}

/// Fail after real authenticated output, before receiving any terminal result.
private final class FailedChannel: CommandFrontendExecutionChannel {
    let session: RetainedCommandExecutionSession
    init(_ session: RetainedCommandExecutionSession) { self.session = session }
    var executionIOMode: CommandIOMode? { session.executionIOMode }
    var supportsCurrentJobQueries: Bool { session.supportsCurrentJobQueries }
    func requestCurrentJob(timeoutMilliseconds: UInt32) throws -> Bool { try session.requestCurrentJob(timeoutMilliseconds: timeoutMilliseconds) }
    func invalidateCurrentJobQuery() { session.invalidateCurrentJobQuery() }
    func pollStreamEvent(timeoutMilliseconds: UInt32, nonblocking: Bool) throws -> CommandExecutionStreamEvent? {
        let event = try session.pollStreamEvent(timeoutMilliseconds: timeoutMilliseconds, nonblocking: nonblocking)
        if case .outputEnded? = event { throw Failure.connectionFailed }
        return event
    }
    func forwardInput(_ bytes: Data) throws -> Int { try session.forwardInput(bytes) }
    func finishInput() throws -> Bool { try session.finishInput() }
    func acknowledgeOutput() throws -> Bool { try session.acknowledgeOutput() }
    func resizeTerminal(rows: UInt16, columns: UInt16, pixelWidth: UInt16, pixelHeight: UInt16) throws -> Bool {
        try session.resizeTerminal(rows: rows, columns: columns, pixelWidth: pixelWidth, pixelHeight: pixelHeight)
    }
    func forwardSignal(_ signal: UInt32) throws -> Bool { try session.forwardSignal(signal) }
    func cancelCommand() throws -> Bool { try session.cancelCommand() }
    func close() { session.close() }
}

/// Cancel one confirmation with an actual local resize while restoring the real terminal lease.
private final class CancelledConfirmationTerminal: CommandFrontendTerminalIO {
    let terminal: CommandFrontendTerminal
    private(set) var injected = false
    init(_ terminal: CommandFrontendTerminal) { self.terminal = terminal }
    var needsRestore: Bool { terminal.needsRestore }
    func isForeground() throws -> Bool { try terminal.isForeground() }
    func activate() throws { try terminal.activate() }
    func restore() throws {
        if !injected && terminal.needsRestore {
            injected = true
            try require(pthread_kill(pthread_self(), SIGWINCH) == 0, "confirmation resize")
        }
        try terminal.restore()
    }
    func read(maximumBytes: Int) throws -> CommandFrontendTerminalRead { try terminal.read(maximumBytes: maximumBytes) }
    func write(_ bytes: Data) throws -> Int { try terminal.write(bytes) }
    func dimensions() throws -> CommandFrontendTerminalSize { try terminal.dimensions() }
    func close() throws { try terminal.close() }
    func closeReportingFailure() { terminal.closeReportingFailure() }
}

@main
private struct Probe {
    static func main() {
        guard geteuid() != 0 else { exit(EX_NOPERM) }
        do {
            let limits = try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024)
            var arguments = try CommandFrontendInvocation.copyArguments(count: CommandLine.argc, vector: CommandLine.unsafeArgv, limits: limits)
            guard arguments.count > 2, let mode = String(data: arguments[1], encoding: .utf8),
                  ["pipes", "signal", "pty", "pty-cleanup", "pty-failure", "pty-suspend-retry", "pty-job", "pty-job-retry"].contains(mode) else { exit(EX_USAGE) }
            arguments.remove(at: 1)
            try run(arguments: arguments, signalMode: mode == "signal", ptyMode: mode.hasPrefix("pty"), cleanupMode: mode == "pty-cleanup", failureMode: mode == "pty-failure", suspendRetryMode: mode == "pty-suspend-retry", jobMode: mode.hasPrefix("pty-job"), jobRetryMode: mode == "pty-job-retry").finish()
        }
        catch { fputs("Composed frontend fixture failed: \(error)\n", stderr); exit(EX_SOFTWARE) }
    }
    private static func expression() throws -> String {
        var code: SecCode?, information: CFDictionary?
        try require(SecCodeCopySelf([], &code) == errSecSuccess, "self code")
        guard let code else { throw Failure.assertion("missing code") }
        try require(remozio_copy_dynamic_signing_information(code, &information) == errSecSuccess, "signing information")
        guard let fields = information as? [String: Any], let hash = fields[kSecCodeInfoUnique as String] as? Data else {
            throw Failure.assertion("hash")
        }
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }
    private static func run(arguments: [Data], signalMode: Bool, ptyMode: Bool, cleanupMode: Bool, failureMode: Bool, suspendRetryMode: Bool, jobMode: Bool, jobRetryMode: Bool) throws -> CommandFrontendExit {
        var cleanupFailed = false
        let runtime = CommandFrontendRuntime(reportCleanupFailure: { _ in cleanupFailed = true })
        defer { try? runtime.close() }
        try runtime.checkReady()
        var master: Int32 = -1, slave: Int32 = -1
        if ptyMode { try require((jobMode ? remozio_fixture_adopt_tty(&master, &slave) : remozio_fixture_open_tty(&master, &slave)) == 0, "owned terminal") }
        defer { if master >= 0 { _ = Darwin.close(master) }; if slave >= 0 { _ = Darwin.close(slave) } }
        let serverMaster = master >= 0 ? fcntl(master, F_DUPFD_CLOEXEC, 0) : -1
        try require(!ptyMode || serverMaster >= 0, "server terminal description")
        var originalAttributes = termios()
        if ptyMode { try require(tcgetattr(slave, &originalAttributes) == 0, "initial attributes") }
        let terminal = try ptyMode ? CommandFrontendTerminal(descriptor: slave, reportRestorationFailure: { _ in cleanupFailed = true }) : nil
        defer { try? terminal?.close() }
        let endpoint = try Endpoint(), port = endpoint.port, expression = try expression(), user = geteuid()
        let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
        let limits = try CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024)
        let rawArguments = [Data("true".utf8), Data(), Data([0xff, 0x0a, 0x80])]
        let invocation = try CommandFrontendInvocation(arguments: arguments, defaultIOMode: ptyMode ? .pty : .pipes,
            defaultDisconnectBehavior: .terminate, limits: limits)
        let directory = try CommandFrontendInvocation.currentDirectory()
        let path = getenv("PATH").map { Data(bytes: $0, count: strlen($0)) } ?? Data()
        let template = try invocation.submission(directory: directory,
            executablePath: invocation.executablePath(directory: directory, searchPath: path),
            binding: .init(id: Data(repeating: 9, count: 16), nonce: Data(repeating: 8, count: 32), callerBinding: Data(repeating: 7, count: 16)),
            schemaVersion: 1, limits: limits)
        let done = DispatchSemaphore(value: 0), outcome = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        let mainThread = pthread_mach_thread_np(pthread_self())
        let keyboardBytes = Data([0, 255, 13, 10, 128])
        let outputBytes = Data((0..<16391).map { UInt8($0 % 251) }) + Data([0, 255, 13, 10])
        DispatchQueue.global().async {
            defer { if serverMaster >= 0 { _ = Darwin.close(serverMaster) }; done.signal() }
            let result = Result<Void, Error> {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                var firstBinding: CapturedSubmission?
                // One verified busy refusal proves the frontend takes a fresh handshake without replaying an admitted request.
                for attempt in 0..<2 {
                    let handshake = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                        capabilities: jobMode ? .mappedTerminalCurrentJobExecution :
                            ptyMode ? .mappedTerminalJobExecution : .mappedPipeJobExecutionControls, macID: mac, accountID: account,
                        expression: expression, userID: user, auditSessionID: nil)
                    defer { handshake.close() }
                    let receipt = try receiver.receiveMappedIOInput(timeoutMilliseconds: 5000)
                    defer { receipt.closeIfUnclaimed() }
                    let submission = try CommandSubmission(canonicalBytes: receipt.payload, limits: limits,
                        expectedSchemaVersion: handshake.profile.submissionSchemaVersion)
                    try require(submission.arguments == rawArguments && submission.requestedTargetUID == 1234 &&
                        submission.executablePath == Data("/usr/bin/true".utf8) && submission.directoryPath == Data("/private/tmp".utf8) &&
                        submission.environmentAdditions == [.init(name: Data("RAW".utf8), value: Data([0xfe, 0x22]))] &&
                        submission.ioMode == (ptyMode ? .pty : .pipes) && submission.disconnectBehavior == .terminate,
                        "raw claims changed")
                    let digest = Data(SHA256.hash(data: submission.canonicalBytes))
                    if attempt == 0 {
                        firstBinding = submission.binding
                        try receipt.sendAdmissionReply(CommandAdmissionResultPayload(profile: handshake.profile,
                            submission: submission.binding, submissionDigest: digest,
                            outcome: .notAdmitted(.updateInstalling, .updateInstalling)).canonicalBytes)
                        continue
                    }
                    guard let firstBinding else { throw Failure.assertion("first binding") }
                    try require(submission.binding.id != firstBinding.id && submission.binding.nonce != firstBinding.nonce &&
                        submission.binding.callerBinding != firstBinding.callerBinding, "reused binding")
                    let request = CommandAdmittedRequest(requestID: Data(repeating: 4, count: 16),
                        requestToken: Data(repeating: 5, count: 32), challenge: Data(repeating: 6, count: 32))
                    guard let outputs = receipt.outputs else { throw Failure.assertion("outputs") }
                    let reply = try outputs.takeTerminalReply()
                    defer { reply.close() }
                    let stream = try MachCommandStreamAuthority(binding: .init(profile: handshake.profile,
                        submission: submission.binding, submissionDigest: digest, request: request),
                        original: receipt.caller, terminal: reply)
                    defer { stream.close() }
                    try receipt.sendAdmissionReply(CommandAdmissionResultPayload(profile: handshake.profile,
                        submission: submission.binding, submissionDigest: digest, outcome: .admitted(request)).canonicalBytes)
                    try queued { try stream.send(.opened) }
                    usleep(100000)
                    if ptyMode {
                        let deadline = Date().addingTimeInterval(5)
                        var resized = false
                        while !resized {
                            if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                guard case .resize = control else { throw Failure.assertion("initial resize") }
                                resized = true
                            }
                            try require(Date() < deadline, "resize deadline"); usleep(1000)
                        }
                        try require(keyboardBytes.withUnsafeBytes { Darwin.write(serverMaster, $0.baseAddress, $0.count) } == keyboardBytes.count,
                            "keyboard bytes")
                        var copiedOutput = Data()
                        for offset in stride(from: 0, to: outputBytes.count, by: CommandStreamFrame.maximumChunk) {
                            let bytes = Data(outputBytes[offset..<min(offset + CommandStreamFrame.maximumChunk, outputBytes.count)])
                            try queued { try stream.send(.output(bytes)) }
                            var copied = Data(count: bytes.count), received = 0
                            while received < copied.count {
                                let remaining = copied.count - received
                                let count = copied.withUnsafeMutableBytes {
                                    Darwin.read(serverMaster, $0.baseAddress!.advanced(by: received), remaining)
                                }
                                if count > 0 { received += count }
                                else { try require(count < 0 && [EAGAIN, EINTR].contains(errno), "terminal read") }
                                try require(Date() < deadline, "terminal output deadline"); usleep(1000)
                            }
                            copiedOutput.append(copied)
                        }
                        try require(copiedOutput == outputBytes, "binary output changed")
                        var forwardedInput = false
                        while !forwardedInput {
                            if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                try require(control == .input(keyboardBytes), "binary input changed"); forwardedInput = true
                            }
                            try require(Date() < deadline, "terminal input deadline"); usleep(1000)
                        }
                        if suspendRetryMode {
                            guard let thread = pthread_from_mach_thread_np(mainThread) else { throw Failure.assertion("main thread") }
                            try require(pthread_kill(thread, SIGTSTP) == 0, "local suspend")
                            for expected in [SIGTSTP, SIGCONT] {
                                var forwarded = false
                                while !forwarded {
                                    if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                        try require(control == .signal(UInt32(expected)), "suspend control"); forwarded = true
                                    }
                                    try require(Date() < deadline, "suspend control deadline"); usleep(1000)
                                }
                                if expected == SIGTSTP { try require(pthread_kill(thread, SIGCONT) == 0, "local continue") }
                            }
                        }
                        try queued { try stream.send(.outputEnd) }
                        if failureMode { return }
                        while !stream.outputDrained {
                            if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                try require(control == .outputDrained, "output acknowledgment")
                            }
                            try require(Date() < deadline, "drain deadline"); usleep(1000)
                        }
                    } else if signalMode {
                        guard let thread = pthread_from_mach_thread_np(mainThread) else { throw Failure.assertion("main thread") }
                        try require(pthread_kill(thread, SIGINT) == 0, "interrupt")
                        let deadline = Date().addingTimeInterval(5)
                        var received = false
                        while !received {
                            if let control = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                try require(control == .signal(UInt32(SIGINT)), "signal control")
                                received = true
                            }
                            try require(Date() < deadline, "signal deadline"); usleep(1000)
                        }
                    } else {
                        try queued { try stream.send(.jobState(.init(revision: 1,
                            state: .stopped(signal: UInt32(SIGTSTP), rawStopCode: UInt32(CLD_STOPPED), tracing: .untraced)))) }
                        try queued { try stream.send(.jobState(.init(revision: 2, state: .continued))) }
                    }
                    if jobMode {
                        try queued { try stream.send(.jobState(.init(revision: 1,
                            state: .stopped(signal: UInt32(SIGTSTP), rawStopCode: UInt32(CLD_STOPPED), tracing: .untraced)))) }
                        let deadline = Date().addingTimeInterval(10)
                        var previousNonce: Data?
                        for _ in 0..<(jobRetryMode ? 2 : 1) {
                            var queried = false
                            while !queried {
                                if let body = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                    guard case .queryCurrentJob(let nonce) = body else { throw Failure.assertion("fresh query required") }
                                    try require(nonce != previousNonce, "fresh confirmation retry nonce")
                                    previousNonce = nonce; queried = true
                                }
                                try require(Date() < deadline, "query deadline"); usleep(1000)
                            }
                            try stream.flushCurrentJob(expression: expression, userID: user, auditSessionID: nil,
                                checkPolicy: {}, currentState: { .stopped(signal: UInt32(SIGTSTP), revision: 1) })
                        }
                        var continued = false
                        while !continued {
                            if let body = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                try require(body == .signal(UInt32(SIGCONT)), "original continue control"); continued = true
                            }
                            try require(Date() < deadline, "continue deadline"); usleep(1000)
                        }
                        guard let reportValue = getenv("REMOZIO_FIXTURE_JOB_REPORT"), let report = Int32(String(cString: reportValue)) else {
                            throw Failure.assertion("owned report descriptor")
                        }
                        try require(Darwin.write(report, "B", 1) == 1, "background marker")
                        var resized = false
                        while !resized {
                            if let body = try stream.receiveControl(expression: expression, userID: user, auditSessionID: nil) {
                                try require(body == .resize(79, 121, 0, 0), "fresh foreground dimensions"); resized = true
                            }
                            try require(Date() < deadline, "foreground resize deadline"); usleep(1000)
                        }
                        try queued { try stream.send(.jobState(.init(revision: 2, state: .continued))) }
                    }
                    let bytes = try CommandTerminalResultPayload(profile: handshake.profile, original: submission, request: request,
                        outcome: signalMode ? .signalled(UInt32(SIGINT)) : .exited(13)).canonicalBytes
                    try queued { try reply.queueTerminalNonblocking(bytes) }
                }
            }
            outcome.withLock { $0 = result }
        }
        var input: [Int32] = [-1, -1]
        try require(pipe(&input) == 0, "input pipe")
        let output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { for descriptor in input + [output] { _ = Darwin.close(descriptor) } }
        let originalInput = Data([0, 255, 13, 10, 128])
        try require(originalInput.withUnsafeBytes { Darwin.write(input[1], $0.baseAddress, $0.count) } == originalInput.count, "input write")
        let flags = fcntl(input[0], F_GETFL)
        var lookups = 0
        let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 10000,
            initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 5000)
        let response = try CommandCallerReadiness.submitMappedIO(template, inputDescriptor: input[0], outputDescriptor: output,
            errorDescriptor: output, controlTerminalDescriptor: ptyMode ? slave : nil, authorityPort: { lookups += 1; return port },
            expression: expression, userID: user, auditSessionID: nil, macID: mac, accountID: account,
            submissionLimits: limits, configuration: configuration, currentJobQueries: jobMode)
        guard case .admitted(let session) = response else { throw Failure.assertion("admission") }
        defer { session.close() }
        let cleanupProbe = (cleanupMode || failureMode || suspendRetryMode) ? terminal.map { InterruptedCleanupTerminal($0, failureBeforeResult: failureMode, suspendRetry: suspendRetryMode) } : nil
        let confirmationProbe = jobRetryMode ? terminal.map(CancelledConfirmationTerminal.init) : nil
        let relay: CommandFrontendRelay
        if let cleanupProbe { relay = try CommandFrontendRelay(channel: failureMode ? FailedChannel(session) : session, terminal: cleanupProbe) }
        else if let confirmationProbe { relay = try CommandFrontendRelay(channel: session, terminal: confirmationProbe) }
        else { relay = try terminal.map { try CommandFrontendRelay(session: session, terminal: $0) } ?? CommandFrontendRelay(pipeSession: session) }
        defer { try? relay.close() }
        try runtime.attach(session: session, terminal: terminal)
        let settings = try CommandFrontendCallerSettings(preferences: [:], defaultIOMode: ptyMode ? .pty : .pipes,
            defaultDisconnectBehavior: .terminate, defaultReadiness: configuration)
        var result: CommandFrontendExit
        do {
            result = try CommandFrontendMain.runLoop(relay: relay, runtime: runtime, settings: settings)
            try require(!failureMode, "connection failure was lost")
        } catch Failure.connectionFailed {
            try require(failureMode && !relay.needsTerminalRestoration && relay.terminalResult == nil,
                "raw lease escaped connection failure")
            try require(cleanupProbe?.failures == 1 && cleanupProbe?.restorationFailures == 1,
                "connection cleanup did not retry")
            result = .status(EX_PROTOCOL)
        }
        try require(!cleanupMode || cleanupProbe?.failures == 1, "cleanup failure was not exercised")
        try require(!suspendRetryMode || cleanupProbe?.restorationFailures == 1 && cleanupProbe?.failures == 0,
            "suspend restoration retry was not exercised")
        try require(!jobRetryMode || confirmationProbe?.injected == true, "confirmation cancellation was not exercised")
        try require(done.wait(timeout: .now() + 5) == .success, "server completion")
        try outcome.withLock { result in
            guard let result else { throw Failure.assertion("server result") }; try result.get()
        }
        var unread = Data(count: originalInput.count)
        try require(unread.withUnsafeMutableBytes { Darwin.read(input[0], $0.baseAddress, $0.count) } == originalInput.count && unread == originalInput,
            "frontend read pipe input")
        try require(fcntl(input[0], F_GETFL) == flags && lookups == 2, "flags or retries")
        try relay.close()
        if ptyMode {
            var restored = termios()
            try require(tcgetattr(slave, &restored) == 0 && restored.c_iflag == originalAttributes.c_iflag &&
                restored.c_oflag == originalAttributes.c_oflag && restored.c_cflag == originalAttributes.c_cflag &&
                restored.c_lflag & ~tcflag_t(PENDIN) == originalAttributes.c_lflag & ~tcflag_t(PENDIN) &&
                restored.c_ispeed == originalAttributes.c_ispeed && restored.c_ospeed == originalAttributes.c_ospeed &&
                withUnsafeBytes(of: restored.c_cc, { Data($0) }) == withUnsafeBytes(of: originalAttributes.c_cc, { Data($0) }),
                "terminal restoration")
            _ = Darwin.close(master); master = -1
            _ = Darwin.close(slave); slave = -1
        }
        try runtime.close()
        try require(!cleanupFailed, "cleanup")
        FileHandle.standardOutput.write(Data("{\"authenticatedComposedLoop\":true,\"actualArgvAndDirectoryCaptured\":true,\"rawClaimsPreserved\":true,\"busyThenOneAdmission\":true,\"pipeInputUnread\":true,\"originalFlagsPreserved\":true,\"cleanupCompleted\":true,\"privatePTYChecked\":\(ptyMode),\"interruptedCleanupChecked\":\(cleanupMode),\"failedConnectionCleanupChecked\":\(failureMode),\"suspendRestorationRetryChecked\":\(suspendRetryMode),\"confirmedJobChecked\":\(jobMode),\"confirmedJobRetryChecked\":\(jobRetryMode)}\n".utf8))
        return result
    }
    private static func queued(_ operation: () throws -> Bool) throws {
        let deadline = Date().addingTimeInterval(5)
        while !(try operation()) { try require(Date() < deadline, "queue deadline"); usleep(1000) }
    }
}
