import Darwin
import Foundation
import RemozioProtocol

public enum CommandFrontendExit {
    case status(Int32), signal(Int32)

    /// Run only in the CLI after its owners have completed cleanup.
    public func finish() -> Never {
        switch self {
        case .status(let status): exit(status)
        case .signal(let number):
            var action = sigaction(); action.__sigaction_u.__sa_handler = SIG_DFL
            sigemptyset(&action.sa_mask)
            var mask = sigset_t(); sigemptyset(&mask); sigaddset(&mask, number)
            guard number > 0, number < NSIG, sigaction(number, &action, nil) == 0,
                  pthread_sigmask(SIG_UNBLOCK, &mask, nil) == 0 else { exit(EX_OSERR) }
            raise(number)
            exit(128 + number)
        }
    }
}

private enum CommandFrontendLocalError: Error { case signal(Int32), noCallingTerminal }

/// Entry point for the bundled CLI. It never executes the requested command locally.
public enum CommandFrontendMain {
    public static let configurationPath = "/Library/Application Support/Remozio/frontend.cbor"
    private static let usage = "Usage: remozio run|sudo [options] -- executable [arguments...]"

    /// Borrows the actual process argv. The executable supplies its fixed app preference domain.
    public static func run(count: Int32, vector: UnsafePointer<UnsafeMutablePointer<CChar>?>,
                           preferencesDomain: String) -> CommandFrontendExit {
        do {
            let ceiling = try CBORLimits(maxBytes: Int(UInt32.max) - 1024, maxDepth: 64, maxItems: Int(Int32.max))
            let arguments = try CommandFrontendInvocation.copyArguments(count: count, vector: vector, limits: ceiling)
            if arguments.count == 2, arguments[1] == Data("--help".utf8) {
                log(usage); return .status(EX_OK)
            }
            // Validate syntax before reading setup or touching any stream. Actual defaults are applied below.
            _ = try CommandFrontendInvocation(arguments: arguments, defaultIOMode: .pty,
                defaultDisconnectBehavior: .terminate, limits: ceiling)
            let selected = try CommandFrontendConfigurationSelection.load(ownerUID: getuid())
            let configuration = selected.configuration
            guard let defaults = UserDefaults(suiteName: preferencesDomain) else {
                throw CommandFrontendCallerSettingsError.invalidPreferences
            }
            let settings = try CommandFrontendCallerSettings(
                preferences: defaults.persistentDomain(forName: preferencesDomain) ?? [:],
                defaultIOMode: configuration.defaultIOMode, defaultDisconnectBehavior: configuration.defaultDisconnectBehavior,
                defaultReadiness: configuration.readiness)
            let invocation = try CommandFrontendInvocation(arguments: arguments, defaultIOMode: settings.ioMode,
                defaultDisconnectBehavior: settings.disconnectBehavior, limits: configuration.submissionLimits)
            return try execute(invocation, configuration: configuration, configurationPath: selected.path, settings: settings)
        } catch CommandFrontendLocalError.signal(let number) { return .signal(number) }
        catch let error as CommandFrontendInvocationError {
            if error == .oversized { log("The command exceeds the configured submission size."); return .status(EX_DATAERR) }
            if error == .executableNotFound { log("Executable not found in the supplied PATH."); return .status(127) }
            log(usage); return .status(EX_USAGE)
        } catch CommandFrontendLocalError.noCallingTerminal {
            log("PTY mode requires a calling terminal. Headless PTY output routing is not configured."); return .status(EX_CONFIG)
        } catch is CommandFrontendCallerSettingsError {
            log("Invalid command settings. Check Remozio Settings."); return .status(EX_CONFIG)
        } catch let error as CommandCallerReadinessError {
            switch error {
            case .deadlineExceeded:
                log("The authority did not become ready within the configured wait."); return .status(EX_TEMPFAIL)
            case .invalidConfiguration:
                log("Invalid command readiness settings."); return .status(EX_CONFIG)
            case .clockMovedBackwards:
                log("The command caller clock failed."); return .status(EX_OSERR)
            }
        } catch is CommandFrontendConfigurationError {
            log("Protected Remozio installation metadata is unavailable or invalid."); return .status(EX_CONFIG)
        } catch {
            log("The request connection failed. Its execution outcome may be unknown. The command was not retried.")
            return .status(EX_PROTOCOL)
        }
    }

    private static func execute(_ invocation: CommandFrontendInvocation, configuration: CommandFrontendConfiguration,
                                configurationPath: String, settings: CommandFrontendCallerSettings) throws -> CommandFrontendExit {
        var cleanupFailed = false
        let report: (Int32) -> Void = { _ in
            cleanupFailed = true; log("Command caller cleanup failed. Terminal settings may require recovery.")
        }
        let runtime = CommandFrontendRuntime(reportCleanupFailure: report)
        defer { do { try runtime.close() } catch { report(EIO) } }
        try runtime.checkReady()
        let terminalDescriptor = Darwin.open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY)
        guard terminalDescriptor >= 0 || [ENXIO, ENODEV, ENOENT, ENOTTY].contains(errno) else {
            throw CommandFrontendTerminalError.native(errno)
        }
        defer { if terminalDescriptor >= 0 { _ = Darwin.close(terminalDescriptor) } }
        let terminal: CommandFrontendTerminal?
        if invocation.ioMode == .pty {
            guard terminalDescriptor >= 0 else { throw CommandFrontendLocalError.noCallingTerminal }
            terminal = try CommandFrontendTerminal(descriptor: terminalDescriptor, reportRestorationFailure: report)
        } else { terminal = nil }
        defer { do { try terminal?.close() } catch { report(EIO) } }
        let directory = try CommandFrontendInvocation.currentDirectory()
        let path = getenv("PATH").map { Data(bytes: $0, count: strlen($0)) } ?? Data()
        let template = try invocation.submission(directory: directory, executablePath: invocation.executablePath(directory: directory, searchPath: path),
            binding: .init(id: Data(repeating: 0, count: 16), nonce: Data(repeating: 0, count: 32),
                           callerBinding: Data(repeating: 0, count: 16)), schemaVersion: 1, limits: configuration.submissionLimits)
        let endpoint = try CommandFrontendEndpoint(serviceName: configuration.serviceName)
        defer { endpoint.close() }
        let response = try CommandCallerReadiness.submitMappedIO(template, inputDescriptor: STDIN_FILENO,
            outputDescriptor: STDOUT_FILENO, errorDescriptor: STDERR_FILENO,
            controlTerminalDescriptor: invocation.submissionControlTerminal(terminalDescriptor),
            authorityPort: endpoint.lookup, authorityPolicy: configuration.authorityPolicy,
            macID: configuration.macID, accountID: configuration.accountID, submissionLimits: configuration.submissionLimits,
            configuration: settings.readiness, checkCancellation: {
                let signals = try runtime.takeSignals()
                if let number = terminatingSignal(signals) { throw CommandFrontendLocalError.signal(number) }
                if signals.contains(.suspend) {
                    try terminal?.restore()
                    try runtime.suspend(waitMilliseconds: settings.foregroundRetryMilliseconds)
                }
            }, onStatus: { status in
                switch status {
                case .connecting: log("Waiting for the command authority.")
                case .waiting: log("The authority is busy. Waiting before a fresh submission.")
                }
            }, refreshAuthorityPolicy: { try configuration.reloadAuthorityPolicy(path: configurationPath) }, currentJobQueries: true)
        switch response {
        case .result(let result): return admissionExit(result)
        case .admitted(let session):
            defer { session.close() }
            let relay = try terminal.map { try CommandFrontendRelay(session: session, terminal: $0) }
                ?? CommandFrontendRelay(pipeSession: session)
            defer { do { try relay.close() } catch { report(EIO) } }
            try runtime.attach(session: session, terminal: terminal)
            let outcome = try runLoop(relay: relay, runtime: runtime, settings: settings)
            // Restore while returning signal routes are still installed, before publishing the native result.
            try relay.close(); try runtime.close()
            return cleanupFailed ? .status(EX_OSERR) : outcome
        }
    }

    static func runLoop(relay: CommandFrontendRelay, runtime: CommandFrontendRuntime,
                        settings: CommandFrontendCallerSettings) throws -> CommandFrontendExit {
        do { return try driveLoop(relay: relay, runtime: runtime, settings: settings) }
        catch {
            let original = error
            do { try restoreAfterFailure(relay: relay, runtime: runtime, settings: settings) }
            catch { log("Command caller cleanup failed. Terminal settings may require recovery.") }
            throw original
        }
    }

    private static func restoreAfterFailure(relay: CommandFrontendRelay, runtime: CommandFrontendRuntime,
                                           settings: CommandFrontendCallerSettings) throws {
        while true {
            do { try relay.close(); return }
            catch CommandFrontendTerminalError.native(let number) where number == EINTR || number == EAGAIN {
                // Preserve the original error and saved settings. Cleanup does not resume command controls.
                _ = try runtime.takeSignals()
                try runtime.wait(milliseconds: Int64(settings.foregroundRetryMilliseconds))
            }
        }
    }

    private static func driveLoop(relay: CommandFrontendRelay, runtime: CommandFrontendRuntime,
                                  settings: CommandFrontendCallerSettings) throws -> CommandFrontendExit {
        var pending: CommandFrontendSignals = []
        let clock = try AuthorityClock()
        var candidateRevision: UInt64?, mirroredRevision: UInt64 = 0
        var query: (ticket: UInt64, deadline: UInt64)?
        var confirmation: (revision: UInt64, ticket: UInt64, deadline: UInt64)?
        var retryAfter: UInt64 = 0
        while true {
            let signals = try runtime.takeSignals()
            pending.formUnion(signals)
            if !signals.isEmpty { relay.invalidateCurrentJobQuery(); confirmation = nil }
            if relay.terminalResult != nil {
                // Keep the verified native result while cleanup retries. Closed channels accept no further controls.
                pending = []
                candidateRevision = nil; query = nil; confirmation = nil
            } else {
                if signals.contains(.continued) {
                    pending.remove(.suspend); candidateRevision = nil; relay.resume()
                }
                if signals.contains(.suspend) || terminatingSignal(signals) != nil { candidateRevision = nil }
                if signals.contains(.suspend) { pending.remove(.continued) }
                if !relay.acceptsControls, let number = terminatingSignal(pending) {
                    throw CommandFrontendLocalError.signal(number)
                }
                if relay.acceptsControls {
                    for (flag, number): (CommandFrontendSignals, Int32) in [(.interrupt, SIGINT), (.terminate, SIGTERM),
                        (.hangup, SIGHUP), (.quit, SIGQUIT), (.brokenPipe, SIGPIPE), (.continued, SIGCONT)] {
                        if pending.contains(flag), try relay.forwardSignal(UInt32(number)) { pending.remove(flag) }
                    }
                }
                if pending.contains(.suspend) {
                    do { try relay.prepareForSuspension() }
                    catch CommandFrontendTerminalError.native(let number) where number == EINTR || number == EAGAIN {
                        // Retry restoration before stopping, without closing the admitted channel or activating over raw settings.
                        try runtime.wait(milliseconds: Int64(settings.foregroundRetryMilliseconds))
                        continue
                    }
                    if try !relay.acceptsControls || relay.forwardSignal(UInt32(SIGTSTP)) {
                        pending.remove(.suspend)
                        try runtime.suspend(waitMilliseconds: settings.foregroundRetryMilliseconds)
                        relay.resume()
                    }
                }
            }
            if let value = confirmation {
                let now = try clock.now().milliseconds, ticket = try runtime.jobTicket()
                if now >= value.deadline || ticket != value.ticket {
                    confirmation = nil; relay.resume()
                } else {
                    do {
                        if try relay.prepareForConfirmedSuspension() {
                            let queued = try runtime.suspendConfirmed(ticket: value.ticket, deadlineMilliseconds: value.deadline,
                                waitMilliseconds: settings.foregroundRetryMilliseconds)
                            if queued { mirroredRevision = value.revision; candidateRevision = nil }
                            relay.resume()
                        }
                        confirmation = nil
                        retryAfter = try clock.now().milliseconds + UInt64(settings.foregroundRetryMilliseconds)
                    } catch CommandFrontendTerminalError.native(let number) where number == EINTR || number == EAGAIN {
                        try runtime.wait(milliseconds: Int64(settings.foregroundRetryMilliseconds))
                        continue
                    }
                }
            }
            if candidateRevision != nil, confirmation == nil, query == nil, relay.supportsCurrentJobQueries,
               relay.acceptsControls, try clock.now().milliseconds >= retryAfter {
                let ticket = try runtime.jobTicket(), started = try clock.now().milliseconds
                if try relay.requestCurrentJob(timeoutMilliseconds: settings.readiness.controlTimeoutMilliseconds) {
                    query = (ticket, started + UInt64(settings.readiness.controlTimeoutMilliseconds))
                } else { retryAfter = started + UInt64(settings.controlRetryMilliseconds) }
            }
            switch try relay.advance(timeoutMilliseconds: settings.readiness.controlTimeoutMilliseconds, nonblocking: true) {
            case .terminal(let result): return terminalExit(result)
            case .progress, .interrupted: continue
            case .jobState(let value):
                if relay.supportsCurrentJobQueries {
                    switch value.state {
                    case .continued: candidateRevision = nil; confirmation = nil
                    case .stopped:
                        if value.revision > mirroredRevision { candidateRevision = value.revision }
                    }
                }
                continue
            case .currentJob(let value):
                let issued = query; query = nil
                switch value.state {
                case .running: candidateRevision = nil; confirmation = nil
                case .unknown:
                    retryAfter = try clock.now().milliseconds + UInt64(settings.foregroundRetryMilliseconds)
                case .stopped(_, let revision):
                    if let issued, revision > mirroredRevision, try clock.now().milliseconds < issued.deadline {
                        candidateRevision = revision
                        confirmation = (revision, issued.ticket, issued.deadline)
                    } else { retryAfter = try clock.now().milliseconds + UInt64(settings.foregroundRetryMilliseconds) }
                }
                continue
            case .waiting, .foregroundRequired, .suspended: break
            }
            let interests = relay.waitInterests
            let retry = interests.controlRetry || !pending.intersection([.interrupt, .terminate, .hangup, .quit, .brokenPipe, .continued, .suspend]).isEmpty
            let milliseconds: Int64
            if retry && interests.foregroundRetry { milliseconds = Int64(min(settings.controlRetryMilliseconds, settings.foregroundRetryMilliseconds)) }
            else if retry { milliseconds = Int64(settings.controlRetryMilliseconds) }
            else if interests.foregroundRetry || candidateRevision != nil { milliseconds = Int64(settings.foregroundRetryMilliseconds) }
            else { milliseconds = -1 }
            try runtime.wait(interests: interests, milliseconds: milliseconds)
        }
    }
    private static func terminatingSignal(_ signals: CommandFrontendSignals) -> Int32? {
        for (flag, number): (CommandFrontendSignals, Int32) in [(.hangup, SIGHUP), (.terminate, SIGTERM),
            (.interrupt, SIGINT), (.quit, SIGQUIT), (.brokenPipe, SIGPIPE)] {
            if signals.contains(flag) { return number }
        }
        return nil
    }
    static func terminalExit(_ result: VerifiedCommandTerminalResult) -> CommandFrontendExit {
        switch result.outcome {
        case .exited(let status): return .status(Int32(status))
        case .signalled(let signal): return .signal(Int32(signal))
        case .denied: return .status(EX_NOPERM)
        case .expired, .cancelledBeforeStart, .requesterExitedBeforeStart: return .status(EX_TEMPFAIL)
        case .failedBeforeStart: return .status(EX_OSERR)
        case .unknown: return .status(EX_SOFTWARE)
        }
    }
    private static func admissionExit(_ result: VerifiedCommandAdmissionResult) -> CommandFrontendExit {
        switch result.outcome {
        case .uncertain: log("Admission is uncertain. The command was not retried."); return .status(EX_PROTOCOL)
        case .notAdmitted(let reason, _):
            switch reason {
            case .policyRejected: return .status(EX_NOPERM)
            case .invalidRequest: return .status(EX_DATAERR)
            case .unsupported: return .status(EX_PROTOCOL)
            default: return .status(EX_TEMPFAIL)
            }
        case .admitted: return .status(EX_SOFTWARE)
        }
    }
    private static func log(_ value: String) {
        let bytes = Data((value + "\n").utf8)
        bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(STDERR_FILENO, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count > 0 { offset += count }
                else if count < 0, errno == EINTR { continue }
                else { break }
            }
        }
    }
}
