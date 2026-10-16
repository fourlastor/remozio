#if !DEBUG
#error("This owned-process fixture must never be built for release.")
#endif
import CryptoKit
import Darwin
import Foundation
import OwnedTTY
import RemozioMach
import RemozioProtocol
import Security
@testable import RemozioCore

private enum Failure: Error { case assertion(String) }
private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure.assertion(message) }
}
private let mac = Data(repeating: 1, count: 16)
private let account = Data(repeating: 2, count: 16)
private func targetArguments(mode: String, target: String, marker: String) -> [String] {
    if mode == "nested" {
        return [target, "--noprofile", "--norc", "-i", "-c",
            "stty -echo; printf '\\nREADY_MARKER\\n'; exec /bin/bash --noprofile --norc -i"]
    }
    return [target, mode, marker]
}

private func signingIdentity() throws -> (String, Data) {
    var code: SecCode?, information: CFDictionary?
    try require(SecCodeCopySelf([], &code) == errSecSuccess, "self code")
    guard let code else { throw Failure.assertion("self code absent") }
    try require(remozio_copy_dynamic_signing_information(code, &information) == errSecSuccess, "code information")
    guard let fields = information as? [String: Any], let hash = fields[kSecCodeInfoUnique as String] as? Data else {
        throw Failure.assertion("code hash absent")
    }
    return ("cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\"", hash)
}

/// Observe authenticated output without replacing the authority's current-job callback.
private final class ObservedChannel: CommandFrontendExecutionChannel {
    let session: RetainedCommandExecutionSession
    let report: Int32
    let mode: String
    let keyboard: Int32
    let nestedTarget: String
    let marker: String
    private var output = Data()
    private(set) var reportedResume = false
    private(set) var stoppedQueries = 0
    private(set) var queryCount = 0
    private(set) var continuations = 0
    private(set) var runningQueries = 0
    private var historicalStop: CommandExecutionStreamEvent?
    private var buffered: [CommandExecutionStreamEvent] = []
    private(set) var nestedPhase = 0
    private(set) var nestedUnknownQueries = 0
    private(set) var originalStopEvents = 0
    init(_ session: RetainedCommandExecutionSession, report: Int32, mode: String, keyboard: Int32,
         nestedTarget: String, marker: String) {
        self.session = session; self.report = report; self.mode = mode; self.keyboard = keyboard
        self.nestedTarget = nestedTarget; self.marker = marker
    }
    private func typeBytes(_ bytes: Data) throws {
        try require(bytes.withUnsafeBytes { Darwin.write(keyboard, $0.baseAddress, $0.count) } == bytes.count,
            "owned frontend keyboard input")
    }
    private func nestedQuery() throws {
        try require(session.requestCurrentJob(timeoutMilliseconds: 5000), "nested current job query")
        queryCount += 1
    }
    var executionIOMode: CommandIOMode? { session.executionIOMode }
    var supportsCurrentJobQueries: Bool { session.supportsCurrentJobQueries }
    func requestCurrentJob(timeoutMilliseconds: UInt32) throws -> Bool {
        let sent = try session.requestCurrentJob(timeoutMilliseconds: timeoutMilliseconds)
        if sent { queryCount += 1 }; return sent
    }
    func invalidateCurrentJobQuery() { session.invalidateCurrentJobQuery() }
    func pollStreamEvent(timeoutMilliseconds: UInt32, nonblocking: Bool) throws -> CommandExecutionStreamEvent? {
        let previousPhase = nestedPhase
        defer {
            if mode == "nested" && previousPhase != nestedPhase {
                FileHandle.standardError.write(Data("Owned nested fixture reached phase \(nestedPhase).\n".utf8))
            }
        }
        if historicalStop == nil && !buffered.isEmpty { return buffered.removeFirst() }
        let event = try session.pollStreamEvent(timeoutMilliseconds: timeoutMilliseconds, nonblocking: nonblocking)
        if case .jobState(let observation)? = event, case .stopped = observation.state { originalStopEvents += 1 }
        if mode == "stale", case .jobState(let observation)? = event, case .stopped = observation.state,
           historicalStop == nil && continuations == 0 {
            historicalStop = event
            try require(session.forwardSignal(UInt32(SIGCONT)), "overtaking actual continuation")
            continuations += 1
            return nil
        }
        if case .currentJob(let observation)? = event, case .stopped = observation.state { stoppedQueries += 1 }
        if mode == "stale", case .currentJob(let observation)? = event, case .running = observation.state {
            runningQueries += 1
            try require(session.forwardInput(Data("FINISH\n".utf8)) == 7, "finish actual stale target")
        }
        if mode == "nested", case .currentJob(let observation)? = event {
            if nestedPhase == 2, case .unknown = observation.state {
                nestedUnknownQueries += 1; nestedPhase = 3
                try typeBytes(Data([0x1a]))
            } else if nestedPhase == 4, case .running = observation.state {
                runningQueries += 1; nestedPhase = 5
                try typeBytes(Data("fg\n".utf8))
            } else { throw Failure.assertion("unexpected actual nested job state") }
        }
        if case .output(let bytes)? = event {
            output.append(bytes)
            if output.count > 4096 { output.removeFirst(output.count - 4096) }
            if !reportedResume && output.range(of: Data("TARGET_RESUMED".utf8)) != nil {
                reportedResume = true
            }
            if mode == "nested" {
                if nestedPhase == 0 && output.range(of: Data("READY_MARKER".utf8)) != nil {
                    nestedPhase = 1; output.removeAll()
                    func quote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
                    try typeBytes(Data("\(quote(nestedTarget)) nested \(quote(marker))\n".utf8))
                } else if nestedPhase == 1 && output.range(of: Data("NESTED_RUNNING".utf8)) != nil {
                    nestedPhase = 2; output.removeAll(); try nestedQuery()
                } else if nestedPhase == 3 && output.range(of: Data("Stopped".utf8)) != nil {
                    nestedPhase = 4; output.removeAll(); try nestedQuery()
                } else if nestedPhase == 5 && output.range(of: Data("NESTED_RESUMED".utf8)) != nil {
                    nestedPhase = 6; output.removeAll(); try typeBytes(Data("RELEASE\n".utf8))
                } else if nestedPhase == 6 && output.range(of: Data("NESTED_DONE".utf8)) != nil {
                    nestedPhase = 7; output.removeAll(); try typeBytes(Data("exit 13\n".utf8))
                }
            }
        }
        if let historicalStop {
            if let event { buffered.append(event) }
            try require(buffered.count <= 128, "bounded delayed frames")
            if reportedResume {
                self.historicalStop = nil
                return historicalStop
            }
            return nil
        }
        return event
    }
    func forwardInput(_ bytes: Data) throws -> Int { try session.forwardInput(bytes) }
    func finishInput() throws -> Bool { try session.finishInput() }
    func acknowledgeOutput() throws -> Bool { try session.acknowledgeOutput() }
    func resizeTerminal(rows: UInt16, columns: UInt16, pixelWidth: UInt16, pixelHeight: UInt16) throws -> Bool {
        try session.resizeTerminal(rows: rows, columns: columns, pixelWidth: pixelWidth, pixelHeight: pixelHeight)
    }
    func forwardSignal(_ number: UInt32) throws -> Bool {
        let sent = try session.forwardSignal(number)
        if sent && number == UInt32(SIGCONT) {
            continuations += 1
            var marker: UInt8 = 66
            try require(Darwin.write(report, &marker, 1) == 1, "background continuation report")
        }
        return sent
    }
    func cancelCommand() throws -> Bool { try session.cancelCommand() }
    func close() { session.close() }
}

@main
private struct Probe {
    static func main() {
        guard geteuid() != 0 else { exit(EX_NOPERM) }
        do {
            let arguments = CommandLine.arguments
            guard arguments.count >= 2 else { throw Failure.assertion("role") }
            switch arguments[1] {
            case "frontend":
                try require(arguments.count == 6 && ["job", "stale", "nested"].contains(arguments[2]), "frontend arguments")
                let result = try frontend(mode: arguments[2], target: arguments[3], marker: arguments[4], nestedTarget: arguments[5])
                result.finish()
            case "authority":
                try require(arguments.count == 8 && ["job", "stale", "nested"].contains(arguments[2]), "authority arguments")
                try authority(mode: arguments[2], supervisor: arguments[3], monitor: arguments[4], child: arguments[5],
                    target: arguments[6], nestedTarget: arguments[7])
            default: throw Failure.assertion("role")
            }
        } catch {
            FileHandle.standardError.write(Data("Live command fixture failed: \(error)\n".utf8))
            exit(EX_SOFTWARE)
        }
    }

    private static func frontend(mode: String, target: String, marker: String, nestedTarget: String) throws -> CommandFrontendExit {
        var failedCleanup = false
        let runtime = CommandFrontendRuntime(reportCleanupFailure: { _ in failedCleanup = true })
        defer { try? runtime.close() }
        try runtime.checkReady()
        var master: Int32 = -1, slave: Int32 = -1
        try require(remozio_fixture_adopt_tty(&master, &slave) == 0, "owned frontend terminal")
        defer { _ = Darwin.close(master); _ = Darwin.close(slave) }
        guard let reportText = getenv("REMOZIO_FIXTURE_JOB_REPORT"), let report = Int32(String(cString: reportText)),
              (3...1024).contains(report), fcntl(report, F_GETFD) >= 0 else { throw Failure.assertion("owned report descriptor") }
        defer { _ = Darwin.close(report) }
        let terminal = try CommandFrontendTerminal(descriptor: slave, reportRestorationFailure: { _ in failedCleanup = true })
        defer { try? terminal.close() }
        var port: mach_port_t = 0
        try require(task_get_special_port(mach_task_self_, TASK_BOOTSTRAP_PORT, &port) == KERN_SUCCESS && port != 0, "inherited authority right")
        defer { _ = mach_port_deallocate(mach_task_self_, port) }
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 16, maxItems: 2048)
        let (expression, _) = try signingIdentity()
        let invocation = try CommandFrontendInvocation(arguments: (["remozio", "run", "--uid", String(geteuid()), "--"] +
            targetArguments(mode: mode, target: target, marker: marker)).map { Data($0.utf8) },
            defaultIOMode: .pty, defaultDisconnectBehavior: .terminate, limits: limits)
        let directory = try CommandFrontendInvocation.currentDirectory()
        let template = try invocation.submission(directory: directory, executablePath: Data(target.utf8),
            binding: .init(id: Data(repeating: 9, count: 16), nonce: Data(repeating: 8, count: 32), callerBinding: Data(repeating: 7, count: 16)),
            schemaVersion: 1, limits: limits)
        let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 10000,
            initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 5000)
        let response = try CommandCallerReadiness.submitMappedIO(template, inputDescriptor: slave, outputDescriptor: slave,
            errorDescriptor: slave, controlTerminalDescriptor: slave, authorityPort: { port }, expression: expression,
            userID: geteuid(), auditSessionID: nil, macID: mac, accountID: account, submissionLimits: limits,
            configuration: configuration, currentJobQueries: true)
        guard case .admitted(let session) = response else { throw Failure.assertion("admission") }
        defer { session.close() }
        let observed = ObservedChannel(session, report: report, mode: mode, keyboard: master, nestedTarget: nestedTarget, marker: marker)
        let relay = try CommandFrontendRelay(channel: observed, terminal: terminal)
        defer { try? relay.close() }
        try runtime.attach(session: session, terminal: terminal)
        let settings = try CommandFrontendCallerSettings(preferences: [:], defaultIOMode: .pty,
            defaultDisconnectBehavior: .terminate, defaultReadiness: configuration)
        let result = try CommandFrontendMain.runLoop(relay: relay, runtime: runtime, settings: settings)
        try relay.close(); try runtime.close()
        let checked: Bool
        if mode == "nested" {
            checked = observed.nestedPhase == 7 && observed.nestedUnknownQueries == 1 && observed.runningQueries == 1 &&
                observed.stoppedQueries == 0 && observed.originalStopEvents == 0 && observed.continuations == 0
        } else {
            checked = observed.reportedResume && observed.continuations == 1 &&
                (mode == "job" ? observed.stoppedQueries >= 1 : observed.stoppedQueries == 0 && observed.runningQueries >= 1)
        }
        try require(!failedCleanup && checked,
            "fresh stop confirmation or original continuation missing")
        let evidence: [String: Any] = ["freshStoppedQueries": observed.stoppedQueries, "queryCount": observed.queryCount,
            "freshRunningQueries": observed.runningQueries,
            "nestedPhase": observed.nestedPhase, "nestedUnknownQueries": observed.nestedUnknownQueries,
            "originalStopEvents": observed.originalStopEvents,
            "originalContinuations": observed.continuations, "targetResumeOutputObserved": observed.reportedResume,
            "frontendCleanupCompleted": !failedCleanup]
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: evidence))
        return result
    }

    private static func authority(mode: String, supervisor: String, monitor: String, child: String, target: String, nestedTarget: String) throws {
        try require(remozio_fixture_install_cancellation() == 0, "owned authority cancellation")
        let clock = try AuthorityClock(), limits = try CBORLimits(maxBytes: 16384, maxDepth: 16, maxItems: 2048)
        let (expression, hash) = try signingIdentity()
        guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.assertion("temporary path") }
        let root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent("remozio-live-\(UUID())")
        free(canonical)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("store"), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        for name in ["writer.lock", "journal.sqlite"] {
            let descriptor = Darwin.open(root.appendingPathComponent("store/\(name)").path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
            try require(descriptor >= 0, "journal file"); _ = Darwin.close(descriptor)
        }
        let database = try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
            macID: mac, accountID: account, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 30, busyMilliseconds: 100, initialize: true, maximumCommandSubmissions: 30)
        let policy = try AuthorityCodePolicy(entries: [AuthorityCodeEntry(role: .commandFrontend, teamID: "TEAMID1234",
            identifier: "dev.remozio.fixture.frontend", installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: hash, active: true)])
        try database.write { transaction in
            _ = try transaction.installCodePolicy(policy, expectedRevision: nil)
            try transaction.installCommandSubmissionReplay()
        }
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let revision = try database.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Data(repeating: 3, count: 16)),
            4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let writer = try database.write { try $0.createEpoch(descriptor) }
        let key = P256.Signing.PrivateKey()
        let enrollment = try StoredApprovalEnrollment(epoch: Data(repeating: 9, count: 16), notificationTag: Data(repeating: 10, count: 32),
            identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            approval: ApprovalEnrollment(phoneID: Data(repeating: 5, count: 16), active: true, capabilities: capabilities, keys: [
                EnrolledApprovalKey(id: Data(repeating: 6, count: 16), keyClass: .biometric, publicKey: key.publicKey.x963Representation),
                EnrolledApprovalKey(id: Data(repeating: 7, count: 16), keyClass: .decision,
                    publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)]))
        _ = try database.write { try $0.addApprovalEnrollment(enrollment, expectedTrustRevision: revision,
            eventID: Data(repeating: 30, count: 16), receiptTimeMs: nil, writer: writer, expectedAuditHead: 0) }
        let requests = try ApprovalRequestCoordinator(database: database, writer: writer, clockEpoch: clock.epoch,
            maximumRequests: 8, maximumRetainedBytes: 65536, requestLimits: limits, captureLimits: limits,
            decisionLimits: limits, signingLimits: limits, auditLimits: limits)
        let journal = AuthorityJournal(requests: requests)
        defer { try? journal.close() }
        var port: mach_port_t = 0
        try require(mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS, "receive right")
        guard mach_port_insert_right(mach_task_self_, port, port, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            throw Failure.assertion("send right")
        }
        defer { _ = mach_port_deallocate(mach_task_self_, port) }
        let host = try CommandReceiveHost(takingReceiveRight: port, macID: mac, accountID: account, userID: geteuid(),
            auditSessionID: nil, maximumSessions: 4, maximumPayloadBytes: 16384, receiveWaitMilliseconds: 10,
            capabilities: .mappedTerminalCurrentJobExecution, context: { _ in
                guard let token = try journal.read({ try $0.codePolicy()?.roleRevisions[.commandFrontend] }) else {
                    throw Failure.assertion("frontend revision")
                }
                return .init(expression: expression, roleRevision: token)
            })
        defer { host.close() }
        var supervisorPID: pid_t = -1, output: Int32 = -1
        let marker = root.appendingPathComponent("target-resumed").path
        let arguments = [supervisor, CommandLine.arguments[0], "frontend", mode, target, marker, nestedTarget]
            .map { value in value.withCString { strdup($0)! } }
        defer { arguments.forEach { free($0) } }
        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { $0 } + [nil]
        try require(remozio_fixture_spawn_supervisor(supervisor, &argv, port, marker, &supervisorPID, &output) == 0, "spawn owned supervisor")
        defer { _ = Darwin.close(output) }
        var reaped = false, status: Int32 = 0, report = Data(), admitted = 0, requestID: Data?
        var failure: Error?
        let deadline = try clock.now().milliseconds + 50000
        while !reaped || journal.activeCommandCount != 0 {
            do {
                if failure == nil {
                    try require(remozio_fixture_cancelled() == 0, "owned fixture cancelled")
                    _ = try host.poll { received in
                        let command = try host.assemble(received: received, captureSchemaVersion: 3,
                            resolvedTarget: CommandTarget(uid: geteuid(), gid: getgid(), supplementaryGroups: [getgid()], observedName: "fixture"),
                            minimalEnvironment: [("HOME", root.path), ("LC_ALL", "C"), ("PATH", "/usr/bin:/bin"),
                                ("PS1", "TEST> "), ("TERM", "dumb")].map { .init(name: Data($0.0.utf8), value: Data($0.1.utf8), source: .minimal) },
                            streamBinding: Data(repeating: 12, count: 16), submissionLimits: limits, captureLimits: limits)
                        let now = try clock.now(), wall = UInt64(Date().timeIntervalSince1970 * 1000)
                        let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: command.capture.canonicalBytes,
                            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
                            firstObservedAt: now, deadlineMilliseconds: now.milliseconds + 15000,
                            createdUnixMilliseconds: wall, expiresUnixMilliseconds: wall + 15000)
                        let request = try journal.admitCommand(command, draft: draft, expression: expression, userID: geteuid(),
                            auditSessionID: nil, now: { try clock.now() }, receiptTimeMs: nil)
                        admitted += 1; requestID = request.requestID
                        let body = try DecisionPayload(macID: mac, accountID: account, requestID: request.requestID,
                            requestDigest: request.requestDigest(bodyLimits: limits, signingLimits: limits), challenge: request.challenge,
                            phoneID: Data(repeating: 5, count: 16), keyID: Data(repeating: 6, count: 16),
                            action: request.permittedActions.first { $0.choice == .execute }!).encode(limits: limits)
                        let signature = try key.signature(for: SigningInput.make(wireVersion: 1, messageType: .decision,
                            purpose: .biometricAuthorization, canonicalPayload: body, payloadLimits: limits, inputLimits: limits)).rawRepresentation
                        _ = try journal.withRequests { try $0.consume(canonicalDecision: body, signature: signature,
                            authenticatedPhoneID: Data(repeating: 5, count: 16), authenticatedEnrollmentEpoch: Data(repeating: 9, count: 16),
                            now: clock.now(), receiptTimeMs: nil) }
                        try journal.beginCommandExecution(requestID: request.requestID, monitorPath: monitor, childPath: child,
                            preparationMilliseconds: 5000, fileCreationMask: 0o022, validateElevation: { capture in
                                try require(capture.target.uid == geteuid() && capture.target.gid == getgid() &&
                                    capture.executable.path == Data(target.utf8) &&
                                    capture.arguments == targetArguments(mode: mode, target: target, marker: marker).map { Data($0.utf8) },
                                    "fixture target policy")
                            }, clock: { try clock.now() }, runtime: { tx, approval, capture in
                                try approval.requireCurrent(tx.requestDeliveryTrust())
                                guard let snapshot = try tx.codePolicy(), let entry = snapshot.policy.entries.first,
                                      let token = snapshot.roleRevisions[.commandFrontend] else { throw Failure.assertion("runtime policy") }
                                return CommandExecutionRuntime(child: entry, childRevision: token, monitor: entry, monitorRevision: token,
                                    frontendRevision: token, callerExpression: expression, userID: capture.requester.effectiveUID, sessionID: nil)
                            }, launcher: { _ in { } })
                    }
                }
                if !reaped {
                    let found = waitpid(supervisorPID, &status, WNOHANG)
                    if found == supervisorPID { reaped = true }
                    else if found < 0 && errno != EINTR {
                        if errno == ECHILD { reaped = true }
                        throw Failure.assertion("supervisor wait")
                    }
                }
                var bytes = [UInt8](repeating: 0, count: 1024)
                let count = Darwin.read(output, &bytes, bytes.count)
                if count > 0 { report.append(contentsOf: bytes.prefix(count)) }
                else if count < 0 && errno != EAGAIN && errno != EINTR { throw Failure.assertion("supervisor report") }
                try require(report.count <= 8192, "bounded report")
                if try clock.now().milliseconds >= deadline { throw Failure.assertion("live fixture deadline") }
            } catch {
                if failure == nil { failure = error; if !reaped { _ = kill(supervisorPID, SIGTERM) } }
            }
            usleep(1000)
        }
        if let failure { throw failure }
        try require(status == 13 << 8 && admitted == 1 && requestID != nil,
            "supervisor status=\(status), admissions=\(admitted), request=\(requestID != nil), reportBytes=\(report.count)")
        guard let requestID else { throw Failure.assertion("request absent") }
        let outcome = try journal.withRequests { try $0.historicalOutcome(requestID: requestID) }
        try require(outcome?.phase == .failed && outcome?.revision == 2, "durable verified exit outcome")
        let frontend = try JSONSerialization.jsonObject(with: report)
        let evidence: [String: Any] = ["separateAuthorityAndFrontend": true, "oneOriginalAdmission": admitted == 1,
            "actualMonitorAndTargetReaped": journal.activeCommandCount == 0, "nativeSupervisorStatus": status,
            "durableVerifiedOutcome": outcome?.revision == 2,
            "frontend": frontend]
        FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys]))
    }
}
