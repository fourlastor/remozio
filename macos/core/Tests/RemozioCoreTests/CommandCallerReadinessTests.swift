import CryptoKit
import Darwin
import Foundation
import os
import RemozioMach
import RemozioProtocol
import Security
import XCTest
@testable import RemozioCore

final class CommandCallerReadinessTests: XCTestCase {
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
    private enum Cancelled: Error { case stopped }
    private enum Reply: Sendable {
        case result(CommandAdmissionOutcome), lost, malformed, wrongDigest
    }
    private final class Endpoint {
        let port: mach_port_t
        init() throws {
            var value: mach_port_t = 0
            guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &value) == KERN_SUCCESS else {
                throw MachCommandCallerError.configuration
            }
            guard mach_port_insert_right(mach_task_self_, value, value, UInt32(MACH_MSG_TYPE_MAKE_SEND)) == KERN_SUCCESS else {
                _ = mach_port_mod_refs(mach_task_self_, value, MACH_PORT_RIGHT_RECEIVE, -1); throw MachCommandCallerError.configuration
            }
            port = value
        }
        deinit {
            _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1)
            _ = mach_port_deallocate(mach_task_self_, port)
        }
    }
    private struct Server {
        let completed: DispatchSemaphore
        let results: OSAllocatedUnfairLock<Result<Void, Error>?>
        let submissions: OSAllocatedUnfairLock<[CommandSubmission]>
        func finish() throws -> [CommandSubmission] {
            XCTAssertEqual(completed.wait(timeout: .now() + 5), .success)
            try results.withLock { try XCTUnwrap($0).get() }
            return submissions.withLock { $0 }
        }
    }
    private func expression() throws -> String {
        var code: SecCode?, information: CFDictionary?
        XCTAssertEqual(SecCodeCopySelf([], &code), errSecSuccess)
        XCTAssertEqual(remozio_copy_dynamic_signing_information(try XCTUnwrap(code), &information), errSecSuccess)
        let values = try XCTUnwrap(information as? [String: Any]), hash = try XCTUnwrap(values[kSecCodeInfoUnique as String] as? Data)
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }
    private func limits() throws -> CBORLimits { try .init(maxBytes: 8192, maxDepth: 16, maxItems: 1024) }
    private func template(ioMode: CommandIOMode = .pipes) throws -> CommandSubmission {
        try .init(schemaVersion: 1, executablePath: Data("/usr/bin/true".utf8),
            arguments: [Data("raw argv0".utf8), Data(), Data([0xff, 0x0a])], directoryPath: Data("/tmp".utf8),
            requestedTargetUID: 1234, environmentAdditions: [.init(name: Data("RAW".utf8), value: Data([0xfe, 0x22]))],
            ioMode: ioMode, disconnectBehavior: .terminate, unverifiedRationale: "original rationale",
            binding: .init(id: Data(repeating: 9, count: 16), nonce: Data(repeating: 8, count: 32),
                callerBinding: Data(repeating: 7, count: 16)), limits: limits())
    }
    private func busy(_ reason: CommandAdmissionRejectionReason) -> Reply {
        .result(.notAdmitted(reason, CommandAdmissionRetryClass(rawValue: reason.rawValue)!))
    }
    private func serve(_ endpoint: Endpoint, replies: [Reply], io: Bool = false, mapped: Bool = false,
                       capabilities: CommandHandshakeCapabilities? = nil,
                       terminalOutcome: CommandTerminalOutcome = .exited(13),
                       inspect: @escaping @Sendable (ReceivedMachCommandInputSubmission, CommandHandshakeProfile) throws -> Void = { _, _ in }) throws -> Server {
        let port = endpoint.port, expression = try expression(), user = geteuid(), mac = mac, account = account
        let completed = DispatchSemaphore(value: 0), results = OSAllocatedUnfairLock(initialState: Result<Void, Error>?.none)
        let submissions = OSAllocatedUnfairLock(initialState: [CommandSubmission]())
        DispatchQueue.global().async {
            defer { completed.signal() }
            let result = Result<Void, Error> {
                let receiver = try MachCommandCallerReceiver(receivePort: port, expression: expression, userID: user,
                    auditSessionID: nil, maxPayloadBytes: 8192)
                for reply in replies {
                    let session = try RetainedCommandHandshake(hello: receiver.receiveHello(timeoutMilliseconds: 5000),
                        capabilities: capabilities ?? (io ? .executionChannels : .admissionResults), macID: mac, accountID: account, expression: expression,
                        userID: user, auditSessionID: nil)
                    defer { session.close() }
                    let input = try mapped ? receiver.receiveMappedIOInput(timeoutMilliseconds: 5000) :
                        (io ? receiver.receiveIOInput(timeoutMilliseconds: 5000) : receiver.receiveAdmissionInput(timeoutMilliseconds: 5000))
                    defer { input.closeIfUnclaimed() }
                    let submission = try CommandSubmission(canonicalBytes: input.payload,
                        limits: CBORLimits(maxBytes: 8192, maxDepth: 16, maxItems: 1024), expectedSchemaVersion: 1)
                    submissions.withLock { $0.append(submission) }
                    try inspect(input, session.profile)
                    let outcome: CommandAdmissionOutcome
                    switch reply {
                    case .lost: continue
                    case .malformed: try input.sendAdmissionReply(Data([0xa0])); continue
                    case .wrongDigest: outcome = .notAdmitted(.updateWaiting, .updateWaiting)
                    case .result(let value): outcome = value
                    }
                    let digest = Data(SHA256.hash(data: submission.canonicalBytes))
                    let replyDigest = if case .wrongDigest = reply { Data(repeating: 0, count: 32) } else { digest }
                    let payload = CommandAdmissionResultPayload(profile: session.profile, submission: submission.binding,
                        submissionDigest: replyDigest, outcome: outcome)
                    try input.sendAdmissionReply(payload.canonicalBytes)
                    if io, case .admitted(let request) = outcome {
                        try XCTUnwrap(input.outputs).sendTerminalResult(CommandTerminalResultPayload(profile: session.profile,
                            original: submission, request: request, outcome: terminalOutcome).canonicalBytes, timeoutMilliseconds: 1000)
                    }
                }
            }
            results.withLock { $0 = result }
        }
        return Server(completed: completed, results: results, submissions: submissions)
    }
    private func submit(_ endpoint: Endpoint, fd: Int32, configuration: CommandCallerReadinessConfiguration? = nil,
                        cancellation: () throws -> Void = {}, status: (CommandCallerReadinessStatus) -> Void = { _ in },
                        clock: (() throws -> UInt64)? = nil, wait: ((UInt32, () throws -> Void) throws -> Void)? = nil,
                        lookup: (() throws -> mach_port_t)? = nil) throws -> VerifiedCommandAdmissionResult {
        try CommandCallerReadiness.submit(template(), inputDescriptor: fd, authorityPort: lookup ?? { endpoint.port },
            expression: expression(), userID: geteuid(), auditSessionID: nil, macID: mac, accountID: account,
            submissionLimits: limits(), configuration: configuration ?? .init(timeoutMilliseconds: 5000,
                initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 1000),
            checkCancellation: cancellation, onStatus: status, clock: clock, wait: wait)
    }
    private func assertNoNextAttempt(_ endpoint: Endpoint) throws {
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression(), userID: geteuid(),
            auditSessionID: nil, maxPayloadBytes: 8192)
        XCTAssertThrowsError(try receiver.receiveNext(timeoutMilliseconds: 20)) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
    }

    func testAllBusyClassesMakeFreshSubmissionsAndPreserveInvocationAndUnreadPipe() throws {
        let endpoint = try Endpoint(), admitted = CommandAdmittedRequest(requestID: Data(repeating: 3, count: 16),
            requestDigest: Data(repeating: 4, count: 32), challenge: Data(repeating: 5, count: 32))
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.admitted(admitted))])
        var fds: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&fds), 0); defer { for fd in fds { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(fds[1], "queued", 6), 6)
        let flags = fcntl(fds[0], F_GETFL), original = try template()
        var statuses: [CommandCallerReadinessStatus] = [], delays: [UInt32] = []
        let result = try submit(endpoint, fd: fds[0], status: { statuses.append($0) }, wait: { delay, check in
            delays.append(delay); try check()
        })
        XCTAssertEqual(result.outcome, .admitted(admitted))
        let submissions = try server.finish(); XCTAssertEqual(submissions.count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.id)).count, 5); XCTAssertEqual(Set(submissions.map(\.binding.nonce)).count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.callerBinding)).count, 5)
        for submission in submissions {
            XCTAssertNotEqual(submission.binding.id, original.binding.id); XCTAssertNotEqual(submission.binding.nonce, original.binding.nonce)
            XCTAssertEqual(submission.executablePath, original.executablePath); XCTAssertEqual(submission.arguments, original.arguments)
            XCTAssertEqual(submission.directoryPath, original.directoryPath); XCTAssertEqual(submission.requestedTargetUID, original.requestedTargetUID)
            XCTAssertEqual(submission.environmentAdditions, original.environmentAdditions); XCTAssertEqual(submission.ioMode, original.ioMode)
            XCTAssertEqual(submission.disconnectBehavior, original.disconnectBehavior); XCTAssertEqual(submission.unverifiedRationale, original.unverifiedRationale)
        }
        XCTAssertEqual(statuses, reasons.map(CommandCallerReadinessStatus.waiting)); XCTAssertEqual(delays, [1, 2, 4, 4])
        XCTAssertEqual(fcntl(fds[0], F_GETFL), flags)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(fds[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
        try assertNoNextAttempt(endpoint)
    }

    func testReasonChangesNeverResetTheDeadlineAndExhaustionKeepsTheLatestReason() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), busy(.storageUnavailable)])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 1000
        let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 3000, initialBackoffMilliseconds: 1000,
            maximumBackoffMilliseconds: 2000, controlTimeoutMilliseconds: 1000)
        XCTAssertThrowsError(try submit(endpoint, fd: fd, configuration: configuration, clock: { now }, wait: { delay, check in
            now += UInt64(delay); try check()
        })) { XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .storageUnavailable)) }
        XCTAssertEqual(now, 4000)
        XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
    }

    func testPermanentAndUncertainOutcomesNeverMakeAnotherAttempt() throws {
        let outcomes: [CommandAdmissionOutcome] = [.notAdmitted(.invalidRequest, .never), .notAdmitted(.policyRejected, .never),
            .notAdmitted(.capacityExceeded, .never), .notAdmitted(.unsupported, .never), .notAdmitted(.requesterExited, .never),
            .uncertain(.admissionRejected), .uncertain(.duplicateSubmission), .uncertain(.storageFailure)]
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        for outcome in outcomes {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [.result(outcome)])
            XCTAssertEqual(try submit(endpoint, fd: fd).outcome, outcome)
            XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        }
    }

    func testLostMalformedAndWrongBindingRepliesDoNotReuseAnEarlierBusyProof() throws {
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        for reply in [Reply.lost, .malformed, .wrongDigest] {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting), reply])
            let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 5000,
                initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 1, controlTimeoutMilliseconds: 100)
            XCTAssertThrowsError(try submit(endpoint, fd: fd, configuration: configuration))
            XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
        }
    }

    func testCancellationDuringBusyWaitNeverResubmits() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.authorityStarting)])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var cancelled = false
        XCTAssertThrowsError(try submit(endpoint, fd: fd, cancellation: { if cancelled { throw Cancelled.stopped } },
            wait: { _, check in cancelled = true; try check() })) { XCTAssertTrue($0 is Cancelled) }
        XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
    }

    func testUnavailableEndpointWaitsBeforeExposureAndUsesTheSameDeadline() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [.result(.uncertain(.admissionRejected))])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var calls = 0, statuses: [CommandCallerReadinessStatus] = []
        let result = try submit(endpoint, fd: fd, status: { statuses.append($0) }, lookup: {
            calls += 1
            if calls < 3 { throw CommandAuthorityEndpointError.unavailable }
            return endpoint.port
        })
        XCTAssertEqual(result.outcome, .uncertain(.admissionRejected)); XCTAssertEqual(calls, 3); XCTAssertEqual(statuses, [.connecting])
        XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        var now: UInt64 = 0
        let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 10, initialBackoffMilliseconds: 10)
        XCTAssertThrowsError(try submit(endpoint, fd: fd, configuration: configuration, clock: { now },
            wait: { delay, check in now += UInt64(delay); try check() }, lookup: { throw CommandAuthorityEndpointError.unavailable })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: nil))
        }
        try assertNoNextAttempt(endpoint)
    }

    func testClockJumpDuringStatusCallbackExpiresBeforeAnotherSubmission() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting)])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, status: { _ in now = 5000 }, clock: { now })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .updateWaiting))
        }
        XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
    }

    func testCancellationDuringNegotiationCannotMasqueradeAsTransportUnavailability() throws {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY)
        defer { _ = Darwin.close(fd) }
        var checkpoints = 0, lookups = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, cancellation: {
            checkpoints += 1
            if checkpoints == 4 { throw MachCommandCallerError.timeout }
        }, lookup: { lookups += 1; return endpoint.port })) {
            XCTAssertEqual($0 as? MachCommandCallerError, .timeout)
        }
        XCTAssertEqual(lookups, 1)
        let receiver = try MachCommandCallerReceiver(receivePort: endpoint.port, expression: expression(), userID: geteuid(),
            auditSessionID: nil, maxPayloadBytes: 8192)
        XCTAssertThrowsError(try receiver.receiveHello(timeoutMilliseconds: 1000)) {
            XCTAssertEqual($0 as? MachCommandCallerError, .malformed)
        }
        try assertNoNextAttempt(endpoint)
    }

    func testDeadlineAfterSendRemainsUncertainDespiteAnEarlierBusyReply() throws {
        let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), .lost])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, cancellation: {
            if server.submissions.withLock({ $0.count }) == 2 { now = 5000 }
        }, clock: { now })) { XCTAssertEqual($0 as? MachCommandCallerError, .timeout) }
        XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
    }

    func testFreshLookupCanReconnectToAReplacementEndpointAfterABusyReply() throws {
        let first = try Endpoint(), second = try Endpoint()
        let firstServer = try serve(first, replies: [busy(.updateInstalling)])
        let secondServer = try serve(second, replies: [.result(.uncertain(.admissionRejected))])
        let fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var lookups = 0
        XCTAssertEqual(try submit(first, fd: fd, lookup: {
            lookups += 1; return lookups == 1 ? first.port : second.port
        }).outcome, .uncertain(.admissionRejected))
        XCTAssertEqual(try firstServer.finish().count, 1); XCTAssertEqual(try secondServer.finish().count, 1)
        XCTAssertEqual(lookups, 2); try assertNoNextAttempt(first); try assertNoNextAttempt(second)
    }

    func testDeadlineDuringLookupAndBackwardClockCannotExposeTheInvocation() throws {
        let endpoint = try Endpoint(), fd = Darwin.open("/dev/null", O_RDONLY); defer { _ = Darwin.close(fd) }
        var now: UInt64 = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, clock: { now }, lookup: { now = 5000; return endpoint.port })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: nil))
        }
        try assertNoNextAttempt(endpoint)
        var reads = 0
        XCTAssertThrowsError(try submit(endpoint, fd: fd, clock: { reads += 1; return reads == 1 ? 10 : 9 })) {
            XCTAssertEqual($0 as? CommandCallerReadinessError, .clockMovedBackwards)
        }
        try assertNoNextAttempt(endpoint)
    }

    func testPublicEntryRequiresRootPolicyBeforeEndpointOrInputUse() throws {
        let policy = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.sebastiano.remozio.macos.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: geteuid())
        XCTAssertThrowsError(try CommandCallerReadiness.submit(template(), inputDescriptor: -1,
            authorityPort: { XCTFail("Must not look up an authority"); return 0 }, authorityPolicy: policy,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: .init(timeoutMilliseconds: 5000))) { XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidConfiguration) }
    }
}


extension CommandCallerReadinessTests {
    private func submitIO(_ endpoint: Endpoint, input: Int32, output: Int32,
                          configuration: CommandCallerReadinessConfiguration? = nil,
                          cancellation: () throws -> Void = {}, status: (CommandCallerReadinessStatus) -> Void = { _ in },
                          clock: (() throws -> UInt64)? = nil,
                          wait: ((UInt32, () throws -> Void) throws -> Void)? = nil) throws -> sending CommandIOAdmission {
        try CommandCallerReadiness.submitIO(template(), inputDescriptor: input, outputDescriptor: output, errorDescriptor: output,
            authorityPort: { endpoint.port }, expression: expression(), userID: geteuid(), auditSessionID: nil,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: configuration ?? .init(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1,
                maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 1000),
            checkCancellation: cancellation, onStatus: status, clock: clock, wait: wait)
    }
    func testIOPipeControlsExplicitNegotiationKeepsBusyRetriesAndUnconsumedInput() throws {
        let endpoint = try Endpoint()
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.notAdmitted(.policyRejected, .never))],
                               io: true, capabilities: .pipeExecutionControls)
        var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
        let output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { for fd in input + [output] { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "queued", 6), 6)
        let original = try template()
        let result = try CommandCallerReadiness.submitIO(original, inputDescriptor: input[0], outputDescriptor: output, errorDescriptor: output,
            authorityPort: { endpoint.port }, expression: expression(), userID: geteuid(), auditSessionID: nil,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: .init(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 4),
            capabilities: .pipeExecutionControls)
        guard case .result(let verified) = result else { return XCTFail("A policy refusal admits no request") }
        XCTAssertEqual(verified.profile.wireVersion, 5); XCTAssertEqual(verified.retryClass, .never)
        let attempts = try server.finish()
        XCTAssertEqual(attempts.count, 5); XCTAssertEqual(Set(attempts.map(\.binding.id)).count, 5)
        XCTAssertEqual(Set(attempts.map(\.binding.nonce)).count, 5); XCTAssertEqual(Set(attempts.map(\.binding.callerBinding)).count, 5)
        for attempt in attempts { XCTAssertEqual(attempt.arguments, original.arguments); XCTAssertEqual(attempt.ioMode, .pipes) }
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(input[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
        try assertNoNextAttempt(endpoint)
    }
    func testIOReadinessRetriesFourBoundBusyClassesAndRetainsActualTerminalSession() throws {
        let endpoint = try Endpoint(), request = CommandAdmittedRequest(requestID: Data(repeating: 4, count: 16),
            requestDigest: Data(repeating: 5, count: 32), challenge: Data(repeating: 6, count: 32))
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.admitted(request))], io: true)
        var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
        let output = Darwin.open("/dev/null", O_WRONLY | O_CLOEXEC)
        defer { for fd in input + [output] { _ = Darwin.close(fd) } }
        XCTAssertEqual(Darwin.write(input[1], "queued", 6), 6)
        let inputFlags = fcntl(input[0], F_GETFL), outputFlags = fcntl(output, F_GETFL)
        var statuses: [CommandCallerReadinessStatus] = [], delays: [UInt32] = []
        let result = try submitIO(endpoint, input: input[0], output: output, status: { statuses.append($0) }, wait: { delay, check in
            delays.append(delay); try check()
        })
        guard case .admitted(let session) = result else { return XCTFail("Admission must keep its terminal session") }
        defer { session.close() }
        let submissions = try server.finish(), original = try template()
        XCTAssertEqual(submissions.count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.id)).count, 5); XCTAssertEqual(Set(submissions.map(\.binding.nonce)).count, 5)
        XCTAssertEqual(Set(submissions.map(\.binding.callerBinding)).count, 5)
        for submission in submissions {
            XCTAssertEqual(submission.arguments, original.arguments); XCTAssertEqual(submission.environmentAdditions, original.environmentAdditions)
            XCTAssertEqual(submission.executablePath, original.executablePath); XCTAssertEqual(submission.directoryPath, original.directoryPath)
            XCTAssertEqual(submission.requestedTargetUID, original.requestedTargetUID); XCTAssertEqual(submission.ioMode, original.ioMode)
            XCTAssertEqual(submission.disconnectBehavior, original.disconnectBehavior); XCTAssertEqual(submission.unverifiedRationale, original.unverifiedRationale)
            XCTAssertNotEqual(submission.binding.id, original.binding.id); XCTAssertNotEqual(submission.binding.nonce, original.binding.nonce)
        }
        let terminal = try XCTUnwrap(session.pollTerminalResult(timeoutMilliseconds: 1000))
        XCTAssertEqual(terminal.outcome, .exited(13)); XCTAssertEqual(terminal.request, request)
        XCTAssertEqual(terminal.submission, submissions.last?.binding)
        XCTAssertEqual(statuses, reasons.map(CommandCallerReadinessStatus.waiting)); XCTAssertEqual(delays, [1, 2, 4, 4])
        XCTAssertEqual(fcntl(input[0], F_GETFL), inputFlags); XCTAssertEqual(fcntl(output, F_GETFL), outputFlags)
        var bytes = [UInt8](repeating: 0, count: 6)
        XCTAssertEqual(Darwin.read(input[0], &bytes, 6), 6); XCTAssertEqual(Data(bytes), Data("queued".utf8))
        try assertNoNextAttempt(endpoint)
    }
    func testIOReadinessNeverRetriesPermanentOrUncertainOrInvalidReplies() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        for reply: Reply in [.result(.notAdmitted(.policyRejected, .never)), .result(.uncertain(.storageFailure)), .malformed, .wrongDigest, .lost] {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [reply], io: true)
            let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1,
                maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 100)
            switch reply {
            case .result(let expected):
                guard case .result(let result) = try submitIO(endpoint, input: input, output: output, configuration: configuration) else {
                    return XCTFail("Only admission can retain a session")
                }
                XCTAssertEqual(result.outcome, expected)
            default: XCTAssertThrowsError(try submitIO(endpoint, input: input, output: output, configuration: configuration))
            }
            XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        }
    }
    func testIOReadinessKeepsOneDeadlineAcrossReasonChangesAndCancellation() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = Darwin.open("/dev/null", O_WRONLY)
        defer { _ = Darwin.close(input); _ = Darwin.close(output) }
        do {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), busy(.storageUnavailable)], io: true)
            var now: UInt64 = 1000
            let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 3000, initialBackoffMilliseconds: 1000,
                maximumBackoffMilliseconds: 2000, controlTimeoutMilliseconds: 1000)
            XCTAssertThrowsError(try submitIO(endpoint, input: input, output: output, configuration: configuration,
                clock: { now }, wait: { delay, check in now += UInt64(delay); try check() })) {
                XCTAssertEqual($0 as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .storageUnavailable))
            }
            XCTAssertEqual(now, 4000)
            XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
        }
        do {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting)], io: true)
            var cancelled = false
            XCTAssertThrowsError(try submitIO(endpoint, input: input, output: output,
                cancellation: { if cancelled { throw Cancelled.stopped } }, status: { _ in cancelled = true })) {
                XCTAssertTrue($0 is Cancelled)
            }
            XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
        }
    }
}


extension CommandCallerReadinessTests {
    private struct DescriptorSnapshot: Equatable, Sendable {
        let device: dev_t, inode: ino_t, mode: mode_t, terminalDevice: dev_t
        let flags: Int32
        let attributes: Data?
    }
    private static func snapshot(_ fd: Int32) throws -> DescriptorSnapshot {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw RetainedCommandInputError.system(errno) }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0 else { throw RetainedCommandInputError.system(errno) }
        var attributes: Data?
        if isatty(fd) == 1 {
            var value = termios()
            guard tcgetattr(fd, &value) == 0 else { throw RetainedCommandInputError.system(errno) }
            attributes = withUnsafeBytes(of: value) { Data($0) }
        }
        return .init(device: info.st_dev, inode: info.st_ino, mode: info.st_mode,
            terminalDevice: info.st_rdev, flags: flags, attributes: attributes)
    }
    private func privateOutput() throws -> Int32 {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-readiness-" + UUID().uuidString).path
        let descriptor = Darwin.open(path, O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw RetainedCommandOutputError.system(errno) }
        _ = unlink(path)
        return descriptor
    }
    private func mapped(_ endpoint: Endpoint, mode: CommandIOMode, input: Int32, output: Int32, error: Int32,
                        control: Int32? = nil, configuration: CommandCallerReadinessConfiguration? = nil,
                        cancellation: () throws -> Void = {}, status: (CommandCallerReadinessStatus) -> Void = { _ in },
                        clock: (() throws -> UInt64)? = nil,
                        wait: ((UInt32, () throws -> Void) throws -> Void)? = nil) throws -> sending CommandIOAdmission {
        try CommandCallerReadiness.submitMappedIO(template(ioMode: mode), inputDescriptor: input, outputDescriptor: output, errorDescriptor: error,
            controlTerminalDescriptor: control, authorityPort: { endpoint.port }, expression: expression(), userID: geteuid(), auditSessionID: nil,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: configuration ?? .init(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1,
                maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 1000),
            checkCancellation: cancellation, onStatus: status, clock: clock, wait: wait)
    }
    private func mappedCapabilities(_ mode: CommandIOMode) -> CommandHandshakeCapabilities {
        mode == .pty ? .mappedTerminalJobExecution : .mappedPipeJobExecutionControls
    }

    func testMappedReadinessRetainsEverySourceAcrossAllBusyClassesAndTheAdmittedChannel() throws {
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let request = CommandAdmittedRequest(requestID: Data(repeating: 4, count: 16),
            requestDigest: Data(repeating: 5, count: 32), challenge: Data(repeating: 6, count: 32))
        let mixed = try CommandHandshakeCapabilities(wireVersions: [8, 9], submissionSchemaVersions: [1], inputCarrierVersions: [5])
        for mode: CommandIOMode in [.pty, .pipes] {
            for hasTerminal in [false, true] {
                let terminal = try RetainedCommandPTY()
                defer { terminal.close() }
                try terminal.withBorrowedSlave { terminalDescriptor in
                    let control: Int32? = hasTerminal ? terminalDescriptor : nil
                    let endpoint = try Endpoint(), output = try privateOutput(), error = try privateOutput()
                    var input: [Int32] = [-1, -1]; XCTAssertEqual(pipe(&input), 0)
                    defer { for fd in input + [output, error] { _ = Darwin.close(fd) } }
                    let data = Data([0, 0xff, 0x0a, 0x0d, 0x80, 0x41])
                    XCTAssertEqual(data.withUnsafeBytes { Darwin.write(input[1], $0.baseAddress, $0.count) }, data.count)
                    let descriptors = [input[0], output, error] + (control.map { [$0] } ?? [])
                    let expected = try descriptors.map(Self.snapshot), descriptorFlags = descriptors.map { fcntl($0, F_GETFD) }
                    let observations = OSAllocatedUnfairLock(initialState: [[DescriptorSnapshot]]())
                    let wire: UInt64 = mode == .pty ? 8 : 9
                    let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.admitted(request))], io: true, mapped: true,
                        capabilities: mixed, terminalOutcome: .cancelledBeforeStart, inspect: { receipt, profile in
                            XCTAssertEqual(profile.wireVersion, wire); XCTAssertEqual(profile.inputCarrierVersion, 5)
                            XCTAssertEqual(receipt.carrierVersion, 5)
                            let outputs = try XCTUnwrap(receipt.outputs)
                            var values = [try receipt.input.withBorrowedDescriptor(Self.snapshot),
                                try outputs.output.withBorrowedDescriptor(Self.snapshot), try outputs.error.withBorrowedDescriptor(Self.snapshot)]
                            if let terminal = receipt.controlTerminal { values.append(try terminal.withBorrowedDescriptor(Self.snapshot)) }
                            observations.withLock { [values] in $0.append(values) }
                        })
                    var statuses: [CommandCallerReadinessStatus] = [], delays: [UInt32] = []
                    let admission = try mapped(endpoint, mode: mode, input: input[0], output: output, error: error, control: control,
                        status: { statuses.append($0) }, wait: { delay, check in delays.append(delay); try check() })
                    guard case .admitted(let session) = admission else { return XCTFail("Expected the original admitted channel") }
                    defer { session.close() }
                    let attempts = try server.finish(), original = try template(ioMode: mode)
                    XCTAssertEqual(attempts.count, 5)
                    XCTAssertEqual(Set(attempts.map(\.binding.id)).count, 5)
                    XCTAssertEqual(Set(attempts.map(\.binding.nonce)).count, 5)
                    XCTAssertEqual(Set(attempts.map(\.binding.callerBinding)).count, 5)
                    for attempt in attempts {
                        XCTAssertEqual(attempt.executablePath, original.executablePath); XCTAssertEqual(attempt.arguments, original.arguments)
                        XCTAssertEqual(attempt.directoryPath, original.directoryPath); XCTAssertEqual(attempt.requestedTargetUID, original.requestedTargetUID)
                        XCTAssertEqual(attempt.environmentAdditions, original.environmentAdditions); XCTAssertEqual(attempt.ioMode, mode)
                        XCTAssertEqual(attempt.disconnectBehavior, original.disconnectBehavior); XCTAssertEqual(attempt.unverifiedRationale, original.unverifiedRationale)
                    }
                    let receipts = observations.withLock { $0 }
                    XCTAssertEqual(receipts.count, 5)
                    for receipt in receipts { XCTAssertEqual(receipt, expected) }
                    guard case .terminal(let result)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else {
                        return XCTFail("Expected the verified before-start terminal result")
                    }
                    XCTAssertEqual(result.outcome, .cancelledBeforeStart); XCTAssertEqual(result.request, request)
                    XCTAssertEqual(result.submission, attempts.last?.binding)
                    XCTAssertEqual(statuses, reasons.map(CommandCallerReadinessStatus.waiting)); XCTAssertEqual(delays, [1, 2, 4, 4])
                    XCTAssertEqual(try descriptors.map(Self.snapshot), expected)
                    XCTAssertEqual(descriptors.map { fcntl($0, F_GETFD) }, descriptorFlags)
                    XCTAssertEqual(lseek(output, 0, SEEK_CUR), 0); XCTAssertEqual(lseek(error, 0, SEEK_CUR), 0)
                    var bytes = Data(count: data.count)
                    XCTAssertEqual(bytes.withUnsafeMutableBytes { Darwin.read(input[0], $0.baseAddress, $0.count) }, data.count)
                    XCTAssertEqual(bytes, data); try assertNoNextAttempt(endpoint)
                }
            }
        }
    }

    func testMappedReadinessNeverRetriesPermanentUncertainOrInvalidReplies() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = try privateOutput(), error = try privateOutput()
        defer { for fd in [input, output, error] { _ = Darwin.close(fd) } }
        for mode: CommandIOMode in [.pty, .pipes] {
            for reply: Reply in [.result(.notAdmitted(.policyRejected, .never)), .result(.uncertain(.storageFailure)), .malformed, .wrongDigest, .lost] {
                let endpoint = try Endpoint(), server = try serve(endpoint, replies: [reply], io: true, mapped: true, capabilities: mappedCapabilities(mode))
                let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1,
                    maximumBackoffMilliseconds: 4, controlTimeoutMilliseconds: 100)
                switch reply {
                case .result(let expected):
                    guard case .result(let result) = try mapped(endpoint, mode: mode, input: input, output: output, error: error,
                        configuration: configuration) else { return XCTFail("Only admission can retain a session") }
                    XCTAssertEqual(result.outcome, expected)
                default:
                    do {
                        let result = try mapped(endpoint, mode: mode, input: input, output: output, error: error, configuration: configuration)
                        if case .admitted(let session) = result { session.close() }
                        XCTFail("Invalid or lost replies must throw")
                    } catch { }
                }
                XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
            }
        }
    }

    func testMappedReadinessSharesTheDeadlineAndCancellationAcrossBusyReplies() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = try privateOutput(), error = try privateOutput()
        defer { for fd in [input, output, error] { _ = Darwin.close(fd) } }
        for mode: CommandIOMode in [.pty, .pipes] {
            do {
                let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateInstalling), busy(.storageUnavailable)],
                    io: true, mapped: true, capabilities: mappedCapabilities(mode))
                var now: UInt64 = 1000
                let configuration = try CommandCallerReadinessConfiguration(timeoutMilliseconds: 3000, initialBackoffMilliseconds: 1000,
                    maximumBackoffMilliseconds: 2000, controlTimeoutMilliseconds: 1000)
                do {
                    let result = try mapped(endpoint, mode: mode, input: input, output: output, error: error, configuration: configuration,
                        clock: { now }, wait: { delay, check in now += UInt64(delay); try check() })
                    if case .admitted(let session) = result { session.close() }
                    XCTFail("Reason changes must not reset the deadline")
                } catch { XCTAssertEqual(error as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: .storageUnavailable)) }
                XCTAssertEqual(now, 4000)
                XCTAssertEqual(try server.finish().count, 2); try assertNoNextAttempt(endpoint)
            }
            do {
                let endpoint = try Endpoint(), server = try serve(endpoint, replies: [busy(.updateWaiting)], io: true, mapped: true,
                    capabilities: mappedCapabilities(mode))
                var cancelled = false
                do {
                    let result = try mapped(endpoint, mode: mode, input: input, output: output, error: error,
                        cancellation: { if cancelled { throw Cancelled.stopped } }, status: { _ in cancelled = true })
                    if case .admitted(let session) = result { session.close() }
                    XCTFail("Cancellation must stop the busy retry")
                } catch { XCTAssertTrue(error is Cancelled) }
                XCTAssertEqual(try server.finish().count, 1); try assertNoNextAttempt(endpoint)
            }
        }
    }

    func testMappedReadinessDoesNotFallbackToALegacyPeer() throws {
        let input = Darwin.open("/dev/null", O_RDONLY), output = try privateOutput(), error = try privateOutput()
        defer { for fd in [input, output, error] { _ = Darwin.close(fd) } }
        for mode: CommandIOMode in [.pty, .pipes] {
            let endpoint = try Endpoint(), server = try serve(endpoint, replies: [.lost], io: true, capabilities: .executionChannels)
            do {
                let result = try mapped(endpoint, mode: mode, input: input, output: output, error: error)
                if case .admitted(let session) = result { session.close() }
                XCTFail("An incompatible peer must not receive the invocation")
            } catch { XCTAssertEqual(error as? MachCommandHandshakeError, .incompatible) }
            XCTAssertEqual(server.completed.wait(timeout: .now() + 5), .success)
            XCTAssertThrowsError(try server.results.withLock { try XCTUnwrap($0).get() }) {
                XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
            }
            XCTAssertTrue(server.submissions.withLock { $0.isEmpty }); try assertNoNextAttempt(endpoint)
        }
    }

    func testMappedPublicReadinessRequiresRootPolicyBeforeAnyEndpointOrDescriptorUse() throws {
        let policy = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.sebastiano.remozio.macos.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: geteuid())
        do {
            let result = try CommandCallerReadiness.submitMappedIO(template(), inputDescriptor: -1, outputDescriptor: -1, errorDescriptor: -1,
                controlTerminalDescriptor: -1, authorityPort: { XCTFail("Must not look up an authority"); return 0 }, authorityPolicy: policy,
                macID: mac, accountID: account, submissionLimits: limits(), configuration: .init(timeoutMilliseconds: 5000))
            if case .admitted(let session) = result { session.close() }
            XCTFail("A non-root policy must be rejected")
        } catch { XCTAssertEqual(error as? MachCommandHandshakeError, .invalidConfiguration) }
    }

    func testMappedRefreshUsesEachAttemptPolicyAndRetainsTheAdmittedPolicy() throws {
        let endpoint = try Endpoint(), input = Darwin.open("/dev/null", O_RDONLY), output = try privateOutput()
        defer { for fd in [input, output] { _ = Darwin.close(fd) } }
        let reasons: [CommandAdmissionRejectionReason] = [.updateInstalling, .authorityStarting, .updateWaiting, .storageUnavailable]
        let request = CommandAdmittedRequest(requestID: Data(repeating: 4, count: 16),
            requestDigest: Data(repeating: 5, count: 32), challenge: Data(repeating: 6, count: 32))
        let server = try serve(endpoint, replies: reasons.map(busy) + [.result(.admitted(request))], io: true, mapped: true,
            capabilities: .mappedPipeJobExecutionControls, terminalOutcome: .cancelledBeforeStart)
        let actual = try expression()
        var refreshes = 0, lookups = 0, policyRetired = false
        let response = try CommandCallerReadiness.submitMappedIO(template(), inputDescriptor: input, outputDescriptor: output,
            errorDescriptor: output, controlTerminalDescriptor: nil, authorityPort: {
                lookups += 1; XCTAssertEqual(refreshes, lookups); return endpoint.port
            }, expression: "cdhash H\"0000000000000000000000000000000000000000\"", userID: geteuid(), auditSessionID: nil,
            macID: mac, accountID: account, submissionLimits: limits(),
            configuration: .init(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1, maximumBackoffMilliseconds: 4),
            wait: { _, check in try check() }, refreshAuthorityRequirement: {
                guard !policyRetired else { throw Cancelled.stopped }
                refreshes += 1
                // Different valid requirements prove each attempt uses its provider, rather than the invalid fixed fallback.
                return .init(expression: "(\(actual)) or cdhash H\"" + String(repeating: String(refreshes), count: 40) + "\"",
                    userID: geteuid(), auditSessionID: nil)
            })
        guard case .admitted(let session) = response else { return XCTFail("Expected the admitted channel") }
        defer { session.close() }
        policyRetired = true
        XCTAssertEqual(try server.finish().count, 5); XCTAssertEqual(refreshes, 5); XCTAssertEqual(lookups, 5)
        guard case .terminal(let result)? = try session.pollStreamEvent(timeoutMilliseconds: 1000) else {
            return XCTFail("The original policy must validate the terminal result")
        }
        XCTAssertEqual(result.outcome, .cancelledBeforeStart); XCTAssertEqual(result.request, request)
        XCTAssertEqual(refreshes, 5); try assertNoNextAttempt(endpoint)
    }

    func testMappedRefreshFailureAfterBusyNeverBecomesUnavailableRetry() throws {
        let endpoint = try Endpoint(), input = Darwin.open("/dev/null", O_RDONLY), output = try privateOutput()
        defer { for fd in [input, output] { _ = Darwin.close(fd) } }
        let server = try serve(endpoint, replies: [busy(.updateInstalling)], io: true, mapped: true,
            capabilities: .mappedPipeJobExecutionControls)
        let actual = try expression()
        var refreshes = 0, lookups = 0
        do {
            let response = try CommandCallerReadiness.submitMappedIO(template(), inputDescriptor: input, outputDescriptor: output,
                errorDescriptor: output, controlTerminalDescriptor: nil, authorityPort: { lookups += 1; return endpoint.port },
                expression: actual, userID: geteuid(), auditSessionID: nil, macID: mac, accountID: account, submissionLimits: limits(),
                configuration: .init(timeoutMilliseconds: 5000, initialBackoffMilliseconds: 1),
                wait: { _, check in try check() }, refreshAuthorityRequirement: {
                    refreshes += 1
                    if refreshes > 1 { throw CommandAuthorityEndpointError.unavailable }
                    return .init(expression: actual, userID: geteuid(), auditSessionID: nil)
                })
            if case .admitted(let session) = response { session.close() }
            XCTFail("A failed provider must stop before another lookup")
        } catch { XCTAssertTrue(error is CommandAuthorityEndpointError) }
        XCTAssertEqual(try server.finish().count, 1); XCTAssertEqual(refreshes, 2); XCTAssertEqual(lookups, 1)
        try assertNoNextAttempt(endpoint)
    }

    func testMappedRefreshKeepsTheOriginalDeadlineAndRootGuard() throws {
        let endpoint = try Endpoint()
        var clock: UInt64 = 0, refreshes = 0
        do {
            let response = try CommandCallerReadiness.submitMappedIO(template(), inputDescriptor: -1, outputDescriptor: -1,
                errorDescriptor: -1, controlTerminalDescriptor: nil,
                authorityPort: { XCTFail("The deadline must be checked before lookup"); return endpoint.port },
                expression: expression(), userID: geteuid(), auditSessionID: nil, macID: mac, accountID: account,
                submissionLimits: limits(), configuration: .init(timeoutMilliseconds: 10), clock: { clock },
                refreshAuthorityRequirement: {
                    refreshes += 1; clock = 10
                    return .init(expression: "false", userID: geteuid(), auditSessionID: nil)
                })
            if case .admitted(let session) = response { session.close() }; XCTFail("Refresh must not reset the deadline")
        } catch { XCTAssertEqual(error as? CommandCallerReadinessError, .deadlineExceeded(lastBusyReason: nil)) }
        XCTAssertEqual(refreshes, 1); try assertNoNextAttempt(endpoint)
        let root = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.sebastiano.remozio.macos.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: 0)
        let user = try XPCPeerPolicy(teamID: "AB12345678", componentIdentifier: "dev.sebastiano.remozio.macos.authority",
            approvedCodeDirectoryHashes: [Data(repeating: 0, count: 20)], expectedUserID: geteuid())
        do {
            let response = try CommandCallerReadiness.submitMappedIO(template(), inputDescriptor: -1, outputDescriptor: -1,
                errorDescriptor: -1, controlTerminalDescriptor: nil,
                authorityPort: { XCTFail("A refreshed non-root policy must not be used"); return endpoint.port },
                authorityPolicy: root, macID: mac, accountID: account, submissionLimits: limits(),
                configuration: .init(timeoutMilliseconds: 5000), refreshAuthorityPolicy: { user })
            if case .admitted(let session) = response { session.close() }; XCTFail("Every refreshed policy must require Root")
        } catch { XCTAssertEqual(error as? MachCommandHandshakeError, .invalidConfiguration) }
        try assertNoNextAttempt(endpoint)
    }
}
