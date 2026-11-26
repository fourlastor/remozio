import Darwin
import Foundation
import RemozioProtocol

/// Owns the original command resources inside the serialized Root controller. This grants no child release permission.
final class RetainedCommandExecutionResources {
    var resolvedExecutablePath: Data { filesystem.resolvedExecutablePath }
    let capture: CommandCapture
    let request: CommandAdmittedRequest
    private let caller: RetainedCommandCaller
    private let input: RetainedCommandInputDescriptor
    private let controlTerminal: RetainedCommandInputDescriptor?
    private let stdioObservation: RetainedCommandStdioObservation?
    private let filesystem: CommandFilesystemCapture
    private let outputs: RetainedCommandOutputChannels
    private let terminal: MachCommandReplyRight
    private let profile: CommandHandshakeProfile
    private let submissionDigest: Data
    private var executionRetired = false
    private var closed = false
    private var terminalAttempted = false
    private struct TerminalDelivery {
        let outcome: CommandTerminalOutcome
        let outputInterrupted: Bool
        let bytes: Data
    }
    private var pendingTerminalDelivery: TerminalDelivery?

    init(capture: CommandCapture, caller: RetainedCommandCaller, input: RetainedCommandInputDescriptor,
         filesystem: CommandFilesystemCapture, outputs: RetainedCommandOutputChannels, terminal: MachCommandReplyRight,
         profile: CommandHandshakeProfile, submissionDigest: Data, request: CommandAdmittedRequest,
         controlTerminal: RetainedCommandInputDescriptor? = nil, stdioObservation: RetainedCommandStdioObservation? = nil) {
        self.capture = capture; self.caller = caller; self.input = input; self.filesystem = filesystem
        self.outputs = outputs; self.terminal = terminal; self.profile = profile; self.controlTerminal = controlTerminal; self.stdioObservation = stdioObservation
        self.submissionDigest = submissionDigest; self.request = request
    }
    deinit { close() }
    var requiresMappedLayout: Bool { profile.supportsMappedLayout }
    var requiresStreamPump: Bool { profile.supportsStreamingExecution }
    var reportsJobState: Bool { profile.supportsJobState }
    var requiresPipeControls: Bool { profile.supportsPipeExecutionControls }
    func makeStreamAuthority() throws -> MachCommandStreamAuthority {
        guard profile.supportsExecutionControls, !closed, !executionRetired else { throw CommandExecutionError.unavailable }
        return try MachCommandStreamAuthority(binding: .init(profile: profile, submission: capture.submission,
            submissionDigest: submissionDigest, request: request), original: caller, terminal: terminal)
    }
    var requesterExitObserved: Bool { caller.requesterExitObserved }

    func recheck(currentPolicy: XPCPeerPolicy, checkCancellation: () throws -> Void = {}) throws {
        try recheck(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, checkCancellation: checkCancellation)
    }
    /// Internal fixture identity seam. Production requires the current protected caller policy.
    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?, checkCancellation: () throws -> Void = {},
                 filesystemChecked: Bool = false) throws {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        do {
            if requiresMappedLayout {
                guard capture.schemaVersion == 3, let stdioObservation, stdioObservation.layout == capture.stdioLayout,
                      capture.ioMode == (requiresStreamPump ? .pty : .pipes) else { throw RetainedCommandCaptureError.invalidContext }
            }
            try checkCancellation()
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            if !filesystemChecked { try filesystem.recheck(checkCancellation: checkCancellation) }
            try input.withBorrowedDescriptor { _ in () }
            try outputs.recheckStreams(); try terminal.recheck()
            if let stdioObservation {
                try stdioObservation.recheck(input: input, outputs: outputs, controlTerminal: controlTerminal)
                try caller.recheckTerminalContext(stdioObservation.context, expression: expression, userID: userID, auditSessionID: auditSessionID)
            }
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        } catch { retireExecutionResources(); throw error }
    }

    func makeFilesystemRecheck() throws -> CommandFilesystemCapture.Recheck {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        return try filesystem.makeRecheck(checkingLaunchPath: true)
    }
    func executableLaunch(from proof: CommandFilesystemCapture.MetadataProof) throws -> CommandExecutableLaunch {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        return try filesystem.executableLaunch(from: proof)
    }

    func verifyFilesystemMetadata(_ proof: CommandFilesystemCapture.MetadataProof) throws {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        try filesystem.verifyMetadata(proof)
    }

    /// Checks the original caller without treating executable changes as a running-command cancellation.
    func recheckCaller(expression: String, userID: uid_t, auditSessionID: au_asid_t?) throws {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
    }

    /// Borrow only during this serialized callback. Do not close or retain these descriptors.
    func withBorrowedDescriptors<Value>(_ body: (Int32, Int32, Int32, Int32) throws -> Value) throws -> Value {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        return try input.withBorrowedDescriptor { input in
            try outputs.output.withBorrowedDescriptor { output in
                try outputs.error.withBorrowedDescriptor { error in
                    try filesystem.withBorrowedDirectoryDescriptor { directory in
                        try body(input, output, error, directory)
                    }
                }
            }
        }
    }

    /// Borrow the original caller terminal only for reading preparation attributes, never for command stdio replacement.
    func withBorrowedCallerTerminal<Value>(_ body: (Int32?) throws -> Value) throws -> Value {
        guard !closed, !executionRetired else { throw RetainedCommandCaptureError.closed }
        if let controlTerminal { return try controlTerminal.withBorrowedDescriptor { try body($0) } }
        return try body(nil)
    }

    /// Only the trusted controller supplies an established result after the required durable transition.
    /// A failed private delivery consumes this attempt and cannot authorize another command.
    func sendTerminalOutcome(_ outcome: CommandTerminalOutcome, outputInterrupted: Bool = false) throws {
        guard !closed, !terminalAttempted, pendingTerminalDelivery == nil else { throw MachCommandHandshakeError.retired }
        let payload = CommandTerminalResultPayload(profile: profile, submission: capture.submission,
            submissionDigest: submissionDigest, request: request, outcome: outcome, outputInterrupted: outputInterrupted)
        let bytes = try payload.canonicalBytes
        terminalAttempted = true
        defer { terminal.close() }
        try terminal.sendTerminalNonblocking(bytes)
    }
    /// Retains one exact result across known zero-progress sends. It cannot retry execution or replace the retained outcome.
    func queueTerminalOutcome(_ outcome: CommandTerminalOutcome, outputInterrupted: Bool) throws -> Bool {
        guard !closed, !terminalAttempted else { throw MachCommandHandshakeError.retired }
        if pendingTerminalDelivery == nil {
            let payload = CommandTerminalResultPayload(profile: profile, submission: capture.submission,
                submissionDigest: submissionDigest, request: request, outcome: outcome, outputInterrupted: outputInterrupted)
            pendingTerminalDelivery = try TerminalDelivery(outcome: outcome, outputInterrupted: outputInterrupted, bytes: payload.canonicalBytes)
        }
        guard let delivery = pendingTerminalDelivery, delivery.outcome == outcome, delivery.outputInterrupted == outputInterrupted else {
            throw MachCommandHandshakeError.invalidConfiguration
        }
        do {
            guard try terminal.queueTerminalNonblocking(delivery.bytes) else { return false }
            terminalAttempted = true; pendingTerminalDelivery = nil
            return true
        } catch {
            terminalAttempted = true; pendingTerminalDelivery = nil; terminal.close()
            throw error
        }
    }
    func close() {
        guard !closed else { return }
        closed = true; pendingTerminalDelivery = nil; retireExecutionResources(); terminal.close()
    }
    private func retireExecutionResources() {
        guard !executionRetired else { return }
        executionRetired = true
        filesystem.close(); outputs.close(); caller.close(); input.close(); controlTerminal?.close()
    }
}
