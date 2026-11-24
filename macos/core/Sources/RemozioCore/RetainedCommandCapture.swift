import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum RetainedCommandCaptureError: Error, Equatable { case binding, invalidContext, closed, alreadyOwned }

/// Owns the original caller, input, and filesystem observations for one command request. This grants no execution authority.
/// Construction takes ownership on success and failure. The request owner must serialize access and must not reuse the received submission.
public final class RetainedCommandCapture {
    public let capture: CommandCapture
    private let caller: RetainedCommandCaller
    private let input: RetainedCommandInputDescriptor
    private let controlTerminal: RetainedCommandInputDescriptor?
    private let stdioObservation: RetainedCommandStdioObservation?
    private let filesystem: CommandFilesystemCapture
    func makeFilesystemRecheck() throws -> CommandFilesystemCapture.Recheck {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        return try filesystem.makeRecheck()
    }
    let outputs: RetainedCommandOutputChannels?
    let admissionProfile: CommandHandshakeProfile?
    let submissionDigest: Data
    private var admissionReply: MachCommandReplyRight?
    private var closed = false
    private var requestOwned = false

    /// Supply target credentials and the minimal environment from protected policy and OS resolution.
    /// The expected caller binding comes from the authenticated channel; the authority creates the stream binding.
    public convenience init(received: sending ReceivedMachCommandInputSubmission, expectedCallerBinding: Data,
                            submissionSchemaVersion: UInt64, captureSchemaVersion: UInt64, currentPolicy: XPCPeerPolicy,
                            resolvedTarget: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data,
                            submissionLimits: CBORLimits, captureLimits: CBORLimits, maximumAncestryEntries: Int = 16,
                            checkCancellation: @Sendable () throws -> Void = {}) throws {
        try self.init(received: received, expectedCallerBinding: expectedCallerBinding, submissionSchemaVersion: submissionSchemaVersion,
            captureSchemaVersion: captureSchemaVersion, expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, resolvedTarget: resolvedTarget, minimalEnvironment: minimalEnvironment,
            streamBinding: streamBinding, submissionLimits: submissionLimits, captureLimits: captureLimits,
            maximumAncestryEntries: maximumAncestryEntries, checkCancellation: checkCancellation)
    }

    convenience init(received: sending ReceivedMachCommandInputSubmission, expectedCallerBinding: Data, submissionSchemaVersion: UInt64,
         captureSchemaVersion: UInt64, expression: String, userID: uid_t, auditSessionID: au_asid_t?, resolvedTarget: CommandTarget,
         minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits,
         maximumAncestryEntries: Int = 16, checkCancellation: @Sendable () throws -> Void = {},
         admissionProfile: CommandHandshakeProfile? = nil) throws {
        try self.init(ownedReceived: received, expectedCallerBinding: expectedCallerBinding,
            submissionSchemaVersion: submissionSchemaVersion, captureSchemaVersion: captureSchemaVersion,
            expression: expression, userID: userID, auditSessionID: auditSessionID, resolvedTarget: resolvedTarget,
            minimalEnvironment: minimalEnvironment, streamBinding: streamBinding, submissionLimits: submissionLimits,
            captureLimits: captureLimits, maximumAncestryEntries: maximumAncestryEntries,
            checkCancellation: checkCancellation, admissionProfile: admissionProfile)
    }

    /// Internal capture from an exclusively owned attempt. Public entry points retain their sending transfer.
    init(ownedReceived received: ReceivedMachCommandInputSubmission, expectedCallerBinding: Data, submissionSchemaVersion: UInt64,
         captureSchemaVersion: UInt64, expression: String, userID: uid_t, auditSessionID: au_asid_t?, resolvedTarget: CommandTarget,
         minimalEnvironment: [CapturedEnvironmentEntry], streamBinding: Data, submissionLimits: CBORLimits, captureLimits: CBORLimits,
         maximumAncestryEntries: Int = 16, checkCancellation: @Sendable () throws -> Void = {},
         admissionProfile: CommandHandshakeProfile? = nil, capturedFilesystem: CommandFilesystemCapture? = nil) throws {
        try received.claimForCaptureOwner()
        var heldFilesystem: CommandFilesystemCapture?
        do {
            try checkCancellation()
            try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            let submission = try CommandSubmission(canonicalBytes: received.payload, limits: submissionLimits,
                expectedSchemaVersion: submissionSchemaVersion)
            guard expectedCallerBinding.count == 16, submission.binding.callerBinding == expectedCallerBinding else {
                throw RetainedCommandCaptureError.binding
            }
            guard resolvedTarget.uid == submission.requestedTargetUID else { throw RetainedCommandCaptureError.invalidContext }
            if let admissionProfile, admissionProfile.supportsMappedLayout {
                guard captureSchemaVersion == 3,
                      submission.ioMode == (admissionProfile.supportsStreamingExecution ? .pty : .pipes) else {
                    throw RetainedCommandCaptureError.invalidContext
                }
            }
            let environment = try Self.environment(minimal: minimalEnvironment, additions: submission.environmentAdditions)
            let filesystem = try capturedFilesystem ?? CommandFilesystemCapture(executablePath: submission.executablePath,
                directoryPath: submission.directoryPath, checkCancellation: checkCancellation)
            heldFilesystem = filesystem
            guard filesystem.executable.path == submission.executablePath, filesystem.directory.path == submission.directoryPath else {
                throw RetainedCommandCaptureError.binding
            }
            let stdioObservation: RetainedCommandStdioObservation?
            let source: CapturedCommandInput
            let requester: CapturedRequester
            if captureSchemaVersion == 3 {
                let context = try received.caller.captureTerminalContext(expression: expression, userID: userID, auditSessionID: auditSessionID)
                let observation = try RetainedCommandStdioObservation(received: received, context: context,
                    mode: submission.ioMode, inputBinding: streamBinding)
                stdioObservation = observation; source = observation.layout.input.source
                let original = received.caller.requester
                requester = CapturedRequester(executablePath: original.executablePath, realUID: original.realUID,
                    effectiveUID: original.effectiveUID, pid: original.pid, pidVersion: original.pidVersion, signing: original.signing,
                    sessionID: UInt32(context.sessionID), ttyPath: observation.layout.terminal?.stream.source.observedPath)
            } else {
                guard received.carrierVersion != MachCommandCallerReceiver.mappedIOInputCarrierVersion else {
                    throw RetainedCommandCaptureError.invalidContext
                }
                stdioObservation = nil; source = try received.input.capture(streamBinding: streamBinding)
                requester = received.caller.requester
            }
            let ancestry = try received.caller.captureAncestry(expression: expression, userID: userID,
                auditSessionID: auditSessionID, maximumEntries: maximumAncestryEntries, checkCancellation: checkCancellation)
            let capture = try CommandCapture(schemaVersion: captureSchemaVersion, executable: filesystem.executable,
                arguments: submission.arguments, directory: filesystem.directory, target: resolvedTarget, environment: environment,
                input: source, ioMode: submission.ioMode, disconnectBehavior: submission.disconnectBehavior,
                requester: requester, ancestry: ancestry, unverifiedRationale: submission.unverifiedRationale,
                submission: submission.binding, stdioLayout: stdioObservation?.layout, limits: captureLimits)
            if capturedFilesystem == nil { try filesystem.recheck(checkCancellation: checkCancellation) }
            if let stdioObservation, let outputs = received.outputs {
                try stdioObservation.recheck(input: received.input, outputs: outputs, controlTerminal: received.controlTerminal)
                try received.caller.recheckTerminalContext(stdioObservation.context, expression: expression, userID: userID, auditSessionID: auditSessionID)
            }
            try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            self.outputs = received.outputs; self.controlTerminal = received.controlTerminal; self.stdioObservation = stdioObservation
            try received.outputs?.recheck()
            self.capture = capture; self.caller = received.caller; self.input = received.input; self.filesystem = filesystem
            if let admissionProfile {
                guard admissionProfile.callerBinding == submission.binding.callerBinding,
                      admissionProfile.submissionSchemaVersion == submission.schemaVersion,
                      admissionProfile.inputCarrierVersion == UInt64(received.carrierVersion) else {
                    throw RetainedCommandCaptureError.binding
                }
            }
            self.admissionProfile = admissionProfile; self.submissionDigest = Data(SHA256.hash(data: received.payload))
            self.admissionReply = received.reply
        } catch {
            heldFilesystem?.close(); received.caller.close(); received.input.close(); received.reply?.close(); received.outputs?.close(); received.controlTerminal?.close()
            throw error
        }
    }

    deinit { close() }

    /// A repeated transfer must not close resources already held by an admitted request.
    func claimForRequestOwner() throws {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        guard !requestOwned else { throw RetainedCommandCaptureError.alreadyOwned }
        requestOwned = true
    }

    /// Preflight may reject a first transfer before the coordinator can claim it.
    func closeIfUnclaimed() {
        if !requestOwned { close() }
    }

    /// Invoke after durable permit consumption and current elevation-policy validation, immediately before dispatch.
    public func recheck(currentPolicy: XPCPeerPolicy, checkCancellation: () throws -> Void = {}) throws {
        try recheck(expression: currentPolicy.requirement, userID: currentPolicy.expectedUserID,
            auditSessionID: currentPolicy.expectedAuditSessionID, checkCancellation: checkCancellation)
    }

    func recheck(expression: String, userID: uid_t, auditSessionID: au_asid_t?, checkCancellation: () throws -> Void = {},
                 filesystemChecked: Bool = false) throws {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        do {
            try checkCancellation()
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
            if !filesystemChecked { try filesystem.recheck(checkCancellation: checkCancellation) }
            try input.withBorrowedDescriptor { _ in () }
            try outputs?.recheck()
            if let stdioObservation, let outputs {
                try stdioObservation.recheck(input: input, outputs: outputs, controlTerminal: controlTerminal)
                try caller.recheckTerminalContext(stdioObservation.context, expression: expression, userID: userID, auditSessionID: auditSessionID)
            }
            try caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
        } catch { close(); throw error }
    }

    /// Borrow the original object only for this callback. Do not close, retain, or pass it to another thread.
    public func withBorrowedInputDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        return try input.withBorrowedDescriptor(body)
    }

    /// Borrow the retained working-directory object only for this callback, under the same ownership rules as input.
    public func withBorrowedDirectoryDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        return try filesystem.withBorrowedDirectoryDescriptor(body)
    }

    /// Only the serialized request controller may reply after transfer. The bytes convey no semantics by themselves.
    func sendAdmissionReply(_ bytes: Data, timeoutMilliseconds: UInt32 = 5000) throws {
        guard !closed, let admissionReply else { throw MachCommandHandshakeError.retired }
        try admissionReply.send(bytes, timeoutMilliseconds: timeoutMilliseconds)
    }

    /// Only the exclusive attempt owner supplies the original detached right after successful capture.
    func installAdmissionReply(_ reply: MachCommandReplyRight) throws {
        guard !closed, !requestOwned, admissionReply == nil, admissionProfile?.supportsAdmissionResults == true else {
            throw RetainedCommandCaptureError.alreadyOwned
        }
        admissionReply = reply
    }

    /// Detach only after the first request transfer. Recheck cleanup cannot close the attempt owner's reply.
    func takeAdmissionReply() throws -> MachCommandReplyRight? {
        guard requestOwned, !closed else { throw RetainedCommandCaptureError.closed }
        guard admissionProfile?.supportsAdmissionResults == true else { return nil }
        let reply = admissionReply
        admissionReply = nil
        return reply
    }

    /// Only the serialized owner supplies an outcome and identity from its retained request state.
    func sendTerminalOutcome(_ outcome: CommandTerminalOutcome, request: CommandAdmittedRequest) throws {
        guard !closed else { throw RetainedCommandCaptureError.closed }
        guard let outputs, let profile = admissionProfile, profile.supportsExecutionChannels else { return }
        let payload = CommandTerminalResultPayload(profile: profile, submission: capture.submission,
            submissionDigest: submissionDigest, request: request, outcome: outcome)
        try outputs.sendTerminalNonblocking(payload.canonicalBytes)
    }

    /// Transfer only from the serialized admitted request owner. This grants no dispatch permission.
    func takeExecutionResources(request: CommandAdmittedRequest) throws -> RetainedCommandExecutionResources {
        guard requestOwned, !closed, let outputs, let profile = admissionProfile,
              profile.supportsExecutionChannels else { throw RetainedCommandCaptureError.closed }
        let template = CommandTerminalResultPayload(profile: profile, submission: capture.submission,
            submissionDigest: submissionDigest, request: request, outcome: .unknown)
        _ = try template.canonicalBytes
        let terminal = try outputs.takeTerminalReply()
        closed = true
        admissionReply?.close(); admissionReply = nil
        return RetainedCommandExecutionResources(capture: capture, caller: caller, input: input, filesystem: filesystem,
            outputs: outputs, terminal: terminal, profile: profile, submissionDigest: submissionDigest, request: request,
            controlTerminal: controlTerminal, stdioObservation: stdioObservation)
    }

    public func close() {
        if !closed { filesystem.close(); outputs?.close(); caller.close(); input.close(); controlTerminal?.close(); admissionReply?.close(); closed = true }
    }

    private static func environment(minimal: [CapturedEnvironmentEntry], additions: [CommandEnvironmentAddition]) throws -> [CapturedEnvironmentEntry] {
        var values: [Data: CapturedEnvironmentEntry] = [:]
        for entry in minimal {
            guard entry.source == .minimal, !entry.name.isEmpty, !entry.name.contains(0), !entry.name.contains(0x3d),
                  !entry.value.contains(0), values[entry.name] == nil else { throw RetainedCommandCaptureError.invalidContext }
            values[entry.name] = entry
        }
        for entry in additions {
            values[entry.name] = CapturedEnvironmentEntry(name: entry.name, value: entry.value, source: .requested)
        }
        return values.values.sorted { $0.name.lexicographicallyPrecedes($1.name) }
    }
}
