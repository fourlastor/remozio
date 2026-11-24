import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum CommandAdmissionAttemptError: Error, Equatable { case closed, alreadyOwned }

/// Root-owned capture settings after current target and elevation-policy resolution. Incoming claims cannot authorize these values.
public struct CommandAdmissionCaptureContext: Sendable {
    public let schemaVersion: UInt64
    public let target: CommandTarget
    public let minimalEnvironment: [CapturedEnvironmentEntry]
    public let streamBinding: Data
    public let limits: CBORLimits
    public let maximumAncestryEntries: Int
    public init(schemaVersion: UInt64, target: CommandTarget, minimalEnvironment: [CapturedEnvironmentEntry],
                streamBinding: Data, limits: CBORLimits, maximumAncestryEntries: Int = 16) {
        self.schemaVersion = schemaVersion; self.target = target; self.minimalEnvironment = minimalEnvironment
        self.streamBinding = streamBinding; self.limits = limits; self.maximumAncestryEntries = maximumAncestryEntries
    }
}

/// The trusted host returns actual policy or lifecycle state. A refusal alone establishes no absence or retry proof.
public enum CommandAdmissionResolution: Sendable {
    case capture(CommandAdmissionCaptureContext)
    case refuse(CommandAdmissionRejectionReason)
}

/// Holds an authenticated submission's original input and private reply before capture. This grants no execution authority.
/// Only the current handshake can construct it. Transfer once to the serialized journal owner.
public final class RetainedCommandAdmissionAttempt {
    public let submission: CommandSubmission
    public let profile: CommandHandshakeProfile
    let userID: uid_t
    let filesystemCaller: CommandFilesystemCaller
    let auditSessionID: au_asid_t?
    private let submissionLimits: CBORLimits
    private let digest: Data
    private var received: ReceivedMachCommandInputSubmission?
    private var reply: MachCommandReplyRight?
    private var claimed = false
    private var closed = false

    init(received original: sending ReceivedMachCommandInputSubmission, profile: CommandHandshakeProfile,
         userID: uid_t, auditSessionID: au_asid_t?, submissionLimits: CBORLimits) throws {
        let (received, reply) = try original.takeForAdmissionAttempt()
        do {
            let submission = try CommandSubmission(canonicalBytes: received.payload, limits: submissionLimits,
                expectedSchemaVersion: profile.submissionSchemaVersion)
            guard profile.supportsAdmissionResults, submission.binding.callerBinding == profile.callerBinding,
                  UInt64(received.carrierVersion) == profile.inputCarrierVersion else { throw MachCommandHandshakeError.wrongBinding }
            self.submission = submission; self.profile = profile; self.digest = Data(SHA256.hash(data: received.payload))
            self.userID = userID; self.auditSessionID = auditSessionID; self.submissionLimits = submissionLimits
            self.filesystemCaller = received.caller.filesystemCaller
            self.received = received; self.reply = reply
        } catch { received.closeIfUnclaimed(); reply.close(); throw error }
    }

    deinit { close() }
    func claimForOwner() throws {
        guard !closed else { throw CommandAdmissionAttemptError.closed }
        guard !claimed else { throw CommandAdmissionAttemptError.alreadyOwned }
        claimed = true
    }
    func closeIfUnclaimed() { if !claimed { close() } }

    func recheck(expression: String) throws {
        guard claimed, !closed, let received else { throw CommandAdmissionAttemptError.closed }
        try received.caller.recheck(expression: expression, userID: userID, auditSessionID: auditSessionID)
    }

    func assemble(context: CommandAdmissionCaptureContext, expression: String, userID: uid_t,
                  auditSessionID: au_asid_t?, checkCancellation: @Sendable () throws -> Void,
                  capturedFilesystem: CommandFilesystemCapture? = nil) throws -> RetainedCommandCapture {
        guard claimed, !closed, let received, let reply else { throw CommandAdmissionAttemptError.closed }
        self.received = nil
        // Capture owns input cleanup on failure. The attempt keeps its detached reply until success.
        let command = try RetainedCommandCapture(ownedReceived: received, expectedCallerBinding: profile.callerBinding,
            submissionSchemaVersion: profile.submissionSchemaVersion, captureSchemaVersion: context.schemaVersion,
            expression: expression, userID: userID, auditSessionID: auditSessionID, resolvedTarget: context.target,
            minimalEnvironment: context.minimalEnvironment, streamBinding: context.streamBinding,
            submissionLimits: submissionLimits, captureLimits: context.limits, maximumAncestryEntries: context.maximumAncestryEntries,
            checkCancellation: checkCancellation, admissionProfile: profile, capturedFilesystem: capturedFilesystem)
        do { try command.installAdmissionReply(reply) }
        catch { command.close(); throw error }
        self.reply = nil
        return command
    }

    func send(_ outcome: CommandAdmissionOutcome) throws {
        guard claimed, !closed, let reply else { throw CommandAdmissionAttemptError.closed }
        let payload = CommandAdmissionResultPayload(profile: profile, submission: submission.binding,
            submissionDigest: digest, outcome: outcome)
        try reply.send(payload.canonicalBytes, timeoutMilliseconds: 5000)
    }

    public func close() {
        if !closed {
            received?.closeIfUnclaimed(); received = nil; reply?.close(); reply = nil; closed = true
        }
    }
}
