import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum CommandTerminalResultError: Error, Equatable { case incompatible, malformed, wrongBinding, deadlineExceeded }

/// These observations never authorize another execution. Exit and signal values come from the actual child supervisor.
public enum CommandTerminalOutcome: Equatable, Sendable {
    case exited(UInt8), signalled(UInt32)
    case denied, expired, cancelledBeforeStart, requesterExitedBeforeStart, failedBeforeStart, unknown
}

/// Constructed only after sender, request, submission and deadline checks. This grants no retry or dispatch authority.
public struct VerifiedCommandTerminalResult: Sendable {
    public let outcome: CommandTerminalOutcome
    /// The authority retired the stream before its output acknowledgment completed. This does not change the native outcome.
    public let outputInterrupted: Bool
    public let request: CommandAdmittedRequest
    public let submission: CapturedSubmission
    fileprivate init(outcome: CommandTerminalOutcome, outputInterrupted: Bool, request: CommandAdmittedRequest, submission: CapturedSubmission) {
        self.outcome = outcome; self.outputInterrupted = outputInterrupted; self.request = request; self.submission = submission
    }
}

/// Only the serialized Root controller can establish an actual terminal observation. Encoding alone proves nothing.
struct CommandTerminalResultPayload {
    let profile: CommandHandshakeProfile
    let submission: CapturedSubmission
    let submissionDigest: Data
    private let submissionSchemaVersion: UInt64
    let request: CommandAdmittedRequest
    let outcome: CommandTerminalOutcome
    let outputInterrupted: Bool
    init(profile: CommandHandshakeProfile, original: CommandSubmission, request: CommandAdmittedRequest,
         outcome: CommandTerminalOutcome, outputInterrupted: Bool = false) {
        self.profile = profile; submission = original.binding; submissionDigest = Data(SHA256.hash(data: original.canonicalBytes))
        submissionSchemaVersion = original.schemaVersion; self.request = request; self.outcome = outcome; self.outputInterrupted = outputInterrupted
    }
    init(profile: CommandHandshakeProfile, submission: CapturedSubmission, submissionDigest: Data,
         request: CommandAdmittedRequest, outcome: CommandTerminalOutcome, outputInterrupted: Bool = false) {
        self.profile = profile; self.submission = submission; self.submissionDigest = submissionDigest
        submissionSchemaVersion = profile.submissionSchemaVersion; self.request = request; self.outcome = outcome; self.outputInterrupted = outputInterrupted
    }
    static func limits() throws -> CBORLimits { try .init(maxBytes: 4096, maxDepth: 6, maxItems: 128) }
    var canonicalBytes: Data { get throws {
        guard profile.supportsExecutionChannels, submissionSchemaVersion == profile.submissionSchemaVersion,
              submission.callerBinding == profile.callerBinding else { throw CommandTerminalResultError.incompatible }
        guard submission.id.count == 16, submission.nonce.count == 32, submissionDigest.count == 32,
              request.requestID.count == 16, request.requestToken.count == 32, request.challenge.count == 32 else {
            throw CommandTerminalResultError.malformed
        }
        let tag: UInt64, body: CBORValue
        switch outcome {
        case .exited(let status): tag = 1; body = .unsigned(UInt64(status))
        case .signalled(let signal):
            guard signal > 0, signal < UInt32(NSIG) else { throw CommandTerminalResultError.malformed }
            tag = 2; body = .unsigned(UInt64(signal))
        case .denied: tag = 3; body = .null
        case .expired: tag = 4; body = .null
        case .cancelledBeforeStart: tag = 5; body = .null
        case .requesterExitedBeforeStart: tag = 6; body = .null
        case .failedBeforeStart: tag = 7; body = .null
        case .unknown: tag = 8; body = .null
        }
        guard !outputInterrupted || profile.supportsStreamingExecution else { throw CommandTerminalResultError.incompatible }
        let binding = submission
        var fields: [UInt64: CBORValue] = [0: .unsigned(1), 1: profile.fields,
            2: .map([0: .bytes(binding.id), 1: .bytes(binding.nonce), 2: .bytes(binding.callerBinding)]),
            3: .bytes(submissionDigest),
            4: .map([0: .bytes(request.requestID), 1: .bytes(request.requestToken), 2: .bytes(request.challenge)]),
            5: .unsigned(tag), 6: body]
        if outputInterrupted { fields[7] = .unsigned(1) }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits())
    } }
    static func decode(_ bytes: Data, profile: CommandHandshakeProfile, original: CommandSubmission,
                       admission: VerifiedCommandAdmissionResult) throws -> VerifiedCommandTerminalResult {
        guard profile.supportsExecutionChannels, case .admitted(let request) = admission.outcome else {
            throw CommandTerminalResultError.incompatible
        }
        guard admission.profile == profile, admission.submission == original.binding,
              admission.submissionDigest == Data(SHA256.hash(data: original.canonicalBytes)) else {
            throw CommandTerminalResultError.wrongBinding
        }
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set((0...(fields[7] == nil ? 6 : 7)).map(UInt64.init)), fields[0] == .unsigned(1), let rawProfile = fields[1],
              case .map(let binding) = fields[2], Set(binding.keys) == [0, 1, 2],
              binding[0] == .bytes(original.binding.id), binding[1] == .bytes(original.binding.nonce),
              binding[2] == .bytes(original.binding.callerBinding), fields[3] == .bytes(admission.submissionDigest),
              case .map(let identity) = fields[4], Set(identity.keys) == [0, 1, 2],
              identity[0] == .bytes(request.requestID), identity[1] == .bytes(request.requestToken),
              identity[2] == .bytes(request.challenge), case .unsigned(let tag) = fields[5], let body = fields[6] else {
            throw CommandTerminalResultError.malformed
        }
        guard try CommandHandshakeProfile.decode(rawProfile) == profile else { throw CommandTerminalResultError.wrongBinding }
        let outputInterrupted = fields[7] != nil
        guard !outputInterrupted || profile.supportsStreamingExecution && fields[7] == .unsigned(1) else {
            throw CommandTerminalResultError.malformed
        }
        let outcome: CommandTerminalOutcome
        switch tag {
        case 1:
            guard case .unsigned(let status) = body, status <= 255 else { throw CommandTerminalResultError.malformed }
            outcome = .exited(UInt8(status))
        case 2:
            guard case .unsigned(let signal) = body, signal > 0, signal < UInt64(NSIG) else { throw CommandTerminalResultError.malformed }
            outcome = .signalled(UInt32(signal))
        case 3...8:
            guard body == .null else { throw CommandTerminalResultError.malformed }
            switch tag {
            case 3: outcome = .denied
            case 4: outcome = .expired
            case 5: outcome = .cancelledBeforeStart
            case 6: outcome = .requesterExitedBeforeStart
            case 7: outcome = .failedBeforeStart
            default: outcome = .unknown
            }
        default: throw CommandTerminalResultError.malformed
        }
        let value = Self(profile: profile, original: original, request: request, outcome: outcome, outputInterrupted: outputInterrupted)
        guard try value.canonicalBytes == bytes else { throw CommandTerminalResultError.malformed }
        return VerifiedCommandTerminalResult(outcome: outcome, outputInterrupted: outputInterrupted, request: request, submission: original.binding)
    }
}
