import CryptoKit
import Foundation
import RemozioProtocol

public enum CommandAdmissionResultError: Error, Equatable { case incompatible, malformed, wrongBinding }

public enum CommandAdmissionRejectionReason: UInt64, Sendable {
    case updateInstalling = 1, authorityStarting = 2, updateWaiting = 3, storageUnavailable = 4
    case invalidRequest = 10, policyRejected = 11, capacityExceeded = 12, unsupported = 13, requesterExited = 14
}
public enum CommandAdmissionRetryClass: UInt64, Sendable {
    case never = 0, updateInstalling = 1, authorityStarting = 2, updateWaiting = 3, storageUnavailable = 4
}
public enum CommandAdmissionUncertainty: UInt64, Sendable { case admissionRejected = 1, duplicateSubmission = 2, storageFailure = 3 }

/// A request identity is an admission acknowledgment. It grants no decision or execution permission.
public struct CommandAdmittedRequest: Equatable, Sendable {
    public let requestID: Data
    /// Opaque Authority value retained by the caller for stream and terminal binding.
    public let requestToken: Data
    public let challenge: Data
    init(requestID: Data, requestToken: Data, challenge: Data) {
        self.requestID = requestID; self.requestToken = requestToken; self.challenge = challenge
    }
}

/// Parsed result data alone is not proof of a reply from the current authority.
public enum CommandAdmissionOutcome: Equatable, Sendable {
    case admitted(CommandAdmittedRequest)
    case notAdmitted(CommandAdmissionRejectionReason, CommandAdmissionRetryClass)
    case uncertain(CommandAdmissionUncertainty)
}

/// Constructed only after actual sender authentication and exact submission binding inside the client deadline.
public struct VerifiedCommandAdmissionResult: Sendable {
    public let outcome: CommandAdmissionOutcome
    public let submission: CapturedSubmission
    public let submissionDigest: Data
    public let profile: CommandHandshakeProfile
    fileprivate init(_ payload: CommandAdmissionResultPayload) {
        outcome = payload.outcome; submission = payload.submission; submissionDigest = payload.submissionDigest; profile = payload.profile
    }
    /// This identifies an understood class. The bounded fresh-submission controller remains a separate gate.
    public var retryClass: CommandAdmissionRetryClass {
        if case .notAdmitted(_, let retry) = outcome { return retry }
        return .never
    }
}

/// Root asserts this state only from its serialized admission owner. Encoding cannot establish that state.
struct CommandAdmissionResultPayload {
    let profile: CommandHandshakeProfile
    let submission: CapturedSubmission
    let submissionDigest: Data
    let outcome: CommandAdmissionOutcome
    static func limits() throws -> CBORLimits { try CBORLimits(maxBytes: 4096, maxDepth: 6, maxItems: 96) }

    var canonicalBytes: Data { get throws {
        guard profile.supportsAdmissionResults, submission.callerBinding == profile.callerBinding,
              submission.id.count == 16, submission.nonce.count == 32, submissionDigest.count == 32 else {
            throw CommandAdmissionResultError.incompatible
        }
        let tag: UInt64, body: CBORValue
        switch outcome {
        case .admitted(let request):
            guard request.requestID.count == 16, request.requestToken.count == 32, request.challenge.count == 32 else {
                throw CommandAdmissionResultError.malformed
            }
            tag = 1; body = .map([0: .bytes(request.requestID), 1: .bytes(request.requestToken), 2: .bytes(request.challenge)])
        case .notAdmitted(let reason, let retry):
            guard Self.valid(reason: reason, retry: retry) else { throw CommandAdmissionResultError.malformed }
            tag = 2; body = .map([0: .unsigned(reason.rawValue), 1: .unsigned(retry.rawValue)])
        case .uncertain(let reason): tag = 3; body = .map([0: .unsigned(reason.rawValue)])
        }
        return try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: profile.fields,
            2: .map([0: .bytes(submission.id), 1: .bytes(submission.nonce), 2: .bytes(submission.callerBinding)]),
            3: .bytes(submissionDigest), 4: .unsigned(tag), 5: body]), limits: Self.limits())
    } }

    static func decode(_ bytes: Data, profile: CommandHandshakeProfile, original: CommandSubmission) throws -> VerifiedCommandAdmissionResult {
        guard profile.supportsAdmissionResults else { throw CommandAdmissionResultError.incompatible }
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits()),
              Set(fields.keys) == Set((0...5).map(UInt64.init)), fields[0] == .unsigned(1), let rawProfile = fields[1],
              case .map(let binding) = fields[2], Set(binding.keys) == [0, 1, 2],
              case .bytes(let id) = binding[0], case .bytes(let nonce) = binding[1], case .bytes(let caller) = binding[2],
              case .bytes(let digest) = fields[3], case .unsigned(let tag) = fields[4], case .map(let body) = fields[5] else {
            throw CommandAdmissionResultError.malformed
        }
        let selected = try CommandHandshakeProfile.decode(rawProfile)
        guard selected == profile, original.schemaVersion == profile.submissionSchemaVersion,
              original.binding.callerBinding == profile.callerBinding,
              id == original.binding.id, nonce == original.binding.nonce, caller == original.binding.callerBinding,
              digest == Data(SHA256.hash(data: original.canonicalBytes)) else { throw CommandAdmissionResultError.wrongBinding }
        let outcome: CommandAdmissionOutcome
        switch tag {
        case 1:
            guard Set(body.keys) == [0, 1, 2], case .bytes(let requestID) = body[0], requestID.count == 16,
                  case .bytes(let requestToken) = body[1], requestToken.count == 32,
                  case .bytes(let challenge) = body[2], challenge.count == 32 else { throw CommandAdmissionResultError.malformed }
            outcome = .admitted(.init(requestID: requestID, requestToken: requestToken, challenge: challenge))
        case 2:
            guard Set(body.keys) == [0, 1], case .unsigned(let rawReason) = body[0],
                  let reason = CommandAdmissionRejectionReason(rawValue: rawReason), case .unsigned(let rawRetry) = body[1],
                  let retry = CommandAdmissionRetryClass(rawValue: rawRetry), valid(reason: reason, retry: retry) else {
                throw CommandAdmissionResultError.malformed
            }
            outcome = .notAdmitted(reason, retry)
        case 3:
            guard Set(body.keys) == [0], case .unsigned(let rawReason) = body[0],
                  let reason = CommandAdmissionUncertainty(rawValue: rawReason) else { throw CommandAdmissionResultError.malformed }
            outcome = .uncertain(reason)
        default: throw CommandAdmissionResultError.malformed
        }
        let payload = Self(profile: profile, submission: original.binding, submissionDigest: digest, outcome: outcome)
        guard try payload.canonicalBytes == bytes else { throw CommandAdmissionResultError.malformed }
        return VerifiedCommandAdmissionResult(payload)
    }
    private static func valid(reason: CommandAdmissionRejectionReason, retry: CommandAdmissionRetryClass) -> Bool {
        if reason.rawValue <= 4 { return retry.rawValue == reason.rawValue }
        return retry == .never
    }
}
