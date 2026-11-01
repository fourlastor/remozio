import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A signed rejection of one scheduling request. Its progress is an observation, not a control acknowledgment.
public struct UpdateSchedulingTooLateResponse: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let requestDigest: Data
    public let progress: UpdateSchedulingProgressResponse
    public static let maximumBytes = 8192
    public static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 16) } }

    public init(request: PhoneUpdateSchedulingFrame, progress: UpdateSchedulingProgressResponse) throws {
        guard try Self.requestMatchesProgress(request, progress: progress) else { throw UpdateSchedulingStatusError.invalidMessage }
        try self.init(requestDigest: Self.digest(request), progress: progress)
    }
    private init(requestDigest: Data, progress: UpdateSchedulingProgressResponse) throws {
        guard requestDigest.count == 32, progress.phase.irreversible, progress.availableActions.isEmpty,
              progress.status.controlDigest == nil else { throw UpdateSchedulingStatusError.invalidMessage }
        self.requestDigest = requestDigest; self.progress = progress
    }
    /// The caller must also verify the Root signature and the original live query deadline.
    public func matches(request: PhoneUpdateSchedulingFrame, expectedScope: ChannelScope) throws -> Bool {
        try progress.status.scope == expectedScope && Self.requestMatchesProgress(request, progress: progress)
            && Self.digest(request) == requestDigest
    }
    public static func digest(_ request: PhoneUpdateSchedulingFrame) throws -> Data {
        switch request {
        case .challenge, .apply: break
        default: throw PhoneUpdateSchedulingFrameError.invalidMessage
        }
        return Data(SHA256.hash(data: Data("dev.remozio.update-scheduling-request\0".utf8) + (try request.encode())))
    }
    private static func requestMatchesProgress(_ request: PhoneUpdateSchedulingFrame,
                                               progress: UpdateSchedulingProgressResponse) throws -> Bool {
        _ = try request.encode()
        guard request.queryNonce == progress.status.queryNonce else { return false }
        switch request {
        case let .challenge(_, update, generation, _, _):
            return update == progress.status.updateID && generation == progress.status.generation
        case let .apply(_, bytes, _):
            let control = try UpdateSchedulingControl.decode(bytes, limits: CBORLimits(maxBytes: 1024, maxDepth: 2, maxItems: 32))
            return control.macID == progress.status.scope.macID && control.accountID == progress.status.scope.accountID
                && control.phoneID == progress.status.scope.phoneID && control.enrollmentEpoch == progress.status.scope.enrollmentEpoch
                && control.updateID == progress.status.updateID && control.expectedGeneration == progress.status.generation
        default: throw PhoneUpdateSchedulingFrameError.invalidMessage
        }
    }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(0),
            2: .bytes(requestDigest), 3: .bytes(progress.encode())]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1), fields[1] == .unsigned(0),
              case let .bytes(digest) = fields[2], case let .bytes(progress) = fields[3] else {
            throw UpdateSchedulingStatusError.invalidMessage
        }
        let value = try Self(requestDigest: digest, progress: UpdateSchedulingProgressResponse.decode(progress))
        guard try value.encode() == bytes else { throw UpdateSchedulingStatusError.invalidMessage }; return value
    }
    public var description: String { "UpdateSchedulingTooLateResponse(redacted)" }
    public var debugDescription: String { description }
}

public enum UpdateSchedulingTooLateSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try UpdateSchedulingTooLateResponse.decode(canonicalPayload)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.update-scheduling-too-late"), 1: .unsigned(1), 2: .unsigned(1),
            3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}
public enum UpdateSchedulingTooLateSignature {
    public static func verify(signature: Data, authorityPublicKey: Data, wireVersion: UInt64,
                              canonicalPayload: Data, inputLimits: CBORLimits) throws -> Bool {
        let input = try UpdateSchedulingTooLateSigningInput.make(wireVersion: wireVersion,
            canonicalPayload: canonicalPayload, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: authorityPublicKey, input: input)
    }
}
