import Foundation

public enum RootUpdateSchedulingChallengeError: String, Error, Equatable {
    case invalidFields, unsupportedSchema, invalidNonce
}

/// The Root binds one scheduling control to the phone's fresh query. This response cannot authorize a target action.
public struct RootUpdateSchedulingChallenge: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let queryNonce: Data
    public let canonicalControl: Data

    public init(queryNonce: Data, canonicalControl: Data, limits: CBORLimits) throws {
        guard queryNonce.count == 32 else { throw RootUpdateSchedulingChallengeError.invalidNonce }
        _ = try UpdateSchedulingControl.decode(canonicalControl, limits: limits)
        self.queryNonce = queryNonce
        self.canonicalControl = canonicalControl
    }

    public var description: String { "RootUpdateSchedulingChallenge(redacted)" }
    public var debugDescription: String { description }

    public func encode(limits: CBORLimits) throws -> Data {
        _ = try UpdateSchedulingControl.decode(canonicalControl, limits: limits)
        return try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(queryNonce), 2: .bytes(canonicalControl),
        ]), limits: limits)
    }

    public static func decode(_ payload: Data, limits: CBORLimits) throws -> RootUpdateSchedulingChallenge {
        guard case let .map(fields) = try DeterministicCBOR.decode(payload, limits: limits),
              Set(fields.keys) == Set<UInt64>([0, 1, 2]) else { throw RootUpdateSchedulingChallengeError.invalidFields }
        guard fields[0] == .unsigned(1) else { throw RootUpdateSchedulingChallengeError.unsupportedSchema }
        guard case let .bytes(nonce) = fields[1] else { throw RootUpdateSchedulingChallengeError.invalidNonce }
        guard case let .bytes(control) = fields[2] else { throw RootUpdateSchedulingChallengeError.invalidFields }
        return try .init(queryNonce: nonce, canonicalControl: control, limits: limits)
    }
}

public enum RootUpdateSchedulingChallengeSigningInput {
    public static func make(wireVersion: UInt64, canonicalPayload: Data, payloadLimits: CBORLimits,
                            inputLimits: CBORLimits) throws -> Data {
        guard wireVersion == 1 else { throw SigningInputError.unsupportedVersion }
        _ = try RootUpdateSchedulingChallenge.decode(canonicalPayload, limits: payloadLimits)
        return try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.update-scheduling-challenge"), 1: .unsigned(1),
            2: .unsigned(1), 3: .unsigned(1), 4: .bytes(canonicalPayload),
        ]), limits: inputLimits)
    }
}

/// The phone selects its enrolled Root key. It must match the query and displayed choice and enforce the original lifetime.
public enum RootUpdateSchedulingChallengeSignature {
    public static func verify(signature: Data, authorityPublicKey: Data, wireVersion: UInt64, canonicalPayload: Data,
                              payloadLimits: CBORLimits, inputLimits: CBORLimits) throws -> Bool {
        let input = try RootUpdateSchedulingChallengeSigningInput.make(wireVersion: wireVersion,
            canonicalPayload: canonicalPayload, payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: authorityPublicKey, input: input)
    }
}
