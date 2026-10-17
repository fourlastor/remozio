import Foundation

/// A mapping observation describes gateway state, not provider delivery or desktop presence.
public enum PhonePushRecoveryPhase: UInt64, Sendable {
    case awaitingProviderProof = 0, proofCommitted = 1, mappingObserved = 2
}

public enum PhonePushRecoveryFailure: UInt64, Sendable {
    case unavailable = 0, superseded = 3, expired = 4, incompatible = 5
}

/// Public metadata excludes the provider challenge. The caller must validate scope and freshness separately.
public struct PhonePushRecoveryState: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let metadata: PhonePushRegistrationMetadata
    public let phase: PhonePushRecoveryPhase
    public let observationAgeMilliseconds: UInt64?
    public static let maximumObservationAgeMilliseconds: UInt64 = 4999
    public init(metadata: PhonePushRegistrationMetadata, phase: PhonePushRecoveryPhase, observationAgeMilliseconds: UInt64? = nil) throws {
        guard (phase == .mappingObserved) == (observationAgeMilliseconds != nil),
              observationAgeMilliseconds.map({ $0 <= Self.maximumObservationAgeMilliseconds }) ?? true else {
            throw PhonePushRegistrationError.invalidFrame
        }
        self.metadata = metadata; self.phase = phase; self.observationAgeMilliseconds = observationAgeMilliseconds
    }
    public var description: String { "PhonePushRecoveryState(redacted)" }
    public var debugDescription: String { description }
    var value: CBORValue {
        .array([metadata.value, .unsigned(phase.rawValue), observationAgeMilliseconds.map(CBORValue.unsigned) ?? .null])
    }
    static func decode(_ value: CBORValue) throws -> Self {
        guard case let .array(fields) = value, fields.count == 3, case let .unsigned(tag) = fields[1],
              let phase = PhonePushRecoveryPhase(rawValue: tag) else { throw PhonePushRegistrationError.invalidFrame }
        let age: UInt64?
        switch fields[2] {
        case .null: age = nil
        case .unsigned(let value): age = value
        default: throw PhonePushRegistrationError.invalidFrame
        }
        return try .init(metadata: PhonePushRegistrationMetadata.decode(fields[0]), phase: phase, observationAgeMilliseconds: age)
    }
}

/// Negotiate schema 2 before sending a token. Proofs retain the separate version 1 exchange and its replay rules.
public enum PhonePushRecoveryFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case probe(correlationID: Data)
    case ready(correlationID: Data)
    case resume(correlationID: Data, offer: PhonePushTokenOffer)
    case state(correlationID: Data, state: PhonePushRecoveryState)
    case outcome(correlationID: Data, failure: PhonePushRecoveryFailure)
    public static let applicationProtocol = "remozio-push-registration/2"
    public static let maximumBytes = 8192
    private static let domain = "dev.remozio.phone.push.registration"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 4, maxItems: 64) } }
    public var correlationID: Data {
        switch self { case .probe(let id), .ready(let id), .resume(let id, _), .state(let id, _), .outcome(let id, _): id }
    }
    public var description: String { "PhonePushRecoveryFrame(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        let kind: UInt64, payload: CBORValue
        switch self {
        case .probe: kind = 6; payload = .null
        case .ready: kind = 7; payload = .unsigned(2)
        case .resume(_, let offer): kind = 4; payload = offer.value
        case .state(_, let state): kind = 5; payload = state.value
        case .outcome(_, let failure): kind = 3; payload = .unsigned(failure.rawValue)
        }
        guard correlationID.count == 16 else { throw PhonePushRegistrationError.invalidFrame }
        return try DeterministicCBOR.encode(.map([0: .text(Self.domain), 1: .unsigned(2), 2: .unsigned(kind),
            3: .bytes(correlationID), 4: payload]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...4),
              fields[0] == .text(domain), fields[1] == .unsigned(2), case let .unsigned(kind) = fields[2],
              case let .bytes(id) = fields[3], let payload = fields[4] else { throw PhonePushRegistrationError.invalidFrame }
        let frame: Self
        switch (kind, payload) {
        case (6, .null): frame = .probe(correlationID: id)
        case (7, .unsigned(2)): frame = .ready(correlationID: id)
        case (4, _): frame = .resume(correlationID: id, offer: try PhonePushTokenOffer.decode(payload))
        case (5, _): frame = .state(correlationID: id, state: try PhonePushRecoveryState.decode(payload))
        case (3, .unsigned(let tag)):
            guard let failure = PhonePushRecoveryFailure(rawValue: tag) else { throw PhonePushRegistrationError.invalidFrame }
            frame = .outcome(correlationID: id, failure: failure)
        default: throw PhonePushRegistrationError.invalidFrame
        }
        guard try frame.encode() == bytes else { throw PhonePushRegistrationError.invalidFrame }; return frame
    }
}
