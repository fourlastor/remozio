import Foundation

public enum PhonePushRegistrationError: Error { case invalidFrame }

/// Opaque provider routing data. These hints never grant enrollment authority.
public struct PhonePushTokenOffer: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let token: String
    public let projectID: String
    public let senderID: String
    public let packageName: String
    public init(token: String, projectID: String, senderID: String, packageName: String) throws {
        func matches(_ value: String, _ pattern: String) -> Bool {
            value.range(of: pattern, options: .regularExpression) == value.startIndex..<value.endIndex
        }
        guard (1...4096).contains(token.utf8.count), token.utf8.allSatisfy({ (33...126).contains($0) }),
              (1...128).contains(projectID.utf8.count), matches(projectID, "[A-Za-z0-9][A-Za-z0-9_.:-]*"),
              (1...32).contains(senderID.utf8.count), senderID.utf8.allSatisfy({ (48...57).contains($0) }),
              (1...255).contains(packageName.utf8.count), matches(packageName, "[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
        else { throw PhonePushRegistrationError.invalidFrame }
        self.token = token; self.projectID = projectID; self.senderID = senderID; self.packageName = packageName
    }
    public var description: String { "PhonePushTokenOffer(redacted)" }
    public var debugDescription: String { description }
    var value: CBORValue { .array([token, projectID, senderID, packageName].map(CBORValue.text)) }
    static func decode(_ value: CBORValue) throws -> Self {
        guard case let .array(fields) = value, fields.count == 4 else { throw PhonePushRegistrationError.invalidFrame }
        func text(_ index: Int) throws -> String {
            guard case let .text(value) = fields[index] else { throw PhonePushRegistrationError.invalidFrame }; return value
        }
        return try .init(token: text(0), projectID: text(1), senderID: text(2), packageName: text(3))
    }
}

/// Fetchable candidate metadata excludes the provider challenge. It is not an activation receipt.
public struct PhonePushRegistrationMetadata: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let identifiers: [Data]
    public let revision: UInt64
    public let operationID: Data
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64
    public var ownerID: Data { identifiers[0] }
    public var macID: Data { identifiers[1] }
    public var accountID: Data { identifiers[2] }
    public var gatewayID: Data { identifiers[3] }
    public var lifecycleEpoch: Data { identifiers[4] }
    public var phoneID: Data { identifiers[5] }
    public var enrollmentEpoch: Data { identifiers[6] }
    public var candidateID: Data { identifiers[7] }
    public var tokenDigest: Data { identifiers[8] }
    public var enrollmentTag: Data { identifiers[9] }
    public init(_ candidate: GatewayTokenCandidate) throws {
        let b = candidate.binding
        try self.init(identifiers: [b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch,
            b.phoneID, b.enrollmentEpoch, b.candidateID, b.tokenDigest, b.enrollmentTag], revision: candidate.revision,
            operationID: candidate.operationID, issuedAtUnixMillis: candidate.issuedAtUnixMillis, expiresAtUnixMillis: candidate.expiresAtUnixMillis)
    }
    private init(identifiers: [Data], revision: UInt64, operationID: Data, issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64) throws {
        guard identifiers.count == 10,
              identifiers.enumerated().allSatisfy({ $0.element.count == ($0.offset < 8 ? 16 : 32) }),
              revision > 0, operationID.count == 16, expiresAtUnixMillis > issuedAtUnixMillis else { throw PhonePushRegistrationError.invalidFrame }
        self.identifiers = identifiers; self.revision = revision; self.operationID = operationID
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
    }
    public var description: String { "PhonePushRegistrationMetadata(redacted)" }
    public var debugDescription: String { description }
    /// Receive this challenge through the provider. Recheck current trust and deadlines separately.
    public func proof(_ challenge: PushTokenChallenge) throws -> GatewayTokenProof {
        guard challenge.candidateID == candidateID, challenge.enrollmentTag == enrollmentTag else { throw PhonePushRegistrationError.invalidFrame }
        return GatewayTokenProof(binding: try .init(ownerID: ownerID, macID: macID, accountID: accountID, gatewayID: gatewayID,
            lifecycleEpoch: lifecycleEpoch, phoneID: phoneID, enrollmentEpoch: enrollmentEpoch, candidateID: candidateID,
            tokenDigest: tokenDigest, challenge: challenge.challenge, enrollmentTag: enrollmentTag))
    }
    var value: CBORValue { .array(identifiers.map(CBORValue.bytes) + [.unsigned(revision), .bytes(operationID), .unsigned(issuedAtUnixMillis), .unsigned(expiresAtUnixMillis)]) }
    static func decode(_ value: CBORValue) throws -> Self {
        guard case let .array(fields) = value, fields.count == 14,
              case let .unsigned(revision) = fields[10], case let .bytes(operationID) = fields[11],
              case let .unsigned(issued) = fields[12], case let .unsigned(expires) = fields[13] else { throw PhonePushRegistrationError.invalidFrame }
        let ids = try fields.prefix(10).map { field -> Data in
            guard case let .bytes(bytes) = field else { throw PhonePushRegistrationError.invalidFrame }; return bytes
        }
        return try .init(identifiers: ids, revision: revision, operationID: operationID, issuedAtUnixMillis: issued, expiresAtUnixMillis: expires)
    }
}

/// Proof consumption and confirmed gateway mapping differ. Neither asserts current phone delivery.
public enum PhonePushRegistrationOutcome: UInt64, Sendable {
    case unavailable = 0, proofCommitted = 1, mappingConfirmed = 2, superseded = 3, expired = 4, incompatible = 5
}

/// Only the dedicated mutually authenticated enrolled channel may carry these frames.
public enum PhonePushRegistrationFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case offer(correlationID: Data, offer: PhonePushTokenOffer)
    case prepared(correlationID: Data, metadata: PhonePushRegistrationMetadata)
    case proof(correlationID: Data, proof: GatewayTokenProof)
    case outcome(correlationID: Data, outcome: PhonePushRegistrationOutcome)
    public static let applicationProtocol = "remozio-push-registration/1"
    public static let maximumBytes = 8192
    private static let domain = "dev.remozio.phone.push.registration"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 4, maxItems: 64) } }
    private static var proofLimits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 4, maxItems: 32) } }
    public var correlationID: Data {
        switch self {
        case .offer(let id, _), .prepared(let id, _), .proof(let id, _), .outcome(let id, _): id
        }
    }
    public var description: String { "PhonePushRegistrationFrame(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        let id: Data, kind: UInt64, payload: CBORValue
        switch self {
        case .offer(let correlationID, let offer): id = correlationID; kind = 0; payload = offer.value
        case .prepared(let correlationID, let metadata): id = correlationID; kind = 1; payload = metadata.value
        case .proof(let correlationID, let proof): id = correlationID; kind = 2; payload = .bytes(try proof.encode(limits: Self.proofLimits))
        case .outcome(let correlationID, let outcome): id = correlationID; kind = 3; payload = .unsigned(outcome.rawValue)
        }
        guard id.count == 16 else { throw PhonePushRegistrationError.invalidFrame }
        return try DeterministicCBOR.encode(.map([0: .text(Self.domain), 1: .unsigned(1), 2: .unsigned(kind), 3: .bytes(id), 4: payload]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...4),
              fields[0] == .text(domain), fields[1] == .unsigned(1), case let .unsigned(kind) = fields[2],
              case let .bytes(id) = fields[3], let payload = fields[4] else { throw PhonePushRegistrationError.invalidFrame }
        let frame: Self
        switch (kind, payload) {
        case (0, _): frame = .offer(correlationID: id, offer: try PhonePushTokenOffer.decode(payload))
        case (1, _): frame = .prepared(correlationID: id, metadata: try PhonePushRegistrationMetadata.decode(payload))
        case (2, .bytes(let bytes)): frame = .proof(correlationID: id, proof: try GatewayTokenProof.decode(bytes, limits: proofLimits))
        case (3, .unsigned(let tag)):
            guard let outcome = PhonePushRegistrationOutcome(rawValue: tag) else { throw PhonePushRegistrationError.invalidFrame }
            frame = .outcome(correlationID: id, outcome: outcome)
        default: throw PhonePushRegistrationError.invalidFrame
        }
        guard try frame.encode() == bytes else { throw PhonePushRegistrationError.invalidFrame }; return frame
    }
}
