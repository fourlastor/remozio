import CryptoKit
import Foundation
import RemozioProtocol

public enum GatewayMappingStateError: Error, Equatable {
    case invalidConfiguration, invalidMessage, invalidSignature, wrongScope, noQuery, expired, invalidClock
}

/// Fixed Root query. It contains no token or provider challenge.
struct GatewayMappingScope: Equatable, Sendable {
    let registration: GatewayRegistrationIdentity
    let phoneID: Data
    let enrollmentEpoch: Data
    let candidateID: Data
    let tokenDigest: Data
    init(registration: GatewayRegistrationIdentity, binding: GatewayTokenBinding) throws {
        guard registration.matches(binding) else { throw GatewayMappingStateError.wrongScope }
        self.registration = registration; phoneID = binding.phoneID; enrollmentEpoch = binding.enrollmentEpoch
        candidateID = binding.candidateID; tokenDigest = binding.tokenDigest
    }
    private init(registration: GatewayRegistrationIdentity, phone: Data, epoch: Data, candidate: Data, digest: Data) throws {
        guard [phone, epoch, candidate].allSatisfy({ $0.count == 16 }), digest.count == 32 else { throw GatewayMappingStateError.invalidMessage }
        self.registration = registration; phoneID = phone; enrollmentEpoch = epoch; candidateID = candidate; tokenDigest = digest
    }
    var fields: [UInt64: CBORValue] { get throws {
        [2: .bytes(try registration.encode()), 4: .bytes(phoneID), 5: .bytes(enrollmentEpoch),
         6: .bytes(candidateID), 7: .bytes(tokenDigest)]
    } }
    static func decode(_ fields: [UInt64: CBORValue]) throws -> Self {
        try .init(registration: GatewayRegistrationIdentity.decode(GatewayMappingStateWire.bytes(fields, 2)),
            phone: GatewayMappingStateWire.bytes(fields, 4), epoch: GatewayMappingStateWire.bytes(fields, 5),
            candidate: GatewayMappingStateWire.bytes(fields, 6), digest: GatewayMappingStateWire.bytes(fields, 7))
    }
    func matches(_ binding: GatewayTokenBinding) -> Bool {
        registration.matches(binding) && phoneID == binding.phoneID && enrollmentEpoch == binding.enrollmentEpoch &&
            candidateID == binding.candidateID && tokenDigest == binding.tokenDigest
    }
}

/// Unverified transport bytes. Only the protected query owner can accept them.
public struct GatewayMappingStateReply: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let canonicalPayload: Data
    public let signature: Data
    public init(canonicalPayload: Data, signature: Data) { self.canonicalPayload = canonicalPayload; self.signature = signature }
    public var description: String { "GatewayMappingStateReply(redacted)" }
    public var debugDescription: String { description }
}

/// Current observation for one fresh Root query. It is not phone delivery, enrollment authority or permission to send.
struct VerifiedGatewayMappingState: Sendable {
    let scope: GatewayMappingScope
    let activation: GatewayMappingActivation?
    let queriedAt: AuthorityMoment
    let receivedAt: AuthorityMoment
    let validUntilMilliseconds: UInt64
    let queryOwnerID: UUID
    fileprivate init(scope: GatewayMappingScope, activation: GatewayMappingActivation?, queriedAt: AuthorityMoment,
                     receivedAt: AuthorityMoment, validUntilMilliseconds: UInt64, queryOwnerID: UUID) {
        self.scope = scope; self.activation = activation; self.queriedAt = queriedAt; self.receivedAt = receivedAt
        self.validUntilMilliseconds = validUntilMilliseconds; self.queryOwnerID = queryOwnerID
    }
}

/// Serialize with local Root state. The gateway key and scope come only from protected startup and retained intent.
final class GatewayMappingQueryOwner {
    private let key: P256.Signing.PublicKey
    private let scope: GatewayMappingScope
    private let epoch: UUID
    private let lifetime: UInt64
    private let identifier = UUID()
    private var pending: (nonce: Data, started: UInt64, deadline: UInt64)?
    private var last: UInt64?
    init(scope: GatewayMappingScope, gatewayPublicKey: Data, clockEpoch: UUID, lifetimeMilliseconds: UInt64 = 5000) throws {
        guard (1...60_000).contains(lifetimeMilliseconds), gatewayPublicKey.count == 65,
              let key = try? P256.Signing.PublicKey(x963Representation: gatewayPublicKey),
              gatewayPublicKey != scope.registration.rootPublicKey else { throw GatewayMappingStateError.invalidConfiguration }
        self.scope = scope; self.key = key; epoch = clockEpoch; lifetime = lifetimeMilliseconds
    }
    func query(now: AuthorityMoment) throws -> Data {
        try clock(now)
        guard pending == nil || now.milliseconds >= pending!.deadline else { throw GatewayMappingStateError.noQuery }
        let (deadline, overflow) = now.milliseconds.addingReportingOverflow(lifetime)
        guard !overflow else { throw GatewayMappingStateError.invalidClock }
        let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        var fields = try scope.fields
        fields[0] = .unsigned(2); fields[1] = .unsigned(4); fields[3] = .bytes(nonce)
        let query = try DeterministicCBOR.encode(.map(fields), limits: GatewayMappingStateWire.queryLimits)
        pending = (nonce, now.milliseconds, deadline); return query
    }
    func accept(_ reply: GatewayMappingStateReply, now: AuthorityMoment) throws -> VerifiedGatewayMappingState {
        try clock(now)
        guard let pending else { throw GatewayMappingStateError.noQuery }
        guard now.milliseconds < pending.deadline else { self.pending = nil; throw GatewayMappingStateError.expired }
        let replyLimits = try GatewayMappingStateWire.replyLimits
        guard reply.signature.count == 64, reply.canonicalPayload.count <= replyLimits.maxBytes,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: reply.signature),
              key.isValidSignature(signature, for: GatewayMappingStateWire.signingInput(reply.canonicalPayload)) else {
            throw GatewayMappingStateError.invalidSignature
        }
        let fields = try GatewayMappingStateWire.fields(reply.canonicalPayload, kind: 5, last: 10, limits: GatewayMappingStateWire.replyLimits)
        guard try GatewayMappingScope.decode(fields) == scope,
              try GatewayMappingStateWire.bytes(fields, 3) == pending.nonce else { throw GatewayMappingStateError.wrongScope }
        let payload = try GatewayMappingStateWire.bytes(fields, 9), rootSignature = try GatewayMappingStateWire.bytes(fields, 10)
        let activation: GatewayMappingActivation?
        switch fields[8] {
        case .unsigned(0):
            guard payload.isEmpty, rootSignature.isEmpty else { throw GatewayMappingStateError.invalidMessage }
            activation = nil
        case .unsigned(1):
            let value = try GatewayMappingActivation.decode(payload, limits: GatewayMappingStateWire.controlLimits)
            guard scope.matches(value.binding),
                  try GatewayRecipientSignature.verify(signature: rootSignature, publicKey: scope.registration.rootPublicKey,
                    wireVersion: 1, kind: .activation, canonicalPayload: payload,
                    payloadLimits: GatewayMappingStateWire.controlLimits, inputLimits: GatewayMappingStateWire.signingLimits) else {
                throw GatewayMappingStateError.invalidSignature
            }
            activation = value
        default: throw GatewayMappingStateError.invalidMessage
        }
        self.pending = nil
        return VerifiedGatewayMappingState(scope: scope, activation: activation, queriedAt: .init(epoch: epoch, milliseconds: pending.started),
            receivedAt: now, validUntilMilliseconds: pending.deadline, queryOwnerID: identifier)
    }
    private func clock(_ now: AuthorityMoment) throws {
        guard now.epoch == epoch, last.map({ now.milliseconds >= $0 }) ?? true else { throw GatewayMappingStateError.invalidClock }
        last = now.milliseconds
    }
}

enum GatewayMappingStateWire {
    static var queryLimits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 1, maxItems: 20) } }
    static var replyLimits: CBORLimits { get throws { try .init(maxBytes: 8192, maxDepth: 1, maxItems: 24) } }
    static var controlLimits: CBORLimits { get throws { try .init(maxBytes: 4096, maxDepth: 8, maxItems: 128) } }
    static var signingLimits: CBORLimits { get throws { try .init(maxBytes: 8192, maxDepth: 8, maxItems: 128) } }
    static func bytes(_ fields: [UInt64: CBORValue], _ key: UInt64) throws -> Data {
        guard case .bytes(let value) = fields[key] else { throw GatewayMappingStateError.invalidMessage }; return value
    }
    static func fields(_ data: Data, kind: UInt64, last: UInt64, limits: CBORLimits) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(data, limits: limits), Set(f.keys) == Set(UInt64(0)...last),
              f[0] == .unsigned(2), f[1] == .unsigned(kind) else { throw GatewayMappingStateError.invalidMessage }
        return f
    }
    static func isQuery(_ data: Data) -> Bool {
        guard let f = try? fields(data, kind: 4, last: 7, limits: queryLimits) else { return false }
        return f[0] == .unsigned(2)
    }
    static func query(_ bytes: Data) throws -> (GatewayMappingScope, Data) {
        let f = try fields(bytes, kind: 4, last: 7, limits: queryLimits), nonce = try self.bytes(f, 3)
        guard nonce.count == 32 else { throw GatewayMappingStateError.invalidMessage }
        return try (GatewayMappingScope.decode(f), nonce)
    }
    static func signingInput(_ payload: Data) -> Data { Data("Remozio/GatewayMappingState/v1\u{0}".utf8) + payload }
}

extension GatewayDatabase {
    /// The coordinator serializes this read and signature with current trust and its live Root lease.
    func mappingStateReply(query: Data, trust: GatewayCandidateTrust, sign: (Data) throws -> Data) throws -> GatewayMappingStateReply {
        let (scope, nonce) = try GatewayMappingStateWire.query(query)
        guard scope.registration == (try headEvidence()).registration, scope.phoneID == trust.enrollment.phoneID,
              scope.enrollmentEpoch == trust.enrollment.epoch else { throw GatewayMappingStateError.wrongScope }
        let mapping = try activeMapping(trust: trust)
        let current = mapping.flatMap { scope.matches($0.activation.binding) ? $0 : nil }
        var fields = try scope.fields
        fields[0] = .unsigned(2); fields[1] = .unsigned(5); fields[3] = .bytes(nonce)
        fields[8] = .unsigned(current == nil ? 0 : 1)
        fields[9] = .bytes(current?.receipt.canonicalPayload ?? Data()); fields[10] = .bytes(current?.receipt.signature ?? Data())
        let payload = try DeterministicCBOR.encode(.map(fields), limits: GatewayMappingStateWire.replyLimits), signature = try sign(GatewayMappingStateWire.signingInput(payload))
        guard signature.count == 64 else { throw GatewayMappingStateError.invalidSignature }
        return GatewayMappingStateReply(canonicalPayload: payload, signature: signature)
    }
}
