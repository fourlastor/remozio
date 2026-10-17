#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

public enum ChannelRole: UInt64, Sendable { case phone = 0, mac = 1 }
public enum ChannelNegotiationError: Error { case rejected }

public struct ChannelScope: Equatable, Sendable, CustomStringConvertible {
    fileprivate let value: CBORValue
    public let macID: Data
    public let accountID: Data
    public let phoneID: Data
    public let enrollmentEpoch: Data
    public init(macID: Data, accountID: Data, phoneID: Data, enrollmentEpoch: Data) throws {
        let values = [macID, accountID, phoneID, enrollmentEpoch]
        try channelCheck(values.allSatisfy { $0.count == 16 })
        self.macID = macID; self.accountID = accountID; self.phoneID = phoneID; self.enrollmentEpoch = enrollmentEpoch
        value = .array(values.map(CBORValue.bytes))
    }
    public var description: String { "ChannelScope(redacted)" }
}

/// Unknown kinds remain opaque. They never enable a renderer or action verifier.
public struct ChannelRequestCapability: Sendable {
    public let kind: UInt64
    public let wireVersion: UInt64
    public let schemaVersion: UInt64
    public let features: Set<UInt64>
    public init(kind: UInt64, wireVersion: UInt64, schemaVersion: UInt64, features: Set<UInt64>) throws {
        try channelCheck(wireVersion > 0 && schemaVersion > 0 && features.count <= 64)
        self.kind = kind; self.wireVersion = wireVersion; self.schemaVersion = schemaVersion; self.features = features
    }
    fileprivate var value: CBORValue {
        .array([.unsigned(kind), .unsigned(wireVersion), .unsigned(schemaVersion), numbers(features)])
    }
    fileprivate var identity: [UInt64] { [kind, wireVersion, schemaVersion] }
}

/// Parsed offers are untrusted until confirmed over the same enrolled TLS connection.
public struct ChannelOffer: Sendable, CustomStringConvertible {
    public let role: ChannelRole
    public let scope: ChannelScope
    public let nonce: Data
    public let envelopeVersions: Set<UInt64>
    public let requests: [ChannelRequestCapability]
    public let auditVersions: Set<UInt64>
    public init(role: ChannelRole, scope: ChannelScope, nonce: Data, envelopeVersions: Set<UInt64>,
                requests: [ChannelRequestCapability], auditVersions: Set<UInt64>) throws {
        try channelCheck(nonce.count == 32 && (1...16).contains(envelopeVersions.count) && !envelopeVersions.contains(0))
        try channelCheck(auditVersions.count <= 16 && !auditVersions.contains(0))
        try channelCheck(requests.count <= 64 && Set(requests.map(\.identity)).count == requests.count)
        self.role = role; self.scope = scope; self.nonce = nonce; self.envelopeVersions = envelopeVersions
        self.requests = requests.sorted { $0.identity.lexicographicallyPrecedes($1.identity) }; self.auditVersions = auditVersions
    }
    public var description: String { "ChannelOffer(redacted)" }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .unsigned(role.rawValue), 2: scope.value, 3: .bytes(nonce),
            4: numbers(envelopeVersions), 5: .array(requests.map(\.value)), 6: numbers(auditVersions),
        ]), limits: offerLimits())
    }
    public static func decode(_ bytes: Data) throws -> ChannelOffer {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: offerLimits()),
              Set(fields.keys) == Set(0...UInt64(6)), fields[0] == .unsigned(1),
              case let .unsigned(tag) = fields[1], let role = ChannelRole(rawValue: tag),
              case let .array(scope) = fields[2], scope.count == 4, case let .bytes(nonce) = fields[3],
              case let .array(rows) = fields[5], rows.count <= 64 else { throw ChannelNegotiationError.rejected }
        func scopeBytes(_ index: Int) throws -> Data {
            guard case let .bytes(value) = scope[index] else { throw ChannelNegotiationError.rejected }
            return value
        }
        let requests = try rows.map { row -> ChannelRequestCapability in
            guard case let .array(values) = row, values.count == 4,
                  case let .unsigned(kind) = values[0], case let .unsigned(wire) = values[1],
                  case let .unsigned(schema) = values[2] else { throw ChannelNegotiationError.rejected }
            return try ChannelRequestCapability(kind: kind, wireVersion: wire, schemaVersion: schema,
                features: numberSet(values[3], maximum: 64))
        }
        let result = try ChannelOffer(role: role,
            scope: ChannelScope(macID: scopeBytes(0), accountID: scopeBytes(1), phoneID: scopeBytes(2), enrollmentEpoch: scopeBytes(3)),
            nonce: nonce, envelopeVersions: numberSet(fields[4], maximum: 16), requests: requests,
            auditVersions: numberSet(fields[6], maximum: 16))
        try channelCheck(result.encode() == bytes)
        return result
    }
}

/// Session metadata, not authority to accept an operation.
public struct NegotiatedChannel: Sendable, CustomStringConvertible {
    public let envelopeVersion: UInt64
    public let sessionID: Data
    public let peer: ChannelOffer
    public var description: String { "NegotiatedChannel(redacted)" }
}

/// One owner for one fresh, mutually authenticated, enrollment-bound TLS connection.
/// The host supplies a fresh random nonce, enforces a deadline, and closes on enrollment changes.
/// Never feed relay metadata or bytes from another connection into this owner.
public final class ChannelNegotiation: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let local: ChannelOffer
    private let trustedMinimum: UInt64
    private var offerSent = false
    private var peer: ChannelOffer?
    private var result: NegotiatedChannel?
    private var confirmationSent = false
    private var peerConfirmed = false
    private var closed = false

    public init(local: ChannelOffer, trustedMinimum: UInt64) throws {
        try channelCheck(trustedMinimum > 0)
        self.local = local; self.trustedMinimum = trustedMinimum
    }
    public func offer() throws -> Data {
        try guarded {
            try channelCheck(!offerSent)
            let bytes = try local.encode(); offerSent = true; return bytes
        }
    }
    public func receiveOffer(_ bytes: Data) throws {
        try guarded {
            try channelCheck(offerSent && peer == nil)
            let remote = try ChannelOffer.decode(bytes)
            try channelCheck(remote.role != local.role && remote.scope == local.scope && remote.nonce != local.nonce)
            let version = try CompatibilityPolicy.envelopeVersion(local: local.envelopeVersions, peer: remote.envelopeVersions,
                trustedMinimum: trustedMinimum)
            let phone = local.role == .phone ? local : remote
            let mac = local.role == .mac ? local : remote
            let transcript = try DeterministicCBOR.encode(.map([
                0: .text("dev.remozio.approval.channel"), 1: .unsigned(1),
                2: .bytes(phone.encode()), 3: .bytes(mac.encode()), 4: .unsigned(version),
            ]), limits: CBORLimits(maxBytes: 131_200, maxDepth: 3, maxItems: 16))
            result = NegotiatedChannel(envelopeVersion: version, sessionID: Data(SHA256.hash(data: transcript)), peer: remote)
            peer = remote
        }
    }
    /// The Mac confirms only after checking the phone's confirmation. Send on the owned TLS connection.
    public func confirmation() throws -> Data {
        try guarded {
            try channelCheck(result != nil && !confirmationSent && (local.role == .phone || peerConfirmed))
            let bytes = try confirmationBytes(local.role); confirmationSent = true; return bytes
        }
    }
    public func receiveConfirmation(_ bytes: Data) throws {
        try guarded {
            try channelCheck(result != nil && !peerConfirmed && (local.role == .mac || confirmationSent))
            try channelCheck(bytes.count <= 128)
            try channelCheck(bytes == confirmationBytes(peer!.role))
            peerConfirmed = true
        }
    }
    public func confirmed() throws -> NegotiatedChannel {
        lock.lock(); defer { lock.unlock() }
        try channelCheck(!closed && confirmationSent && peerConfirmed)
        return result!
    }
    public func close() {
        lock.lock(); defer { lock.unlock() }
        closed = true; peer = nil; result = nil
    }
    private func confirmationBytes(_ role: ChannelRole) throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .unsigned(role.rawValue), 2: .bytes(result!.sessionID)]),
            limits: CBORLimits(maxBytes: 128, maxDepth: 2, maxItems: 8))
    }
    private func guarded<T>(_ block: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        try channelCheck(!closed)
        do { return try block() } catch { close(); throw error }
    }
}

private func offerLimits() throws -> CBORLimits { try CBORLimits(maxBytes: 65_536, maxDepth: 5, maxItems: 5000) }
private func numbers(_ values: Set<UInt64>) -> CBORValue { .array(values.sorted().map(CBORValue.unsigned)) }
private func numberSet(_ value: CBORValue?, maximum: Int) throws -> Set<UInt64> {
    guard case let .array(values) = value, values.count <= maximum else { throw ChannelNegotiationError.rejected }
    let result = try values.map { value -> UInt64 in
        guard case let .unsigned(number) = value else { throw ChannelNegotiationError.rejected }
        return number
    }
    try channelCheck(zip(result, result.dropFirst()).allSatisfy { $0 < $1 })
    return Set(result)
}
private func channelCheck(_ condition: Bool) throws { if !condition { throw ChannelNegotiationError.rejected } }
