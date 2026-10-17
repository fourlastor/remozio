#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

public enum PairingError: Error { case invalidTranscript }

/// Public key material. Local aliases and credentials are excluded.
public struct PairingKey: Sendable, CustomStringConvertible {
    public let keyID: Data
    public let publicKey: Data
    public init(keyID: Data, publicKey: Data) throws {
        try pairingCheck(keyID.count == 16)
        try pairingPoint(publicKey)
        self.keyID = keyID; self.publicKey = publicKey
    }
    fileprivate var value: CBORValue { .array([.bytes(keyID), .bytes(publicKey)]) }
    public var description: String { "PairingKey(redacted)" }
}

public struct PairingReplacement: Sendable, CustomStringConvertible {
    public let phoneID: Data
    public let epoch: Data
    public init(phoneID: Data, epoch: Data) throws {
        try pairingCheck(phoneID.count == 16 && epoch.count == 16)
        self.phoneID = phoneID; self.epoch = epoch
    }
    fileprivate var value: CBORValue { .array([.bytes(phoneID), .bytes(epoch)]) }
    public var description: String { "PairingReplacement(redacted)" }
}

public enum PairingProofPurpose: UInt64, Sendable { case phoneBiometric = 0, macCommit = 1 }

/// Untrusted setup claims. Parsing or signature verification does not authorize enrollment.
public struct PairingTranscript: Sendable, CustomStringConvertible {
    public let setupID: Data
    public let challenge: Data
    public let phone: ChannelOffer
    public let mac: ChannelOffer
    public let minimumEnvelopeVersion: UInt64
    public let selectedEnvelopeVersion: UInt64
    public let macAuthorityKey: Data
    public let macTransportKey: Data
    public let transportKey: PairingKey
    public let decisionKey: PairingKey
    public let biometricKey: PairingKey
    public let enrollmentTag: Data
    public let replacement: PairingReplacement?
    public let expectedTrustRevision: Data
    public let issuedAtUnixMillis: UInt64
    public let expiresAtUnixMillis: UInt64

    public init(setupID: Data, challenge: Data, phone: ChannelOffer, mac: ChannelOffer,
                minimumEnvelopeVersion: UInt64, selectedEnvelopeVersion: UInt64,
                macAuthorityKey: Data, macTransportKey: Data, transportKey: PairingKey,
                decisionKey: PairingKey, biometricKey: PairingKey, enrollmentTag: Data,
                replacement: PairingReplacement?, expectedTrustRevision: Data,
                issuedAtUnixMillis: UInt64, expiresAtUnixMillis: UInt64) throws {
        try pairingCheck(setupID.count == 16 && challenge.count == 32 && enrollmentTag.count == 32 && expectedTrustRevision.count == 16)
        try pairingCheck(phone.role == .phone && mac.role == .mac && phone.scope == mac.scope && phone.nonce != mac.nonce)
        try pairingCheck(minimumEnvelopeVersion > 0 && selectedEnvelopeVersion ==
            CompatibilityPolicy.envelopeVersion(local: phone.envelopeVersions, peer: mac.envelopeVersions, trustedMinimum: minimumEnvelopeVersion))
        try pairingCheck(expiresAtUnixMillis > issuedAtUnixMillis)
        try pairingPoint(macAuthorityKey); try pairingPoint(macTransportKey)
        let keys = [transportKey, decisionKey, biometricKey]
        try pairingCheck(Set(keys.map(\.keyID)).count == 3)
        try pairingCheck(Set(keys.map(\.publicKey) + [macAuthorityKey, macTransportKey]).count == 5)
        if let replacement {
            guard case let .map(fields) = try DeterministicCBOR.decode(phone.encode(), limits: CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 20_000)),
                  case let .array(scope) = fields[2] else { throw PairingError.invalidTranscript }
            try pairingCheck(scope[3] != .bytes(replacement.epoch))
        }
        self.setupID = setupID; self.challenge = challenge; self.phone = phone; self.mac = mac
        self.minimumEnvelopeVersion = minimumEnvelopeVersion; self.selectedEnvelopeVersion = selectedEnvelopeVersion
        self.macAuthorityKey = macAuthorityKey; self.macTransportKey = macTransportKey
        self.transportKey = transportKey; self.decisionKey = decisionKey; self.biometricKey = biometricKey
        self.enrollmentTag = enrollmentTag; self.replacement = replacement; self.expectedTrustRevision = expectedTrustRevision
        self.issuedAtUnixMillis = issuedAtUnixMillis; self.expiresAtUnixMillis = expiresAtUnixMillis
    }
    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(setupID), 2: .bytes(challenge),
            3: .bytes(phone.encode()), 4: .bytes(mac.encode()),
            5: .unsigned(minimumEnvelopeVersion), 6: .unsigned(selectedEnvelopeVersion),
            7: .bytes(macAuthorityKey), 8: .bytes(macTransportKey),
            9: .array([transportKey, decisionKey, biometricKey].map(\.value)),
            10: .bytes(enrollmentTag), 11: replacement?.value ?? .null,
            12: .bytes(expectedTrustRevision), 13: .unsigned(issuedAtUnixMillis), 14: .unsigned(expiresAtUnixMillis),
        ]), limits: pairingLimits())
    }
    public func digest() throws -> Data { Data(SHA256.hash(data: try signingInput(purpose: .phoneBiometric))) }
    /// Compare this code on independently authenticated setup surfaces. It never replaces the complete confirmation digest.
    public func verificationCode() throws -> String {
        let alphabet = Array("23456789ABCDEFGHJKLMNPQRSTUVWXYZ")
        let bytes = try digest()
        var symbols: [Character] = []
        for start in stride(from: 0, to: 100, by: 5) {
            var value = 0
            for bit in start..<start + 5 {
                value <<= 1
                value |= Int((bytes[bit / 8] >> (7 - bit % 8)) & 1)
            }
            symbols.append(alphabet[value])
        }
        return stride(from: 0, to: symbols.count, by: 5)
            .map { String(symbols[$0..<min($0 + 5, symbols.count)]) }.joined(separator: " ")
    }
    public func signingInput(purpose: PairingProofPurpose) throws -> Data {
        try DeterministicCBOR.encode(.map([
            0: .text("dev.remozio.pairing"), 1: .unsigned(1), 2: .unsigned(purpose.rawValue), 3: .bytes(encode()),
        ]), limits: CBORLimits(maxBytes: 132_096, maxDepth: 3, maxItems: 16))
    }
    public func verify(signature: Data, publicKey: Data, purpose: PairingProofPurpose) throws -> Bool {
        P256Verification.verify(signature: signature, publicKey: publicKey, input: try signingInput(purpose: purpose))
    }
    public var description: String { "PairingTranscript(redacted)" }
    public static func decode(_ bytes: Data) throws -> PairingTranscript {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: pairingLimits()),
              Set(f.keys) == Set(0...UInt64(14)), f[0] == .unsigned(1),
              case let .array(keys) = f[9], keys.count == 3 else { throw PairingError.invalidTranscript }
        func b(_ k: UInt64) throws -> Data {
            guard case let .bytes(v) = f[k] else { throw PairingError.invalidTranscript }; return v
        }
        func u(_ k: UInt64) throws -> UInt64 {
            guard case let .unsigned(v) = f[k] else { throw PairingError.invalidTranscript }; return v
        }
        func pair(_ value: CBORValue?) throws -> (Data, Data) {
            guard case let .array(row) = value, row.count == 2,
                  case let .bytes(a) = row[0], case let .bytes(b) = row[1] else { throw PairingError.invalidTranscript }
            return (a, b)
        }
        func key(_ index: Int) throws -> PairingKey {
            let (id, point) = try pair(keys[index]); return try PairingKey(keyID: id, publicKey: point)
        }
        let replacement: PairingReplacement?
        if f[11] == .null { replacement = nil }
        else { let (id, epoch) = try pair(f[11]); replacement = try PairingReplacement(phoneID: id, epoch: epoch) }
        let result = try PairingTranscript(setupID: b(1), challenge: b(2), phone: ChannelOffer.decode(b(3)), mac: ChannelOffer.decode(b(4)),
            minimumEnvelopeVersion: u(5), selectedEnvelopeVersion: u(6), macAuthorityKey: b(7), macTransportKey: b(8),
            transportKey: key(0), decisionKey: key(1), biometricKey: key(2), enrollmentTag: b(10), replacement: replacement,
            expectedTrustRevision: b(12), issuedAtUnixMillis: u(13), expiresAtUnixMillis: u(14))
        try pairingCheck(result.encode() == bytes)
        return result
    }
}
private func pairingCheck(_ condition: Bool) throws { if !condition { throw PairingError.invalidTranscript } }
func pairingPoint(_ bytes: Data) throws {
    try pairingCheck(bytes.count == 65 && bytes.first == 4)
    _ = try P256.Signing.PublicKey(x963Representation: bytes)
}
private func pairingLimits() throws -> CBORLimits { try CBORLimits(maxBytes: 132_000, maxDepth: 4, maxItems: 80) }
