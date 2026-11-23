import Foundation

/// Public phone claims only. A proposal grants no enrollment or request authority.
public struct PairingPhoneProposal: Sendable, CustomStringConvertible {
    public let phone: ChannelOffer
    public let transportKey: PairingKey
    public let decisionKey: PairingKey
    public let biometricKey: PairingKey
    public let replacement: PairingReplacement?
    public var description: String { "PairingPhoneProposal(redacted)" }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: 66_000, maxDepth: 3, maxItems: 24) } }
    public init(phone: ChannelOffer, transportKey: PairingKey, decisionKey: PairingKey, biometricKey: PairingKey,
                replacement: PairingReplacement? = nil) throws {
        guard phone.role == .phone, Set([transportKey.keyID, decisionKey.keyID, biometricKey.keyID]).count == 3,
              Set([transportKey.publicKey, decisionKey.publicKey, biometricKey.publicKey]).count == 3 else {
            throw PairingError.invalidTranscript
        }
        if let replacement {
            guard replacement.phoneID == phone.scope.phoneID, replacement.epoch != phone.scope.enrollmentEpoch else {
                throw PairingError.invalidTranscript
            }
        }
        self.phone = phone; self.transportKey = transportKey; self.decisionKey = decisionKey; self.biometricKey = biometricKey
        self.replacement = replacement
    }
    public func encode() throws -> Data {
        var fields: [UInt64: CBORValue] = [
            0: .text("dev.remozio.pairing.proposal"), 1: .unsigned(1), 2: .bytes(try phone.encode()),
            3: .array([transportKey, decisionKey, biometricKey].map { .array([.bytes($0.keyID), .bytes($0.publicKey)]) }),
        ]
        if let replacement {
            fields[1] = .unsigned(2)
            fields[4] = replacement.value
        }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }
    public func validate(_ transcript: PairingTranscript) throws {
        guard transcript.replacement == replacement, try transcript.phone.encode() == phone.encode(),
              transcript.transportKey.keyID == transportKey.keyID, transcript.transportKey.publicKey == transportKey.publicKey,
              transcript.decisionKey.keyID == decisionKey.keyID, transcript.decisionKey.publicKey == decisionKey.publicKey,
              transcript.biometricKey.keyID == biometricKey.keyID, transcript.biometricKey.publicKey == biometricKey.publicKey else {
            throw PairingError.invalidTranscript
        }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              f[0] == .text("dev.remozio.pairing.proposal"), case .bytes(let phone) = f[2],
              case .array(let keys) = f[3], keys.count == 3 else { throw PairingError.invalidTranscript }
        let replacement: PairingReplacement?
        switch f[1] {
        case .unsigned(1) where Set(f.keys) == Set(UInt64(0)...3):
            replacement = nil
        case .unsigned(2) where Set(f.keys) == Set(UInt64(0)...4):
            guard case .array(let row) = f[4], row.count == 2,
                  case .bytes(let phoneID) = row[0], case .bytes(let epoch) = row[1] else {
                throw PairingError.invalidTranscript
            }
            replacement = try PairingReplacement(phoneID: phoneID, epoch: epoch)
        default:
            throw PairingError.invalidTranscript
        }
        func key(_ index: Int) throws -> PairingKey {
            guard case .array(let row) = keys[index], row.count == 2,
                  case .bytes(let id) = row[0], case .bytes(let point) = row[1] else { throw PairingError.invalidTranscript }
            return try .init(keyID: id, publicKey: point)
        }
        let result = try Self(phone: ChannelOffer.decode(phone), transportKey: key(0), decisionKey: key(1), biometricKey: key(2), replacement: replacement)
        guard try result.encode() == bytes else { throw PairingError.invalidTranscript }; return result
    }
}
