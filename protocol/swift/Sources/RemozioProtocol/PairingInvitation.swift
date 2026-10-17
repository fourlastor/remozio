#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

public enum PairingInvitationError: Error { case invalidInvitation, mismatchedTranscript }

/// Public bootstrap pins. Importing these claims does not authenticate the Mac or authorize enrollment.
public struct PairingInvitation: Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let label: String
    public let authorityPublicKey: Data
    public let transportPublicKey: Data
    public let minimumEnvelopeVersion: UInt64
    public var description: String { "PairingInvitation(redacted)" }
    private static let prefix = "remozio-pairing:v1:"
    private static let maximumBytes = 512
    private static let maximumTextCharacters = prefix.count + (maximumBytes * 4 + 2) / 3
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 1, maxItems: 15) } }

    public init(macID: Data, accountID: Data, label: String, authorityPublicKey: Data,
                transportPublicKey: Data, minimumEnvelopeVersion: UInt64) throws {
        guard macID.count == 16, accountID.count == 16, (1...200).contains(label.utf8.count),
              label.unicodeScalars.contains(where: { $0.value != 32 }),
              label.unicodeScalars.allSatisfy({ scalar in
                  let n = scalar.value
                  return n >= 32 && !(127...159).contains(n) && !(0x2028...0x202e).contains(n) &&
                      !(0x2066...0x2069).contains(n) && n != 0x200e && n != 0x200f
              }), minimumEnvelopeVersion > 0, authorityPublicKey != transportPublicKey else {
            throw PairingInvitationError.invalidInvitation
        }
        try pairingPoint(authorityPublicKey); try pairingPoint(transportPublicKey)
        self.macID = macID; self.accountID = accountID; self.label = label
        self.authorityPublicKey = authorityPublicKey; self.transportPublicKey = transportPublicKey
        self.minimumEnvelopeVersion = minimumEnvelopeVersion
    }

    public func encode() throws -> Data {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID),
            3: .text(label), 4: .bytes(authorityPublicKey), 5: .bytes(transportPublicKey),
            6: .unsigned(minimumEnvelopeVersion)]), limits: Self.limits)
    }

    /// QR and pasted text use the same bounded, unpadded base64url payload. This is not a browser URL.
    public func exportText() throws -> String {
        Self.prefix + (try encode()).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    /// Compare the complete fingerprint through an independently authenticated Mac setup surface.
    /// This is not an abbreviated verification code or evidence of freshness.
    public func fingerprint() throws -> String {
        let input = try DeterministicCBOR.encode(.map([0: .text("dev.remozio.pairing.invitation"),
            1: .unsigned(1), 2: .bytes(encode())]), limits: .init(maxBytes: 576, maxDepth: 1, maxItems: 7))
        let bytes = Array(SHA256.hash(data: input))
        return stride(from: 0, to: bytes.count, by: 4).map { start in
            bytes[start..<start + 4].map { String(format: "%02X", $0) }.joined()
        }.joined(separator: "-")
    }

    /// A consistency check only. The host still verifies the complete fresh transcript and peer identity.
    public func validateMacClaims(in transcript: PairingTranscript) throws {
        guard transcript.phone.scope.macID == macID, transcript.phone.scope.accountID == accountID,
              transcript.macAuthorityKey == authorityPublicKey, transcript.macTransportKey == transportPublicKey,
              transcript.minimumEnvelopeVersion == minimumEnvelopeVersion else {
            throw PairingInvitationError.mismatchedTranscript
        }
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(f.keys) == Set(UInt64(0)...6), f[0] == .unsigned(1),
              case .bytes(let mac) = f[1], case .bytes(let account) = f[2], case .text(let label) = f[3],
              case .bytes(let authority) = f[4], case .bytes(let transport) = f[5],
              case .unsigned(let minimum) = f[6] else { throw PairingInvitationError.invalidInvitation }
        let result = try Self(macID: mac, accountID: account, label: label, authorityPublicKey: authority,
            transportPublicKey: transport, minimumEnvelopeVersion: minimum)
        guard try result.encode() == bytes else { throw PairingInvitationError.invalidInvitation }; return result
    }

    public static func importText(_ text: String) throws -> Self {
        guard text.utf8.count <= maximumTextCharacters, text.hasPrefix(prefix) else {
            throw PairingInvitationError.invalidInvitation
        }
        let payload = text.dropFirst(prefix.count)
        guard !payload.isEmpty, payload.utf8.allSatisfy({ n in
            (65...90).contains(n) || (97...122).contains(n) || (48...57).contains(n) || n == 45 || n == 95
        }), payload.count % 4 != 1 else { throw PairingInvitationError.invalidInvitation }
        let encoded = String(payload).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padded = encoded + String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded), bytes.count <= maximumBytes else {
            throw PairingInvitationError.invalidInvitation
        }
        let result = try decode(bytes)
        guard try result.exportText() == text else { throw PairingInvitationError.invalidInvitation }; return result
    }
}
