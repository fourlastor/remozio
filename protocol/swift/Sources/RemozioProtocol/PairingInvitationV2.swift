#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

/// A short-lived invitation from an authenticated setup surface. Treat its serialized bytes as a credential.
public struct PairingInvitationV2: Sendable, CustomStringConvertible, CustomReflectable {
    public let invitation: PairingInvitation
    public let windowID: Data
    public let replacement: PairingReplacement?
    public let lifetimeMilliseconds: UInt64
    private let secret: Data

    public static let maximumBytes = 768
    public static let maximumLifetimeMilliseconds: UInt64 = 300_000
    public static let exporterLabel = "EXPORTER-dev.remozio.pairing.invitation/2"
    private static let prefix = "remozio-pairing:v2:"
    private static let maximumTextCharacters = prefix.utf8.count + (maximumBytes * 4 + 2) / 3
    private static let keyDomain = Data("dev.remozio.pairing.invitation-key/2".utf8)
    private static let proofDomain = "dev.remozio.pairing.invitation-proof/2"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 24) } }

    public var description: String { "PairingInvitationV2(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [Mirror.Child]()) }

    public init(invitation: PairingInvitation, windowID: Data, secret: Data,
                replacement: PairingReplacement? = nil, lifetimeMilliseconds: UInt64) throws {
        guard windowID.count == 16, secret.count == 32,
              (1...Self.maximumLifetimeMilliseconds).contains(lifetimeMilliseconds) else {
            throw PairingInvitationError.invalidInvitation
        }
        self.invitation = invitation; self.windowID = windowID; self.secret = secret
        self.replacement = replacement; self.lifetimeMilliseconds = lifetimeMilliseconds
    }

    /// A public discovery hint derived from the Authority's random window identifier.
    public static func bonjourInstanceName(windowID: Data) throws -> String {
        guard windowID.count == 16 else { throw PairingInvitationError.invalidInvitation }
        let input = Data("dev.remozio.pairing.bonjour-instance/2\u{0}".utf8) + windowID
        let suffix = SHA256.hash(data: input).prefix(16).map { String(format: "%02x", $0) }.joined()
        return "R2-" + suffix
    }

    private func publicFields() throws -> [UInt64: CBORValue] {
        let predecessor: CBORValue
        if let replacement {
            predecessor = .array([invitation.macID, invitation.accountID, replacement.phoneID, replacement.epoch].map(CBORValue.bytes))
        } else {
            predecessor = .null
        }
        return [0: .unsigned(2), 1: .bytes(try invitation.encode()), 2: .bytes(windowID),
                4: .unsigned(replacement == nil ? 0 : 1), 5: predecessor, 6: .unsigned(lifetimeMilliseconds)]
    }

    public func encode() throws -> Data {
        var fields = try publicFields()
        fields[3] = .bytes(secret)
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }

    public func exportText() throws -> String {
        Self.prefix + (try encode()).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...6), fields[0] == .unsigned(2),
              case .bytes(let publicBytes) = fields[1], case .bytes(let windowID) = fields[2],
              case .bytes(let secret) = fields[3], case .unsigned(let lifetime) = fields[6] else {
            throw PairingInvitationError.invalidInvitation
        }
        let invitation = try PairingInvitation.decode(publicBytes)
        let replacement: PairingReplacement?
        switch (fields[4], fields[5]) {
        case (.unsigned(0), .null):
            replacement = nil
        case (.unsigned(1), .array(let scope)):
            guard scope.count == 4, scope[0] == .bytes(invitation.macID), scope[1] == .bytes(invitation.accountID),
                  case .bytes(let phoneID) = scope[2], case .bytes(let epoch) = scope[3] else {
                throw PairingInvitationError.invalidInvitation
            }
            replacement = try PairingReplacement(phoneID: phoneID, epoch: epoch)
        default:
            throw PairingInvitationError.invalidInvitation
        }
        let result = try Self(invitation: invitation, windowID: windowID, secret: secret,
                              replacement: replacement, lifetimeMilliseconds: lifetime)
        guard try result.encode() == bytes else { throw PairingInvitationError.invalidInvitation }
        return result
    }

    public static func importText(_ text: String) throws -> Self {
        guard text.utf8.count <= maximumTextCharacters, text.hasPrefix(prefix) else {
            throw PairingInvitationError.invalidInvitation
        }
        let payload = text.dropFirst(prefix.count)
        guard !payload.isEmpty, payload.utf8.count % 4 != 1, payload.utf8.allSatisfy({ byte in
            (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 || byte == 95
        }) else { throw PairingInvitationError.invalidInvitation }
        let base64 = payload.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padded = base64 + String(repeating: "=", count: (4 - base64.utf8.count % 4) % 4)
        guard let bytes = Data(base64Encoded: padded) else { throw PairingInvitationError.invalidInvitation }
        let result = try decode(bytes)
        guard try result.exportText() == text else { throw PairingInvitationError.invalidInvitation }
        return result
    }

    func proofInput(proposal: PairingPhoneProposal, challenge: Data, exporter: Data) throws -> Data {
        let scope = proposal.phone.scope
        guard challenge.count == 32, exporter.count == 32,
              scope.macID == invitation.macID, scope.accountID == invitation.accountID, proposal.replacement == replacement,
              [proposal.transportKey, proposal.decisionKey, proposal.biometricKey].allSatisfy({ key in
                  key.publicKey != invitation.authorityPublicKey && key.publicKey != invitation.transportPublicKey
              }) else {
            throw PairingInvitationError.invalidInvitation
        }
        let publicBytes = try DeterministicCBOR.encode(.map(publicFields()), limits: Self.limits)
        return try DeterministicCBOR.encode(.array([
            .text(Self.proofDomain), .bytes(Data(SHA256.hash(data: publicBytes))),
            .bytes(challenge), .bytes(exporter), .bytes(Data(SHA256.hash(data: try proposal.encode()))),
        ]), limits: .init(maxBytes: 256, maxDepth: 1, maxItems: 6))
    }

    private func proofKey() -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: windowID,
                               info: Self.keyDomain, outputByteCount: 32)
    }

    public func proof(proposal: PairingPhoneProposal, challenge: Data, exporter: Data) throws -> Data {
        let input = try proofInput(proposal: proposal, challenge: challenge, exporter: exporter)
        return Data(HMAC<SHA256>.authenticationCode(for: input, using: proofKey()))
    }

    /// Checks possession alone. A thrown error rejects the proof.
    /// The Authority owns freshness, reservation and enrollment consent.
    public func verifiesProof(_ tag: Data, proposal: PairingPhoneProposal, challenge: Data, exporter: Data) throws -> Bool {
        guard tag.count == 32 else { return false }
        let input = try proofInput(proposal: proposal, challenge: challenge, exporter: exporter)
        return HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: input, using: proofKey())
    }
}
