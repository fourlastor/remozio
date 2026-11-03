#if os(Linux)
import Glibc
#endif
import CPairingTLS
import Crypto
import Foundation
import PairingCommitState
import RemozioProtocol

public enum PairingIdentityError: Error, Equatable {
    case notInitialized
    case corruptIdentity
    case invalidLabel
    case certificate(status: UInt32)
}

/// Software-key experiment identity for one Linux peer: random Mac and account IDs plus two P-256 keys. The private
/// keys sit in the commit store's private directory. Any process of the same user can read them. This is not the
/// protected host identity and gives no claim about key custody.
public struct PairingIdentity: Sendable {
    public static let minimumEnvelopeVersion: UInt64 = 1
    public let macID: Data
    public let accountID: Data
    public let label: String
    let transportKey: P256.Signing.PrivateKey
    let authorityKey: P256.Signing.PrivateKey

    public var transportPublicKey: Data { transportKey.publicKey.x963Representation }
    public var authorityPublicKey: Data { authorityKey.publicKey.x963Representation }

    private struct Stored: Codable {
        var format: Int
        var macID: Data
        var accountID: Data
        var label: String
        var transportKey: Data
        var authorityKey: Data
    }

    init(macID: Data, accountID: Data, label: String, transportKey: P256.Signing.PrivateKey,
         authorityKey: P256.Signing.PrivateKey) throws {
        guard macID.count == 16, accountID.count == 16,
              transportKey.publicKey.x963Representation != authorityKey.publicKey.x963Representation else {
            throw PairingIdentityError.corruptIdentity
        }
        self.macID = macID; self.accountID = accountID; self.label = label
        self.transportKey = transportKey; self.authorityKey = authorityKey
        // The invitation applies the label rules; an identity that cannot export one is refused here.
        _ = try invitation()
    }

    /// Generates fresh IDs and keys and publishes them once. Throws `PairingCommitError.identityExists` if the store
    /// already holds an identity.
    @discardableResult
    public static func create(in store: PairingCommitStore, label: String) throws -> PairingIdentity {
        let identity: PairingIdentity
        do {
            identity = try PairingIdentity(macID: randomBytes(16), accountID: randomBytes(16), label: label,
                transportKey: P256.Signing.PrivateKey(), authorityKey: P256.Signing.PrivateKey())
        } catch PairingInvitationError.invalidInvitation { throw PairingIdentityError.invalidLabel }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try store.createIdentity(encoder.encode(Stored(format: 1, macID: identity.macID, accountID: identity.accountID,
            label: identity.label, transportKey: identity.transportKey.rawRepresentation,
            authorityKey: identity.authorityKey.rawRepresentation)))
        return identity
    }

    public static func load(from store: PairingCommitStore) throws -> PairingIdentity {
        guard let bytes = try store.identity() else { throw PairingIdentityError.notInitialized }
        guard let stored = try? JSONDecoder().decode(Stored.self, from: bytes), stored.format == 1,
              let transport = try? P256.Signing.PrivateKey(rawRepresentation: stored.transportKey),
              let authority = try? P256.Signing.PrivateKey(rawRepresentation: stored.authorityKey),
              let identity = try? PairingIdentity(macID: stored.macID, accountID: stored.accountID, label: stored.label,
                                                  transportKey: transport, authorityKey: authority) else {
            throw PairingIdentityError.corruptIdentity
        }
        return identity
    }

    public func invitation() throws -> PairingInvitation {
        try PairingInvitation(macID: macID, accountID: accountID, label: label, authorityPublicKey: authorityPublicKey,
                              transportPublicKey: transportPublicKey, minimumEnvelopeVersion: Self.minimumEnvelopeVersion)
    }

    /// The DNS-SD instance name the Android client looks for: `R-` and the unpadded base64url Mac and account IDs.
    public var serviceName: String { "R-\(Self.base64URL(macID))-\(Self.base64URL(accountID))" }
    public static let serviceType = "_remozio-pairing._tcp"

    /// A fresh self-signed leaf for the persisted transport key, valid from a minute ago for `lifetimeSeconds`.
    /// The phone pins the key, not the certificate, so each run may present a new one.
    public func transportCertificate(nowUnixSeconds: Int64, lifetimeSeconds: Int64) throws -> (certificate: Data, key: Data) {
        let key = transportKey.derRepresentation
        var output: UnsafeMutablePointer<UInt8>?
        var length = 0
        let status = key.withUnsafeBytes { buffer in
            remozio_tls_issue_certificate(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count,
                                          nowUnixSeconds - 60, nowUnixSeconds + lifetimeSeconds, &output, &length)
        }
        guard status == REMOZIO_TLS_OK, let output else { throw PairingIdentityError.certificate(status: status.rawValue) }
        defer { remozio_tls_free(output) }
        return (Data(bytes: output, count: length), key)
    }

    /// Signs the MAC_COMMIT receipt for a committed transcript and checks the signature before returning it.
    func receiptSignature(for transcript: PairingTranscript) throws -> Data {
        let signature = try authorityKey.signature(for: transcript.signingInput(purpose: .macCommit)).rawRepresentation
        guard try transcript.verify(signature: signature, publicKey: authorityPublicKey, purpose: .macCommit) else {
            throw PairingIdentityError.corruptIdentity
        }
        return signature
    }

    static func base64URL(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

func randomBytes(_ count: Int) -> Data {
    var generator = SystemRandomNumberGenerator()
    return Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) })
}
