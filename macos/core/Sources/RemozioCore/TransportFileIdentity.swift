import CryptoKit
import Foundation
import RemozioProtocol
import Security

/// Explicit transport-only custody. Authority and credential recipient loaders do not use this format.
enum TransportFileIdentity {
    struct Created {
        let encoded: Data
        let subjectPublicKeyInfo: Data
        let publicKeyX963: Data
    }

    /// Creates the explicitly selected transport file format. It writes no file and performs no fallback.
    static func create(notValidBefore: Date, notValidAfter: Date) throws -> Created {
        let privateKey = P256.Signing.PrivateKey()
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256]
        guard let native = SecKeyCreateWithData(privateKey.x963Representation as CFData,
                                                attributes as CFDictionary, nil) else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
        let certificate = try TransportTLSCertificate.issue(key: native,
            notValidBefore: notValidBefore, notValidAfter: notValidAfter)
        let encoded = try DeterministicCBOR.encode(.map([0: .unsigned(1),
            1: .text("remozio-transport-identity"), 2: .bytes(privateKey.x963Representation),
            3: .bytes(certificate)]), limits: CBORLimits(maxBytes: 16_384, maxDepth: 1, maxItems: 9))
        return Created(encoded: encoded, subjectPublicKeyInfo: privateKey.publicKey.derRepresentation,
            publicKeyX963: privateKey.publicKey.x963Representation)
    }

    static func load(bytes: Data, publicKeyInfo: Data) throws -> SecIdentity {
        let limits = try CBORLimits(maxBytes: 16_384, maxDepth: 1, maxItems: 9)
        guard let decoded = try? DeterministicCBOR.decode(bytes, limits: limits), case .map(let fields) = decoded,
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .unsigned(1),
              fields[1] == .text("remozio-transport-identity"),
              case .bytes(let privateBytes) = fields[2], privateBytes.count == 97,
              let privateKey = try? P256.Signing.PrivateKey(x963Representation: privateBytes),
              privateKey.x963Representation == privateBytes,
              case .bytes(let certificateBytes) = fields[3], (1...8192).contains(certificateBytes.count),
              let certificate = SecCertificateCreateWithData(nil, certificateBytes as CFData) else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256]
        guard let key = SecKeyCreateWithData(privateBytes as CFData, attributes as CFDictionary, nil) else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
        try ApprovalTransportIdentity.validate(key: key, certificate: certificate, publicKeyInfo: publicKeyInfo)
        guard let identity = SecIdentityCreate(nil, certificate, key) else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
        return identity
    }
}
