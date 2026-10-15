import CryptoKit
import Foundation
import Security
import X509

enum TransportTLSCertificateError: Error, Equatable { case invalidKey, invalidValidity, invalidCertificate }

/// Issues a transport leaf through its native key. It exports only the public key.
/// The caller selects storage and validity. Issuance never changes the key custody mode.
enum TransportTLSCertificate {
    static func issue(key: SecKey, notValidBefore: Date, notValidAfter: Date) throws -> Data {
        let before = notValidBefore.timeIntervalSince1970, after = notValidAfter.timeIntervalSince1970
        // Keep the encoded interval inside the requested interval, with at least one whole second.
        guard before.isFinite, after.isFinite, before >= -62_135_596_800, after < 253_402_300_800,
              after.rounded(.down) > before.rounded(.up) else {
            throw TransportTLSCertificateError.invalidValidity
        }
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256),
              let publicKey = SecKeyCopyPublicKey(key),
              let publicBytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw TransportTLSCertificateError.invalidKey
        }
        let pin = try P256.Signing.PublicKey(x963Representation: publicBytes).derRepresentation
        let signer = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("Remozio transport") }
        let certificate = try Certificate(version: .v3, serialNumber: .init(), publicKey: signer.publicKey,
            notValidBefore: Date(timeIntervalSince1970: before.rounded(.up)),
            notValidAfter: Date(timeIntervalSince1970: after.rounded(.down)), issuer: name, subject: name,
            signatureAlgorithm: .ecdsaWithSHA256, extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth, .clientAuth])
            }, issuerPrivateKey: signer)
        let native = try SecCertificate.makeWithCertificate(certificate)
        let bytes = SecCertificateCopyData(native) as Data
        guard certificate.publicKey.isValidSignature(certificate.signature, for: certificate),
              try Certificate(native) == certificate,
              try PinnedTLSPeer(subjectPublicKeyInfo: pin).accepts(certificate: bytes,
                  at: Date(timeIntervalSince1970: before.rounded(.up))) else {
            throw TransportTLSCertificateError.invalidCertificate
        }
        return bytes
    }
}
