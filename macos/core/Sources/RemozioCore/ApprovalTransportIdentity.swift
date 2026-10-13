import Foundation
import Darwin
import LocalAuthentication
import Security

/// Loads only the provisioned transport identity. Lookup failure does not change the configured custody path.
public enum ApprovalTransportIdentity {
    public static func load(configuration: ApprovalTransportConfiguration) throws -> SecIdentity {
        try configuration.requireNativeProcess()
        return try load(configuration: configuration, lookup: { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query, &result)
            return (status, result)
        })
    }

    static func load(configuration: ApprovalTransportConfiguration,
                     lookup: (CFDictionary) -> (OSStatus, CFTypeRef?),
                     readFile: (String, uid_t) throws -> Data = ProtectedServiceConfiguration.readServicePrivate) throws -> SecIdentity {
        let reference: Data
        switch configuration.identitySource {
        case .secureEnclaveKeychain(let value): reference = value
        case .protectedFile(let path):
            let bytes = try readFile(path, configuration.serviceUID)
            return try TransportFileIdentity.load(bytes: bytes, publicKeyInfo: configuration.identityPublicKeyInfo)
        }
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [CFString: Any] = [kSecClass: kSecClassIdentity,
            kSecMatchItemList: [reference], kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitOne, kSecUseAuthenticationContext: context]
        let (status, result) = lookup(query as CFDictionary)
        guard status == errSecSuccess, let result else { throw ApprovalTransportStartupError.identityUnavailable }
        guard CFGetTypeID(result) == SecIdentityGetTypeID() else { throw ApprovalTransportStartupError.invalidIdentity }
        let identity = result as! SecIdentity
        var key: SecKey?, certificate: SecCertificate?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key,
              SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate,
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256 else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
        try validate(key: key, certificate: certificate, publicKeyInfo: configuration.identityPublicKeyInfo)
        return identity
    }

    static func validate(key: SecKey, certificate: SecCertificate, publicKeyInfo: Data) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let publicKey = SecKeyCopyPublicKey(key),
              let certificateKey = SecCertificateCopyKey(certificate),
              let publicBytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let certificateBytes = SecKeyCopyExternalRepresentation(certificateKey, nil) as Data?,
              publicBytes == certificateBytes,
              try PinnedTLSPeer(subjectPublicKeyInfo: publicKeyInfo)
                .accepts(certificate: SecCertificateCopyData(certificate) as Data) else {
            throw ApprovalTransportStartupError.invalidIdentity
        }
    }
}
