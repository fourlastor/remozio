#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

enum P256Verification {
    static func verify(signature: Data, publicKey: Data, input: Data) -> Bool {
        guard signature.count == 64, publicKey.count == 65, publicKey.first == 4 else { return false }
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let value = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(value, for: input)
    }
}
