#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
import Foundation

/// Verify with the public key and context selected from trusted enrollment and retained request state.
public enum ApprovalSignature {
    public static func verify(
        signature: Data,
        publicKey: Data,
        wireVersion: UInt64,
        messageType: ApprovalMessageType,
        purpose: SigningPurpose,
        canonicalPayload: Data,
        payloadLimits: CBORLimits,
        inputLimits: CBORLimits
    ) throws -> Bool {
        let input = try SigningInput.make(wireVersion: wireVersion, messageType: messageType, purpose: purpose,
            canonicalPayload: canonicalPayload, payloadLimits: payloadLimits, inputLimits: inputLimits)
        return P256Verification.verify(signature: signature, publicKey: publicKey, input: input)
    }
}
