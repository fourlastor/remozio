package dev.remozio.protocol

/** Verify with the public key and context selected from trusted enrollment and retained request state. */
object ApprovalSignature {
    fun verify(
        signature: ByteArray,
        publicKey: ByteArray,
        wireVersion: ULong,
        messageType: ApprovalMessageType,
        purpose: SigningPurpose,
        canonicalPayload: ByteArray,
        payloadLimits: CborLimits,
        inputLimits: CborLimits,
    ): Boolean {
        val input = SigningInput.make(wireVersion, messageType, purpose, canonicalPayload, payloadLimits, inputLimits)
        return P256Verification.verify(signature, publicKey, input)
    }
}
