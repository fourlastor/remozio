package dev.remozio.protocol

/** This domain permits a token-possession probe, never recipient activation or an approval action. */
object GatewayTokenCandidateSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        GatewayTokenCandidate.decode(payload, payloadLimits)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.gateway"), 1uL to CborValue.Unsigned(wireVersion),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(payload),
        )), inputLimits)
    }
}

/** Select the root key from authenticated gateway registration, never from the incoming candidate. */
object GatewayTokenCandidateSignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, canonicalPayload: ByteArray,
               payloadLimits: CborLimits, inputLimits: CborLimits): Boolean = P256Verification.verify(
        signature, publicKey, GatewayTokenCandidateSigningInput.make(wireVersion, canonicalPayload, payloadLimits, inputLimits))
}
