package dev.remozio.protocol

object GatewaySubmissionSigningInput {
    fun make(wireVersion: ULong, kind: GatewaySubmissionKind, canonicalPayload: ByteArray,
             payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        val control = GatewaySubmissionControl.decode(payload, payloadLimits)
        if (control.kind != kind) throw GatewayTokenException(GatewayTokenFailure.INVALID_CONTROL)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text("dev.remozio.gateway"),
            1uL to CborValue.Unsigned(wireVersion), 2uL to CborValue.Unsigned(kind.wireValue),
            3uL to CborValue.Unsigned(kind.wireValue), 4uL to CborValue.Bytes(payload))), inputLimits)
    }
}

/** Select the Root key from protected registration. A submission credential cannot sign its own replacement or revocation. */
object GatewaySubmissionSignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, kind: GatewaySubmissionKind,
               canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): Boolean =
        P256Verification.verify(signature, publicKey,
            GatewaySubmissionSigningInput.make(wireVersion, kind, canonicalPayload, payloadLimits, inputLimits))
}
