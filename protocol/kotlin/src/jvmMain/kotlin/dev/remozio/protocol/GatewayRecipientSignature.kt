package dev.remozio.protocol

object GatewayRecipientSigningInput {
    fun make(wireVersion: ULong, kind: GatewayRecipientKind, canonicalPayload: ByteArray,
             payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        when (kind) {
            GatewayRecipientKind.ACTIVATION -> GatewayMappingActivation.decode(payload, payloadLimits)
            GatewayRecipientKind.PHONE_REVOCATION -> GatewayPhoneRevocation.decode(payload, payloadLimits)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text("dev.remozio.gateway"),
            1uL to CborValue.Unsigned(wireVersion), 2uL to CborValue.Unsigned(kind.wireValue),
            3uL to CborValue.Unsigned(kind.wireValue), 4uL to CborValue.Bytes(payload))), inputLimits)
    }
}

/** The operation is explicit. Select the root key from protected registration, never from control fields. */
object GatewayRecipientSignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, kind: GatewayRecipientKind,
               canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): Boolean =
        P256Verification.verify(signature, publicKey,
            GatewayRecipientSigningInput.make(wireVersion, kind, canonicalPayload, payloadLimits, inputLimits))
}
