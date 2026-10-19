package dev.remozio.protocol

/** Audit-only signature input. Parsing a batch and checking its expected scope are separate obligations. */
object AuditBatchSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        if (DeterministicCbor.decode(payload, payloadLimits) !is CborValue.Fields) {
            throw SigningInputException(SigningInputFailure.PAYLOAD_MUST_BE_MAP)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.audit"), 1uL to CborValue.Unsigned(wireVersion),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(payload),
        )), inputLimits)
    }
}

/** Uses the authority key selected from trusted enrollment, never a key from the batch. */
object AuditBatchSignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, canonicalPayload: ByteArray,
               payloadLimits: CborLimits, inputLimits: CborLimits): Boolean = P256Verification.verify(
        signature, publicKey, AuditBatchSigningInput.make(wireVersion, canonicalPayload, payloadLimits, inputLimits))
}
