package dev.remozio.protocol

enum class RootUpdateSchedulingChallengeFailure { INVALID_FIELDS, UNSUPPORTED_SCHEMA, INVALID_NONCE }
class RootUpdateSchedulingChallengeException(val reason: RootUpdateSchedulingChallengeFailure) : IllegalArgumentException(reason.name)

/** The Root binds one scheduling control to the phone's fresh query. This response cannot authorize a target action. */
class RootUpdateSchedulingChallenge(queryNonce: ByteArray, canonicalControl: ByteArray, limits: CborLimits) {
    private val nonce = run {
        if (queryNonce.size != 32)
            throw RootUpdateSchedulingChallengeException(RootUpdateSchedulingChallengeFailure.INVALID_NONCE)
        CborValue.Bytes(queryNonce)
    }
    private val body = run {
        if (canonicalControl.size > limits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        CborValue.Bytes(canonicalControl)
    }
    init { UpdateSchedulingControl.decode(body.copyBytes(), limits) }
    val queryNonce: ByteArray get() = nonce.copyBytes()
    val canonicalControl: ByteArray get() = body.copyBytes()
    override fun toString() = "RootUpdateSchedulingChallenge(redacted)"

    fun encode(limits: CborLimits): ByteArray {
        UpdateSchedulingControl.decode(body.copyBytes(), limits)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to nonce, 2uL to body,
        )), limits)
    }

    companion object {
        fun decode(payload: ByteArray, limits: CborLimits): RootUpdateSchedulingChallenge {
            val fields = (DeterministicCbor.decode(payload, limits) as? CborValue.Fields)?.values
                ?: throw RootUpdateSchedulingChallengeException(RootUpdateSchedulingChallengeFailure.INVALID_FIELDS)
            if (fields.keys != setOf(0uL, 1uL, 2uL))
                throw RootUpdateSchedulingChallengeException(RootUpdateSchedulingChallengeFailure.INVALID_FIELDS)
            if (fields[0u] != CborValue.Unsigned(1u))
                throw RootUpdateSchedulingChallengeException(RootUpdateSchedulingChallengeFailure.UNSUPPORTED_SCHEMA)
            val nonce = (fields[1u] as? CborValue.Bytes)?.copyBytes()
                ?: throw RootUpdateSchedulingChallengeException(RootUpdateSchedulingChallengeFailure.INVALID_NONCE)
            val body = (fields[2u] as? CborValue.Bytes)?.copyBytes()
                ?: throw RootUpdateSchedulingChallengeException(RootUpdateSchedulingChallengeFailure.INVALID_FIELDS)
            return RootUpdateSchedulingChallenge(nonce, body, limits)
        }
    }
}

object RootUpdateSchedulingChallengeSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val captured = canonicalPayload.copyOf()
        RootUpdateSchedulingChallenge.decode(captured, payloadLimits)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.update-scheduling-challenge"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(captured),
        )), inputLimits)
    }
}

/** The phone selects its enrolled Root key. It must match the query and displayed choice and enforce the original lifetime. */
object RootUpdateSchedulingChallengeSignature {
    fun verify(signature: ByteArray, authorityPublicKey: ByteArray, wireVersion: ULong, canonicalPayload: ByteArray,
               payloadLimits: CborLimits, inputLimits: CborLimits): Boolean = P256Verification.verify(
        signature, authorityPublicKey,
        RootUpdateSchedulingChallengeSigningInput.make(wireVersion, canonicalPayload, payloadLimits, inputLimits))
}
