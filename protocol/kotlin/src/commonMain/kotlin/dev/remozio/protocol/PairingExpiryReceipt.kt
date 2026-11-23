package dev.remozio.protocol

enum class PairingExpiryReason(val tag: ULong) {
    DEADLINE_ELAPSED(0u),
    RETIRED_INCARNATION(1u),
}

/** A terminal no-commit result. Verification requires the exact locally retained re-pair transcript. */
class PairingExpiryReceipt private constructor(private val claims: Claims, signature: ByteArray) {
    val signature = CborValue.Bytes(signature)
    val setupID: CborValue.Bytes get() = claims.setupID
    val reason: PairingExpiryReason get() = claims.reason

    init { require(this.signature.size == 64) }

    constructor(transcript: PairingTranscript, reason: PairingExpiryReason, signature: ByteArray) :
        this(Claims.fromTranscript(transcript, reason), signature)

    fun verify(transcript: PairingTranscript): Boolean {
        val predecessor = transcript.replacement ?: return false
        if (predecessor.phoneID != transcript.phone.scope.value.values[2]) return false
        if (claims != Claims.fromTranscript(transcript, reason)) return false
        return P256Verification.verify(signature.copyBytes(), transcript.macAuthorityKey.copyBytes(), claims.encode())
    }

    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Bytes(claims.encode()), 1uL to signature,
    )), LIMITS)

    override fun toString() = "PairingExpiryReceipt(redacted)"

    companion object {
        const val MAXIMUM_BYTES = 1_024
        private const val DOMAIN = "dev.remozio.pairing.expired-without-commit"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 1, 8)

        fun signingInput(transcript: PairingTranscript, reason: PairingExpiryReason): ByteArray =
            Claims.fromTranscript(transcript, reason).encode()

        fun decode(bytes: ByteArray): PairingExpiryReceipt {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: error("Invalid expiry receipt")
            require(fields.keys == setOf(0uL, 1uL))
            val input = (fields[0uL] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid expiry receipt")
            val signature = (fields[1uL] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid expiry receipt")
            return PairingExpiryReceipt(Claims.decode(input), signature).also {
                require(it.encode().contentEquals(bytes))
            }
        }
    }

    private data class Claims(
        val setupID: CborValue.Bytes,
        val transcriptDigest: CborValue.Bytes,
        val scope: ChannelScope,
        val predecessorEpoch: CborValue.Bytes,
        val revision: CborValue.Bytes,
        val expiry: ULong,
        val reason: PairingExpiryReason,
    ) {
        init {
            require(setupID.size == 16 && transcriptDigest.size == 32 && predecessorEpoch.size == 16 &&
                predecessorEpoch != scope.value.values[3] && revision.size == 16 && expiry > 0uL)
        }

        fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to setupID, 3uL to transcriptDigest, 4uL to scope.value, 5uL to predecessorEpoch,
            6uL to revision, 7uL to CborValue.Unsigned(expiry), 8uL to CborValue.Unsigned(reason.tag),
        )), LIMITS)

        companion object {
            private val LIMITS = CborLimits(512, 2, 32)

            fun fromTranscript(transcript: PairingTranscript, reason: PairingExpiryReason): Claims {
                val scope = transcript.phone.scope
                val predecessor = requireNotNull(transcript.replacement)
                require(predecessor.phoneID == scope.value.values[2])
                return Claims(transcript.setupID, CborValue.Bytes(transcript.digest()), scope, predecessor.epoch,
                    transcript.expectedTrustRevision, transcript.expiresAtUnixMillis, reason)
            }

            fun decode(input: ByteArray): Claims {
                val fields = (DeterministicCbor.decode(input, LIMITS) as? CborValue.Fields)?.values
                    ?: error("Invalid expiry receipt")
                require(fields.keys == (0uL..8uL).toSet() && fields[0uL] == CborValue.Text(DOMAIN) &&
                    fields[1uL] == CborValue.Unsigned(1u))
                fun field(key: ULong) = fields[key] as? CborValue.Bytes ?: error("Invalid expiry receipt")
                val scope = (fields[4uL] as? CborValue.ArrayValue)?.values ?: error("Invalid expiry receipt")
                require(scope.size == 4)
                fun scopeBytes(index: Int) = (scope[index] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid expiry receipt")
                val expiry = (fields[7uL] as? CborValue.Unsigned)?.value ?: error("Invalid expiry receipt")
                val reason = PairingExpiryReason.entries.singleOrNull { fields[8uL] == CborValue.Unsigned(it.tag) }
                    ?: error("Invalid expiry receipt")
                return Claims(field(2uL), field(3uL), ChannelScope(scopeBytes(0), scopeBytes(1), scopeBytes(2), scopeBytes(3)),
                    field(5uL), field(6uL), expiry, reason)
            }
        }
    }
}
