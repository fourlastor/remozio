package dev.remozio.protocol

/** An explicit scheduling version. Version1 readers never accept its messages. */
sealed class PhoneUpdateSchedulingFrameV2 {
    abstract val queryNonce: CborValue.Bytes

    class Message(val frame: PhoneUpdateSchedulingFrame) : PhoneUpdateSchedulingFrameV2() {
        override val queryNonce: CborValue.Bytes get() = frame.queryNonce
    }

    class TooLate(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : PhoneUpdateSchedulingFrameV2() {
        override val queryNonce = CborValue.Bytes(queryNonce)
        val canonicalPayload = CborValue.Bytes(canonicalPayload)
        val signature = CborValue.Bytes(signature)
        init {
            require(this.queryNonce.size == 32 && this.signature.size == 64)
            require(UpdateSchedulingTooLateResponse.decode(this.canonicalPayload.copyBytes()).progress.status.queryNonce == this.queryNonce)
        }
    }

    fun encode(): ByteArray {
        val fields = when (this) {
            is Message -> {
                val source = (DeterministicCbor.decode(frame.encode(), LIMITS) as CborValue.Fields).values
                source + (1uL to CborValue.Unsigned(2u))
            }
            is TooLate -> mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(2u),
                2uL to CborValue.Unsigned(6u), 3uL to queryNonce,
                4uL to CborValue.ArrayValue(listOf(canonicalPayload, signature)))
        }
        return DeterministicCbor.encode(CborValue.Fields(fields), LIMITS)
    }

    override fun toString() = "PhoneUpdateSchedulingFrameV2(redacted)"

    companion object {
        const val APPLICATION_PROTOCOL = "remozio-update-scheduling/2"
        const val MAXIMUM_BYTES = 9216
        private const val DOMAIN = "dev.remozio.phone.update-scheduling"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 3, 32)

        fun decode(bytes: ByteArray): PhoneUpdateSchedulingFrameV2 {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid scheduling version2 frame")
            require(fields.keys == (0uL..4uL).toSet() && fields[0u] == CborValue.Text(DOMAIN) &&
                fields[1u] == CborValue.Unsigned(2u))
            val kind = (fields[2u] as CborValue.Unsigned).value
            val frame = if (kind == 6uL) {
                val pair = (fields[4u] as CborValue.ArrayValue).values
                require(pair.size == 2)
                TooLate((fields[3u] as CborValue.Bytes).copyBytes(), (pair[0] as CborValue.Bytes).copyBytes(),
                    (pair[1] as CborValue.Bytes).copyBytes())
            } else {
                require(kind <= 5uL)
                Message(PhoneUpdateSchedulingFrame.decode(DeterministicCbor.encode(
                    CborValue.Fields(fields + (1uL to CborValue.Unsigned(1u))), LIMITS)))
            }
            require(frame.encode().contentEquals(bytes))
            return frame
        }
    }
}
