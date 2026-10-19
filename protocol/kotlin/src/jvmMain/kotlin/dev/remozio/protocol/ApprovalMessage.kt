package dev.remozio.protocol

/** Routing claims and exact signed bytes. Parsing this carrier does not authenticate its contents. */
class ApprovalMessage(
    val wireVersion: ULong,
    val type: ApprovalMessageType,
    val purpose: SigningPurpose,
    body: ByteArray,
    signature: ByteArray,
) {
    val body = CborValue.Bytes(body)
    val signature = CborValue.Bytes(signature)
    init {
        require(wireVersion == 1uL && body.isNotEmpty() && signature.size == 64)
        require(when (type) {
            ApprovalMessageType.REQUEST -> purpose == SigningPurpose.ISSUED_REQUEST
            ApprovalMessageType.STATUS -> purpose == SigningPurpose.STATUS
            ApprovalMessageType.DECISION -> purpose in setOf(SigningPurpose.CANCELLATION,
                SigningPurpose.ONE_TIME_UI, SigningPurpose.BIOMETRIC_AUTHORIZATION)
        })
    }
    fun encode(maximumBodyBytes: Int): ByteArray {
        require(body.size <= maximumBodyBytes)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to CborValue.Unsigned(wireVersion),
            2uL to CborValue.Unsigned(type.tag), 3uL to CborValue.Unsigned(purpose.tag), 4uL to body, 5uL to signature,
        )), limits(maximumBodyBytes))
    }
    override fun toString() = "ApprovalMessage(redacted)"
    companion object {
        const val OVERHEAD_BYTES = 128
        fun decode(bytes: ByteArray, maximumBodyBytes: Int): ApprovalMessage {
            val fields = (DeterministicCbor.decode(bytes, limits(maximumBodyBytes)) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid approval carrier")
            require(fields.keys == (0uL..5uL).toSet() && fields[0u] == CborValue.Unsigned(1u))
            fun number(key: ULong) = (fields[key] as? CborValue.Unsigned)?.value
                ?: throw IllegalArgumentException("Invalid approval carrier")
            fun data(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid approval carrier")
            val type = ApprovalMessageType.entries.singleOrNull { it.tag == number(2u) }
                ?: throw IllegalArgumentException("Unknown message type")
            val purpose = SigningPurpose.entries.singleOrNull { it.tag == number(3u) }
                ?: throw IllegalArgumentException("Unknown signing purpose")
            val body = data(4u)
            require(body.size <= maximumBodyBytes)
            return ApprovalMessage(number(1u), type, purpose, body, data(5u))
        }
        private fun limits(maximum: Int): CborLimits {
            require(maximum in 1..(16_777_216 - OVERHEAD_BYTES))
            return CborLimits(maximum + OVERHEAD_BYTES, 2, 16)
        }
    }
}
