package dev.remozio.protocol

enum class PhoneUpdateProgressFailure(val tag: ULong) { UNAVAILABLE(0u), INCOMPATIBLE(1u) }

/** Carries observations only. Parsing does not verify the Root signature or establish freshness. */
sealed class PhoneUpdateProgressFrame(queryNonce: ByteArray) {
    val queryNonce = CborValue.Bytes(queryNonce)
    init { require(this.queryNonce.size == 32) }
    class Status(queryNonce: ByteArray) : PhoneUpdateProgressFrame(queryNonce)
    class Response(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : PhoneUpdateProgressFrame(queryNonce) {
        val canonicalPayload = CborValue.Bytes(canonicalPayload)
        val signature = CborValue.Bytes(signature)
        init {
            require(this.signature.size == 64 &&
                UpdateSchedulingProgressResponse.decode(this.canonicalPayload.copyBytes()).status.queryNonce == this.queryNonce)
        }
    }
    class Failure(queryNonce: ByteArray, val reason: PhoneUpdateProgressFailure) : PhoneUpdateProgressFrame(queryNonce)
    fun encode(): ByteArray {
        val kind: ULong
        val payload: CborValue
        when (this) {
            is Status -> { kind = 0u; payload = CborValue.Null }
            is Response -> { kind = 1u; payload = CborValue.ArrayValue(listOf(canonicalPayload, signature)) }
            is Failure -> { kind = 2u; payload = CborValue.Unsigned(reason.tag) }
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u), 2uL to CborValue.Unsigned(kind),
            3uL to queryNonce, 4uL to payload,
        )), LIMITS)
    }
    final override fun toString() = "PhoneUpdateProgressFrame(redacted)"
    companion object {
        const val APPLICATION_PROTOCOL = "remozio-update-progress/1"
        const val MAXIMUM_BYTES = 8192
        private const val DOMAIN = "dev.remozio.phone.update-progress"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 32)
        fun decode(bytes: ByteArray): PhoneUpdateProgressFrame {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid update progress frame")
            require(fields.keys == (0uL..4uL).toSet() && fields[0uL] == CborValue.Text(DOMAIN) && fields[1uL] == CborValue.Unsigned(1u))
            val kind = (fields[2uL] as? CborValue.Unsigned)?.value ?: throw IllegalArgumentException("Invalid progress role")
            val nonce = (fields[3uL] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid progress nonce")
            val payload = fields.getValue(4u)
            val frame = when (kind) {
                0uL -> { require(payload == CborValue.Null); Status(nonce) }
                1uL -> {
                    val parts = (payload as? CborValue.ArrayValue)?.values ?: throw IllegalArgumentException("Invalid progress response")
                    require(parts.size == 2)
                    val body = (parts[0] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid progress body")
                    val signature = (parts[1] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid progress signature")
                    Response(nonce, body, signature)
                }
                2uL -> Failure(nonce, PhoneUpdateProgressFailure.entries.single {
                    it.tag == (payload as? CborValue.Unsigned)?.value
                })
                else -> throw IllegalArgumentException("Invalid progress role")
            }
            require(frame.encode().contentEquals(bytes)); return frame
        }
    }
}
