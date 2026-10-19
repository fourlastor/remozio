package dev.remozio.protocol

/** Opaque application bytes. The consumer must still verify the exact message contract and authority. */
class SessionEnvelope(sessionID: ByteArray, val sequence: ULong, payload: ByteArray) {
    val sessionID = CborValue.Bytes(sessionID)
    val payload = CborValue.Bytes(payload)
    init { require(sessionID.size == 32 && payload.isNotEmpty()) }
    fun encode(maximumPayloadBytes: Int): ByteArray {
        require(payload.size <= maximumPayloadBytes)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to sessionID, 2uL to CborValue.Unsigned(sequence), 3uL to payload,
        )), limits(maximumPayloadBytes))
    }
    override fun toString() = "SessionEnvelope(redacted)"
    companion object {
        fun decode(bytes: ByteArray, maximumPayloadBytes: Int): SessionEnvelope {
            val fields = (DeterministicCbor.decode(bytes, limits(maximumPayloadBytes)) as? CborValue.Fields)?.values
                ?: throw ChannelNegotiationException()
            require(fields.keys == (0uL..3uL).toSet() && fields[0u] == CborValue.Unsigned(1u))
            val session = (fields[1u] as? CborValue.Bytes)?.copyBytes() ?: throw ChannelNegotiationException()
            val sequence = (fields[2u] as? CborValue.Unsigned)?.value ?: throw ChannelNegotiationException()
            val payload = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: throw ChannelNegotiationException()
            require(payload.size <= maximumPayloadBytes)
            return SessionEnvelope(session, sequence, payload)
        }
        private fun limits(maximum: Int): CborLimits {
            require(maximum in 1..16_777_216)
            return CborLimits(maximum + 64, 2, 12)
        }
    }
}
