package dev.remozio.protocol

/** A read-only query inside an authenticated session. Only a signed status can establish the result. */
class RequestStatusQuery(requestID: ByteArray) {
    val requestID = CborValue.Bytes(requestID)
    init { require(requestID.size == 16) }
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Text("request-state"), 2uL to requestID,
    )), limits)
    override fun toString() = "RequestStatusQuery(redacted)"
    companion object {
        const val MAXIMUM_BYTES = 64
        private val limits = CborLimits(MAXIMUM_BYTES, 1, 7)
        fun decode(bytes: ByteArray): RequestStatusQuery {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid status query")
            require(fields.keys == (0uL..2uL).toSet() && fields[0u] == CborValue.Unsigned(1u) &&
                fields[1u] == CborValue.Text("request-state"))
            val requestID = (fields[2u] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid status query")
            return RequestStatusQuery(requestID)
        }
    }
}
