package dev.remozio.protocol

enum class PhoneAuditFailure(val tag: ULong) { UNAVAILABLE(0u), INCOMPATIBLE(1u) }

/** Read-only carrier. Typed parsing, signature verification and pending-query matching remain mandatory. */
sealed class PhoneAuditFrame(queryNonce: ByteArray) {
    val queryNonce = CborValue.Bytes(queryNonce)
    init { require(this.queryNonce.size == 32) }
    class HistoryQuery(queryNonce: ByteArray, epoch: ByteArray?, val requestedAfter: ULong?) : PhoneAuditFrame(queryNonce) {
        val requestedEpoch = epoch?.let { CborValue.Bytes(it) }
        init { require((requestedEpoch == null) == (requestedAfter == null) && (requestedEpoch == null || requestedEpoch.size == 16)) }
    }
    class PageQuery(queryNonce: ByteArray, epoch: ByteArray, val epochCreationGeneration: ULong,
                    val requestedAfter: ULong) : PhoneAuditFrame(queryNonce) {
        val journalEpoch = CborValue.Bytes(epoch)
        init { require(journalEpoch.size == 16) }
    }
    sealed class Response(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : PhoneAuditFrame(queryNonce) {
        val canonicalPayload = CborValue.Bytes(canonicalPayload)
        val signature = CborValue.Bytes(signature)
        init { require(this.canonicalPayload.size in 1..MAXIMUM_PAYLOAD_BYTES && this.signature.size == 64) }
    }
    class HistoryResponse(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : Response(queryNonce, canonicalPayload, signature)
    class PageResponse(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : Response(queryNonce, canonicalPayload, signature)
    class Failure(queryNonce: ByteArray, val reason: PhoneAuditFailure) : PhoneAuditFrame(queryNonce)
    val isQuery: Boolean get() = this is HistoryQuery || this is PageQuery

    fun encode(): ByteArray {
        val (kind, payload) = when (this) {
            is HistoryQuery -> 0uL to CborValue.ArrayValue(listOf(requestedEpoch ?: CborValue.Null,
                requestedAfter?.let { CborValue.Unsigned(it) } ?: CborValue.Null))
            is PageQuery -> 1uL to CborValue.ArrayValue(listOf(journalEpoch, CborValue.Unsigned(epochCreationGeneration), CborValue.Unsigned(requestedAfter)))
            is HistoryResponse -> 2uL to CborValue.ArrayValue(listOf(canonicalPayload, signature))
            is PageResponse -> 3uL to CborValue.ArrayValue(listOf(canonicalPayload, signature))
            is Failure -> 4uL to CborValue.Unsigned(reason.tag)
        }
        val bytes = DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(kind), 3uL to queryNonce, 4uL to payload)), LIMITS)
        require(!isQuery || bytes.size <= MAXIMUM_QUERY_BYTES)
        return bytes
    }
    override fun toString() = "PhoneAuditFrame(redacted)"

    companion object {
        const val APPLICATION_PROTOCOL = "remozio-audit/1"
        const val MAXIMUM_PAYLOAD_BYTES = 1_048_576
        const val OVERHEAD_BYTES = 256
        const val MAXIMUM_BYTES = MAXIMUM_PAYLOAD_BYTES + OVERHEAD_BYTES
        const val MAXIMUM_QUERY_BYTES = 256
        private const val DOMAIN = "dev.remozio.phone.audit"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 3, 20)
        fun decode(bytes: ByteArray): PhoneAuditFrame {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: throw IllegalArgumentException("Invalid audit carrier")
            require(f.keys == (0uL..4uL).toSet() && f[0u] == CborValue.Text(DOMAIN) && f[1u] == CborValue.Unsigned(1u))
            val nonce = (f[3u] as CborValue.Bytes).copyBytes(); val payload = f.getValue(4u)
            fun array(count: Int): List<CborValue> = (payload as CborValue.ArrayValue).values.also { require(it.size == count) }
            fun bytes(value: CborValue) = (value as CborValue.Bytes).copyBytes()
            fun number(value: CborValue) = (value as CborValue.Unsigned).value
            val frame = when (number(f.getValue(2u))) {
                0uL -> array(2).let { fields ->
                    if (fields == listOf(CborValue.Null, CborValue.Null)) HistoryQuery(nonce, null, null)
                    else HistoryQuery(nonce, bytes(fields[0]), number(fields[1]))
                }
                1uL -> array(3).let { PageQuery(nonce, bytes(it[0]), number(it[1]), number(it[2])) }
                2uL -> array(2).let { HistoryResponse(nonce, bytes(it[0]), bytes(it[1])) }
                3uL -> array(2).let { PageResponse(nonce, bytes(it[0]), bytes(it[1])) }
                4uL -> Failure(nonce, PhoneAuditFailure.entries.single { it.tag == number(payload) })
                else -> throw IllegalArgumentException("Unsupported audit carrier")
            }
            require(frame.encode().contentEquals(bytes)); return frame
        }
    }
}
