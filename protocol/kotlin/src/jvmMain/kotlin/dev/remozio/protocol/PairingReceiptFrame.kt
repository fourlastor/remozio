package dev.remozio.protocol

/** Read-only recovery over an enrolled TLS channel. Only a verified Root receipt can activate the retained pairing. */
sealed class PairingReceiptFrame {
    class Query(setupID: ByteArray) : PairingReceiptFrame() {
        val setupID = CborValue.Bytes(setupID)
        init { require(this.setupID.size == 16) }
    }
    class Response(setupID: ByteArray, signature: ByteArray?) : PairingReceiptFrame() {
        val setupID = CborValue.Bytes(setupID)
        val signature = signature?.let(CborValue::Bytes)
        init { require(this.setupID.size == 16 && (this.signature == null || this.signature.size == 64)) }
    }
    fun encode(): ByteArray {
        val (kind, id, signature) = when (this) {
            is Query -> Triple(0uL, setupID, null)
            is Response -> Triple(1uL, setupID, signature)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.pairing.receipt"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(kind), 3uL to id, 4uL to (signature ?: CborValue.Null),
        )), LIMITS)
    }
    final override fun toString() = "PairingReceiptFrame(redacted)"
    companion object {
        const val MAXIMUM_BYTES = 160
        const val APPLICATION_PROTOCOL = "remozio-receipt/1"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 1, 11)
        fun decode(bytes: ByteArray): PairingReceiptFrame {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: error("Invalid receipt frame")
            require(fields.keys == (0uL..4uL).toSet() && fields[0u] == CborValue.Text("dev.remozio.pairing.receipt") &&
                fields[1u] == CborValue.Unsigned(1u))
            val kind = (fields[2u] as? CborValue.Unsigned)?.value ?: error("Invalid receipt frame")
            val id = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid receipt frame")
            val proof = fields.getValue(4u)
            val result = when {
                kind == 0uL && proof == CborValue.Null -> Query(id)
                kind == 1uL && proof == CborValue.Null -> Response(id, null)
                kind == 1uL && proof is CborValue.Bytes -> Response(id, proof.copyBytes())
                else -> error("Invalid receipt frame")
            }
            require(result.encode().contentEquals(bytes))
            return result
        }
    }
}
