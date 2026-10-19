package dev.remozio.protocol

/** Restricted setup messages. Administrator rights, commands and credential releases have no representation here. */
sealed class PairingSetupFrame {
    data object Hello : PairingSetupFrame()
    class Proposal(val value: PairingPhoneProposal) : PairingSetupFrame()
    class Transcript(val value: PairingTranscript) : PairingSetupFrame()
    class Proof(setupID: ByteArray, digest: ByteArray, signature: ByteArray) : PairingSetupFrame() {
        val setupID = CborValue.Bytes(setupID); val digest = CborValue.Bytes(digest); val signature = CborValue.Bytes(signature)
        init { proofValue(this.setupID, this.digest, this.signature) }
    }
    class Receipt(setupID: ByteArray, digest: ByteArray, signature: ByteArray) : PairingSetupFrame() {
        val setupID = CborValue.Bytes(setupID); val digest = CborValue.Bytes(digest); val signature = CborValue.Bytes(signature)
        init { proofValue(this.setupID, this.digest, this.signature) }
    }
    fun encode(): ByteArray {
        val (kind, body) = when (this) {
            Hello -> 0uL to CborValue.Null
            is Proposal -> 1uL to CborValue.Bytes(value.encode())
            is Transcript -> 2uL to CborValue.Bytes(value.encode())
            is Proof -> 3uL to proofValue(setupID, digest, signature)
            is Receipt -> 4uL to proofValue(setupID, digest, signature)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text("dev.remozio.pairing.exchange"),
            1uL to CborValue.Unsigned(1u), 2uL to CborValue.Unsigned(kind), 3uL to body)), LIMITS)
    }
    final override fun toString() = "PairingSetupFrame(redacted)"
    companion object {
        const val MAXIMUM_BYTES = 132_256
        const val APPLICATION_PROTOCOL = "remozio-pairing/1"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 20)
        private fun proofValue(id: CborValue.Bytes, digest: CborValue.Bytes, signature: CborValue.Bytes): CborValue {
            require(id.size == 16 && digest.size == 32 && signature.size == 64)
            return CborValue.ArrayValue(listOf(id, digest, signature))
        }
        fun decode(bytes: ByteArray): PairingSetupFrame {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid setup frame")
            require(f.keys == (0uL..3uL).toSet() && f[0u] == CborValue.Text("dev.remozio.pairing.exchange") && f[1u] == CborValue.Unsigned(1u))
            val kind = (f[2u] as? CborValue.Unsigned)?.value ?: error("Invalid setup frame")
            val body = f.getValue(3u)
            val result = when (kind) {
                0uL -> { require(body == CborValue.Null); Hello }
                1uL -> Proposal(PairingPhoneProposal.decode((body as CborValue.Bytes).copyBytes()))
                2uL -> Transcript(PairingTranscript.decode((body as CborValue.Bytes).copyBytes()))
                3uL, 4uL -> {
                    val row = (body as CborValue.ArrayValue).values; require(row.size == 3)
                    val b = row.map { (it as CborValue.Bytes).copyBytes() }
                    if (kind == 3uL) Proof(b[0], b[1], b[2]) else Receipt(b[0], b[1], b[2])
                }
                else -> error("Unsupported setup frame")
            }
            require(result.encode().contentEquals(bytes)); return result
        }
    }
}
