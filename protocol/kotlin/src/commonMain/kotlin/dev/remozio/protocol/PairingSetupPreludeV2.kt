package dev.remozio.protocol

/** The invitation proof precedes the existing transcript and receipt exchange. */
sealed class PairingSetupPreludeV2 {
    class Challenge(value: ByteArray) : PairingSetupPreludeV2() {
        val value = CborValue.Bytes(value)
        init { require(value.size == 32) }
    }

    class Proposal(val value: PairingPhoneProposal, tag: ByteArray) : PairingSetupPreludeV2() {
        val tag = CborValue.Bytes(tag)
        init { require(tag.size == 32) }
    }

    fun encode(): ByteArray {
        val (kind, body) = when (this) {
            is Challenge -> 0uL to value
            is Proposal -> 1uL to CborValue.ArrayValue(listOf(CborValue.Bytes(value.encode()), tag))
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(2u), 2uL to CborValue.Unsigned(kind), 3uL to body,
        )), LIMITS)
    }

    final override fun toString() = "PairingSetupPreludeV2(redacted)"

    companion object {
        const val APPLICATION_PROTOCOL = "remozio-pairing/2"
        const val MAXIMUM_BYTES = 66_128
        private const val DOMAIN = "dev.remozio.pairing.exchange"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 13)

        fun decode(bytes: ByteArray): PairingSetupPreludeV2 {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: error("Invalid setup prelude")
            require(fields.keys == (0uL..3uL).toSet() && fields[0u] == CborValue.Text(DOMAIN) && fields[1u] == CborValue.Unsigned(2u))
            val body = fields[3u]
            val frame = when (fields[2u]) {
                CborValue.Unsigned(0u) -> {
                    val challenge = body as? CborValue.Bytes ?: error("Invalid setup challenge")
                    Challenge(challenge.copyBytes())
                }
                CborValue.Unsigned(1u) -> {
                    val row = (body as? CborValue.ArrayValue)?.values ?: error("Invalid setup proposal body")
                    require(row.size == 2)
                    val proposal = row[0] as? CborValue.Bytes ?: error("Invalid setup proposal")
                    val tag = row[1] as? CborValue.Bytes ?: error("Invalid setup proof tag")
                    Proposal(PairingPhoneProposal.decode(proposal.copyBytes()), tag.copyBytes())
                }
                else -> error("Invalid setup prelude kind")
            }
            return frame.also { require(it.encode().contentEquals(bytes)) }
        }
    }
}
