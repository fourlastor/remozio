package dev.remozio.protocol

enum class PhoneUpdateSchedulingFailure(val tag: ULong) { UNAVAILABLE(0u), INCOMPATIBLE(1u) }

/** Bounded scheduling messages for a dedicated enrolled channel. Parsing grants no authority. */
sealed class PhoneUpdateSchedulingFrame(queryNonce: ByteArray) {
    val queryNonce = CborValue.Bytes(queryNonce)
    init { require(this.queryNonce.size == 32) }
    class Status(queryNonce: ByteArray) : PhoneUpdateSchedulingFrame(queryNonce)
    class Challenge(queryNonce: ByteArray, updateID: ByteArray, val generation: ULong, val revision: ULong,
                    val action: UpdateSchedulingAction) : PhoneUpdateSchedulingFrame(queryNonce) {
        val updateID = CborValue.Bytes(updateID)
        init { require(this.updateID.size == 32 && generation > 0uL) }
    }
    class Apply(queryNonce: ByteArray, canonicalControl: ByteArray, signature: ByteArray) : PhoneUpdateSchedulingFrame(queryNonce) {
        val canonicalControl = CborValue.Bytes(canonicalControl); val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64); UpdateSchedulingControl.decode(this.canonicalControl.copyBytes(), CONTROL_LIMITS) }
    }
    class ChallengeResponse(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : PhoneUpdateSchedulingFrame(queryNonce) {
        val canonicalPayload = CborValue.Bytes(canonicalPayload); val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64 && RootUpdateSchedulingChallenge.decode(this.canonicalPayload.copyBytes(), RESPONSE_LIMITS).queryNonce.contentEquals(this.queryNonce.copyBytes())) }
    }
    class StateResponse(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : PhoneUpdateSchedulingFrame(queryNonce) {
        val canonicalPayload = CborValue.Bytes(canonicalPayload); val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64 && UpdateSchedulingStatusResponse.decode(this.canonicalPayload.copyBytes()).queryNonce == this.queryNonce) }
    }
    class Failure(queryNonce: ByteArray, val reason: PhoneUpdateSchedulingFailure) : PhoneUpdateSchedulingFrame(queryNonce)
    fun encode(): ByteArray {
        val (kind, payload) = when (this) {
            is Status -> 0uL to CborValue.Null
            is Challenge -> 1uL to CborValue.ArrayValue(listOf(updateID, CborValue.Unsigned(generation), CborValue.Unsigned(revision), CborValue.Unsigned(action.tag)))
            is Apply -> 2uL to CborValue.ArrayValue(listOf(canonicalControl, signature))
            is ChallengeResponse -> 3uL to CborValue.ArrayValue(listOf(canonicalPayload, signature))
            is StateResponse -> 4uL to CborValue.ArrayValue(listOf(canonicalPayload, signature))
            is Failure -> 5uL to CborValue.Unsigned(reason.tag)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(kind), 3uL to queryNonce, 4uL to payload)), LIMITS)
    }
    override fun toString() = "PhoneUpdateSchedulingFrame(redacted)"
    companion object {
        const val APPLICATION_PROTOCOL = "remozio-update-scheduling/1"
        const val MAXIMUM_BYTES = 4096
        private const val DOMAIN = "dev.remozio.phone.update-scheduling"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 3, 32)
        private val CONTROL_LIMITS = CborLimits(1024, 2, 32)
        private val RESPONSE_LIMITS = CborLimits(2048, 2, 32)
        fun decode(bytes: ByteArray): PhoneUpdateSchedulingFrame {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: throw IllegalArgumentException("Invalid update scheduling frame")
            require(f.keys == (0uL..4uL).toSet() && f[0u] == CborValue.Text(DOMAIN) && f[1u] == CborValue.Unsigned(1u))
            val nonce = (f[3u] as CborValue.Bytes).copyBytes(); val payload = f.getValue(4u)
            fun pair(): List<ByteArray> {
                val values = (payload as CborValue.ArrayValue).values; require(values.size == 2)
                return values.map { (it as CborValue.Bytes).copyBytes() }
            }
            val frame = when ((f[2u] as CborValue.Unsigned).value) {
                0uL -> { require(payload == CborValue.Null); Status(nonce) }
                1uL -> {
                    val v = (payload as CborValue.ArrayValue).values; require(v.size == 4)
                    val action = UpdateSchedulingAction.entries.single { it.tag == (v[3] as CborValue.Unsigned).value }
                    Challenge(nonce, (v[0] as CborValue.Bytes).copyBytes(), (v[1] as CborValue.Unsigned).value,
                        (v[2] as CborValue.Unsigned).value, action)
                }
                2uL -> pair().let { Apply(nonce, it[0], it[1]) }
                3uL -> pair().let { ChallengeResponse(nonce, it[0], it[1]) }
                4uL -> pair().let { StateResponse(nonce, it[0], it[1]) }
                5uL -> Failure(nonce, PhoneUpdateSchedulingFailure.entries.single { CborValue.Unsigned(it.tag) == payload })
                else -> throw IllegalArgumentException("Unsupported update scheduling frame")
            }
            require(frame.encode().contentEquals(bytes)); return frame
        }
    }
}
