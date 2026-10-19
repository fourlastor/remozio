package dev.remozio.protocol

/** A mapping observation describes gateway state, not provider delivery or desktop presence. */
enum class PhonePushRecoveryPhase(val tag: ULong) { AWAITING_PROVIDER_PROOF(0u), PROOF_COMMITTED(1u), MAPPING_OBSERVED(2u) }

enum class PhonePushRecoveryFailure(val tag: ULong) { UNAVAILABLE(0u), SUPERSEDED(3u), EXPIRED(4u), INCOMPATIBLE(5u) }

/** Public metadata excludes the provider challenge. The caller validates scope and freshness separately. */
class PhonePushRecoveryState(
    val metadata: PhonePushRegistrationMetadata,
    val phase: PhonePushRecoveryPhase,
    val observationAgeMilliseconds: ULong? = null,
) {
    init {
        require((phase == PhonePushRecoveryPhase.MAPPING_OBSERVED) == (observationAgeMilliseconds != null))
        require(observationAgeMilliseconds == null || observationAgeMilliseconds <= MAXIMUM_OBSERVATION_AGE_MILLISECONDS)
    }
    override fun toString() = "PhonePushRecoveryState(redacted)"
    internal fun value() = CborValue.ArrayValue(listOf(metadata.value(), CborValue.Unsigned(phase.tag),
        observationAgeMilliseconds?.let { CborValue.Unsigned(it) } ?: CborValue.Null))
    companion object {
        const val MAXIMUM_OBSERVATION_AGE_MILLISECONDS = 4999uL
        internal fun decode(value: CborValue): PhonePushRecoveryState {
            val fields = (value as CborValue.ArrayValue).values; require(fields.size == 3)
            val phase = PhonePushRecoveryPhase.entries.single { CborValue.Unsigned(it.tag) == fields[1] }
            val age = when (val item = fields[2]) {
                CborValue.Null -> null
                is CborValue.Unsigned -> item.value
                else -> throw IllegalArgumentException("Invalid observation age")
            }
            return PhonePushRecoveryState(PhonePushRegistrationMetadata.decode(fields[0]), phase, age)
        }
    }
}

/** Negotiate schema 2 before sending a token. Proofs retain the separate version 1 exchange and its replay rules. */
sealed class PhonePushRecoveryFrame(correlationID: ByteArray) {
    val correlationID = CborValue.Bytes(correlationID)
    init { require(correlationID.size == 16) }
    class Probe(correlationID: ByteArray) : PhonePushRecoveryFrame(correlationID)
    class Ready(correlationID: ByteArray) : PhonePushRecoveryFrame(correlationID)
    class Resume(correlationID: ByteArray, val offer: PhonePushTokenOffer) : PhonePushRecoveryFrame(correlationID)
    class State(correlationID: ByteArray, val state: PhonePushRecoveryState) : PhonePushRecoveryFrame(correlationID)
    class Outcome(correlationID: ByteArray, val failure: PhonePushRecoveryFailure) : PhonePushRecoveryFrame(correlationID)
    override fun toString() = "PhonePushRecoveryFrame(redacted)"
    fun encode(): ByteArray {
        val (kind, payload) = when (this) {
            is Probe -> 6uL to CborValue.Null
            is Ready -> 7uL to CborValue.Unsigned(2u)
            is Resume -> 4uL to offer.value()
            is State -> 5uL to state.value()
            is Outcome -> 3uL to CborValue.Unsigned(failure.tag)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(2u),
            2uL to CborValue.Unsigned(kind), 3uL to correlationID, 4uL to payload)), LIMITS)
    }
    companion object {
        const val APPLICATION_PROTOCOL = "remozio-push-registration/2"
        const val MAXIMUM_BYTES = 8192
        private const val DOMAIN = "dev.remozio.phone.push.registration"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 4, 64)
        fun decode(bytes: ByteArray): PhonePushRecoveryFrame {
            require(bytes.size <= MAXIMUM_BYTES)
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as CborValue.Fields).values
            require(fields.keys == (0uL..4uL).toSet() && fields[0u] == CborValue.Text(DOMAIN) && fields[1u] == CborValue.Unsigned(2u))
            val id = (fields[3u] as CborValue.Bytes).copyBytes(); val payload = fields.getValue(4u)
            val frame = when ((fields[2u] as CborValue.Unsigned).value) {
                6uL -> { require(payload == CborValue.Null); Probe(id) }
                7uL -> { require(payload == CborValue.Unsigned(2u)); Ready(id) }
                4uL -> Resume(id, PhonePushTokenOffer.decode(payload))
                5uL -> State(id, PhonePushRecoveryState.decode(payload))
                3uL -> Outcome(id, PhonePushRecoveryFailure.entries.single { CborValue.Unsigned(it.tag) == payload })
                else -> throw IllegalArgumentException("Unsupported recovery frame")
            }
            require(frame.encode().contentEquals(bytes)); return frame
        }
    }
}
