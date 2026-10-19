package dev.remozio.protocol

/** An opaque provider address and compatibility hints. None of these fields grant enrollment authority. */
class PhonePushTokenOffer(val token: String, val projectID: String, val senderID: String, val packageName: String) {
    init {
        require(token.length in 1..4096 && token.all { it.code in 33..126 })
        require(projectID.length in 1..128 && Regex("[A-Za-z0-9][A-Za-z0-9_.:-]*").matches(projectID))
        require(senderID.length in 1..32 && senderID.all { it in '0'..'9' })
        require(packageName.length in 1..255 && Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+").matches(packageName))
    }
    override fun toString() = "PhonePushTokenOffer(redacted)"
    internal fun value() = CborValue.ArrayValue(listOf(token, projectID, senderID, packageName).map { CborValue.Text(it) })
    companion object {
        internal fun decode(value: CborValue): PhonePushTokenOffer {
            val fields = (value as CborValue.ArrayValue).values; require(fields.size == 4)
            fun text(i: Int) = (fields[i] as CborValue.Text).value
            return PhonePushTokenOffer(text(0), text(1), text(2), text(3))
        }
    }
}

/** Fetchable candidate metadata deliberately has no provider challenge. It is not an activation receipt. */
class PhonePushRegistrationMetadata private constructor(
    private val identifiers: List<CborValue.Bytes>,
    val revision: ULong, operationID: ByteArray, val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong,
) {
    private val operation = CborValue.Bytes(operationID)
    val ownerID get() = identifiers[0].copyBytes()
    val macID get() = identifiers[1].copyBytes()
    val accountID get() = identifiers[2].copyBytes()
    val gatewayID get() = identifiers[3].copyBytes()
    val lifecycleEpoch get() = identifiers[4].copyBytes()
    val phoneID get() = identifiers[5].copyBytes()
    val enrollmentEpoch get() = identifiers[6].copyBytes()
    val candidateID get() = identifiers[7].copyBytes()
    val tokenDigest get() = identifiers[8].copyBytes()
    val enrollmentTag get() = identifiers[9].copyBytes()
    val operationID get() = operation.copyBytes()
    val scope get() = ChannelScope(macID, accountID, phoneID, enrollmentEpoch)
    init {
        require(identifiers.size == 10)
        identifiers.forEachIndexed { i, value -> require(value.copyBytes().size == if (i < 8) 16 else 32) }
        require(revision > 0uL && operationID.size == 16 && expiresAtUnixMillis > issuedAtUnixMillis)
    }
    constructor(candidate: GatewayTokenCandidate) : this(candidate.binding.let { binding ->
        listOf(binding.ownerID, binding.macID, binding.accountID, binding.gatewayID, binding.lifecycleEpoch,
            binding.phoneID, binding.enrollmentEpoch, binding.candidateID, binding.tokenDigest, binding.enrollmentTag).map { CborValue.Bytes(it) }
    }, candidate.revision, candidate.operationID, candidate.issuedAtUnixMillis, candidate.expiresAtUnixMillis)

    /** The caller must receive this challenge through the provider and recheck current trust and deadlines separately. */
    fun proof(challenge: PushData.TokenChallenge): GatewayTokenProof {
        require(challenge.candidateID.contentEquals(candidateID) && challenge.enrollmentTag.contentEquals(enrollmentTag))
        return GatewayTokenProof(GatewayTokenBinding(ownerID, macID, accountID, gatewayID, lifecycleEpoch,
            phoneID, enrollmentEpoch, candidateID, tokenDigest, challenge.challenge, enrollmentTag))
    }
    override fun toString() = "PhonePushRegistrationMetadata(redacted)"
    internal fun value(): CborValue = CborValue.ArrayValue(identifiers + listOf(CborValue.Unsigned(revision), operation,
        CborValue.Unsigned(issuedAtUnixMillis), CborValue.Unsigned(expiresAtUnixMillis)))
    companion object {
        internal fun decode(value: CborValue): PhonePushRegistrationMetadata {
            val fields = (value as CborValue.ArrayValue).values; require(fields.size == 14)
            fun uint(i: Int) = (fields[i] as CborValue.Unsigned).value
            return PhonePushRegistrationMetadata(fields.take(10).map { it as CborValue.Bytes }, uint(10),
                (fields[11] as CborValue.Bytes).copyBytes(), uint(12), uint(13))
        }
    }
}

/** Proof consumption and confirmed gateway mapping are different outcomes. None asserts current phone delivery. */
enum class PhonePushRegistrationOutcome(val tag: ULong) {
    UNAVAILABLE(0u), PROOF_COMMITTED(1u), MAPPING_CONFIRMED(2u), SUPERSEDED(3u), EXPIRED(4u), INCOMPATIBLE(5u),
}

/** Only the purpose-specific, mutually authenticated enrolled channel may carry these frames. */
sealed class PhonePushRegistrationFrame(correlationID: ByteArray) {
    val correlationID = CborValue.Bytes(correlationID)
    init { require(correlationID.size == 16) }
    class Offer(correlationID: ByteArray, val offer: PhonePushTokenOffer) : PhonePushRegistrationFrame(correlationID)
    class Prepared(correlationID: ByteArray, val metadata: PhonePushRegistrationMetadata) : PhonePushRegistrationFrame(correlationID)
    class Proof(correlationID: ByteArray, val proof: GatewayTokenProof) : PhonePushRegistrationFrame(correlationID)
    class Outcome(correlationID: ByteArray, val outcome: PhonePushRegistrationOutcome) : PhonePushRegistrationFrame(correlationID)

    fun encode(): ByteArray {
        val (kind, payload) = when (this) {
            is Offer -> 0uL to offer.value()
            is Prepared -> 1uL to metadata.value()
            is Proof -> 2uL to CborValue.Bytes(proof.encode(PROOF_LIMITS))
            is Outcome -> 3uL to CborValue.Unsigned(outcome.tag)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(kind), 3uL to correlationID, 4uL to payload)), LIMITS)
    }
    override fun toString() = "PhonePushRegistrationFrame(redacted)"
    companion object {
        const val APPLICATION_PROTOCOL = "remozio-push-registration/1"
        const val MAXIMUM_BYTES = 8192
        private const val DOMAIN = "dev.remozio.phone.push.registration"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 4, 64)
        private val PROOF_LIMITS = CborLimits(1024, 4, 32)
        fun decode(bytes: ByteArray): PhonePushRegistrationFrame {
            require(bytes.size <= MAXIMUM_BYTES)
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as CborValue.Fields).values
            require(fields.keys == (0uL..4uL).toSet() && fields[0u] == CborValue.Text(DOMAIN) && fields[1u] == CborValue.Unsigned(1u))
            val id = (fields[3u] as CborValue.Bytes).copyBytes(); val payload = fields.getValue(4u)
            val frame = when ((fields[2u] as CborValue.Unsigned).value) {
                0uL -> Offer(id, PhonePushTokenOffer.decode(payload))
                1uL -> Prepared(id, PhonePushRegistrationMetadata.decode(payload))
                2uL -> Proof(id, GatewayTokenProof.decode((payload as CborValue.Bytes).copyBytes(), PROOF_LIMITS))
                3uL -> Outcome(id, PhonePushRegistrationOutcome.entries.single { CborValue.Unsigned(it.tag) == payload })
                else -> throw IllegalArgumentException("Unsupported registration frame")
            }
            require(frame.encode().contentEquals(bytes)); return frame
        }
    }
}
