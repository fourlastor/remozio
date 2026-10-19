package dev.remozio.protocol

enum class RequestStatusReason(val tag: ULong) {
    NONE(0u), VERIFIED_RESULT(1u), OUTCOME_UNAVAILABLE(2u), DECLINED(3u),
    USER_CANCELLED(4u), AUTHORIZATION_EXPIRED(5u), TARGET_TIMED_OUT(6u),
    TARGET_DISAPPEARED(7u), AUTHORITY_RESTARTED(8u), NO_DISPATCH_PROVED(9u);

    internal fun permits(phase: RequestPhase): Boolean = when (this) {
        NONE -> !phase.isTerminal
        VERIFIED_RESULT -> phase == RequestPhase.SUCCEEDED || phase == RequestPhase.FAILED
        OUTCOME_UNAVAILABLE -> phase == RequestPhase.UNKNOWN
        DECLINED -> phase == RequestPhase.DECLINED
        USER_CANCELLED, TARGET_DISAPPEARED, NO_DISPATCH_PROVED -> phase == RequestPhase.CANCELLED
        AUTHORIZATION_EXPIRED, TARGET_TIMED_OUT -> phase == RequestPhase.EXPIRED
        AUTHORITY_RESTARTED -> phase == RequestPhase.CANCELLED || phase == RequestPhase.UNKNOWN
    }
}

enum class RequestStatusFailure { INVALID_FIELDS, UNSUPPORTED_SCHEMA, INVALID_BYTES, INVALID_STATE, INVALID_TIMING }
class RequestStatusException(val reason: RequestStatusFailure) : IllegalArgumentException(reason.name)

/** A status claim. Authentication, freshness, retained bindings, and transition checks belong to the receiver. */
class RequestStatusPayload(
    macID: ByteArray,
    accountID: ByteArray,
    requestID: ByteArray,
    requestDigest: ByteArray,
    challenge: ByteArray,
    val revision: ULong,
    val phase: RequestPhase,
    val reason: RequestStatusReason,
    observationID: ByteArray,
    val observedAgeMs: ULong,
    val authorizationRemainingMs: ULong?,
    val estimatedLifetimeMs: ULong?,
    val lateObservation: Boolean,
    val terminalAgeMs: ULong?,
    decisionPhoneID: ByteArray?,
) {
    init {
        ensure(listOf(macID.size, accountID.size, requestID.size, requestDigest.size, challenge.size, observationID.size) ==
            listOf(16, 16, 16, 32, 32, 16), RequestStatusFailure.INVALID_BYTES)
        ensure(decisionPhoneID == null || decisionPhoneID.size == 16, RequestStatusFailure.INVALID_BYTES)
        ensure(revision > 0u && reason.permits(phase), RequestStatusFailure.INVALID_STATE)
        val pending = phase == RequestPhase.QUEUED || phase == RequestPhase.PRESENTED
        ensure(!pending || decisionPhoneID == null, RequestStatusFailure.INVALID_STATE)
        ensure(pending == (authorizationRemainingMs != null), RequestStatusFailure.INVALID_TIMING)
        ensure(estimatedLifetimeMs == null || estimatedLifetimeMs > 0u, RequestStatusFailure.INVALID_TIMING)
        ensure(phase.isTerminal == (terminalAgeMs != null), RequestStatusFailure.INVALID_TIMING)
        ensure(terminalAgeMs == null || terminalAgeMs <= observedAgeMs, RequestStatusFailure.INVALID_TIMING)
    }

    private val bindings = listOf(macID, accountID, requestID, requestDigest, challenge, observationID).map { CborValue.Bytes(it) }
    private val decidingPhone = decisionPhoneID?.let(CborValue::Bytes)
    val macID: ByteArray get() = bindings[0].copyBytes()
    val accountID: ByteArray get() = bindings[1].copyBytes()
    val requestID: ByteArray get() = bindings[2].copyBytes()
    val requestDigest: ByteArray get() = bindings[3].copyBytes()
    val challenge: ByteArray get() = bindings[4].copyBytes()
    val observationID: ByteArray get() = bindings[5].copyBytes()
    val decisionPhoneID: ByteArray? get() = decidingPhone?.copyBytes()

    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to bindings[0], 2uL to bindings[1], 3uL to bindings[2],
        4uL to bindings[3], 5uL to bindings[4], 6uL to CborValue.Unsigned(revision),
        7uL to CborValue.Unsigned(phases.indexOf(phase).toULong()), 8uL to CborValue.Unsigned(reason.tag),
        9uL to bindings[5], 10uL to CborValue.Unsigned(observedAgeMs),
        11uL to number(authorizationRemainingMs), 12uL to number(estimatedLifetimeMs),
        13uL to CborValue.BooleanValue(lateObservation), 14uL to number(terminalAgeMs),
        15uL to (decidingPhone ?: CborValue.Null),
    )), limits)

    companion object {
        private val phases = listOf(RequestPhase.QUEUED, RequestPhase.PRESENTED, RequestPhase.AUTHORIZED,
            RequestPhase.EXECUTING, RequestPhase.SUCCEEDED, RequestPhase.FAILED, RequestPhase.UNKNOWN,
            RequestPhase.DECLINED, RequestPhase.CANCELLED, RequestPhase.EXPIRED)

        fun decode(bytes: ByteArray, limits: CborLimits): RequestStatusPayload {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values
                ?: fail(RequestStatusFailure.INVALID_FIELDS)
            ensure(fields.keys == (0uL..15uL).toSet(), RequestStatusFailure.INVALID_FIELDS)
            ensure(fields[0u] == CborValue.Unsigned(1u), RequestStatusFailure.UNSUPPORTED_SCHEMA)
            fun data(key: ULong): ByteArray = (fields[key] as? CborValue.Bytes)?.copyBytes()
                ?: fail(RequestStatusFailure.INVALID_BYTES)
            fun uint(key: ULong): ULong = (fields[key] as? CborValue.Unsigned)?.value
                ?: fail(RequestStatusFailure.INVALID_FIELDS)
            fun optional(key: ULong): ULong? = if (fields[key] == CborValue.Null) null else uint(key)
            val phaseTag = uint(7u)
            val phase = phases.getOrNull(if (phaseTag <= 9u) phaseTag.toInt() else -1)
                ?: fail(RequestStatusFailure.INVALID_STATE)
            val reason = RequestStatusReason.entries.firstOrNull { it.tag == uint(8u) }
                ?: fail(RequestStatusFailure.INVALID_STATE)
            val late = (fields[13u] as? CborValue.BooleanValue)?.value ?: fail(RequestStatusFailure.INVALID_FIELDS)
            return RequestStatusPayload(data(1u), data(2u), data(3u), data(4u), data(5u), uint(6u), phase, reason,
                data(9u), uint(10u), optional(11u), optional(12u), late, optional(14u),
                if (fields[15u] == CborValue.Null) null else data(15u))
        }

        private fun number(value: ULong?): CborValue = value?.let(CborValue::Unsigned) ?: CborValue.Null
        private fun ensure(condition: Boolean, reason: RequestStatusFailure) { if (!condition) fail(reason) }
        private fun fail(reason: RequestStatusFailure): Nothing = throw RequestStatusException(reason)
    }
}
