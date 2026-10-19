package dev.remozio.protocol

enum class AuditEventKind(val tag: ULong) {
    UNKNOWN(0u), REQUEST_CREATED(1u), PHONE_DECISION(2u), DECISION_ACCEPTED(3u),
    DECISION_REJECTED(4u), CONSUMED(5u), DISPATCHED(6u), VERIFIED_RESULT(7u),
    EXPIRED(8u), CANCELLED(9u), UNKNOWN_OUTCOME(10u), ENROLLMENT_ADDED(11u),
    ENROLLMENT_REVOKED(12u), RECOVERY(13u), UPDATE_SCHEDULED(14u), UPDATE_ACTIVATED(15u),
    UPDATE_INTERRUPTED(16u), BRIDGE_STARTED(17u), BRIDGE_STOPPED(18u), DISMISSED(19u),
    BIOMETRIC_CANCELLED(20u), AGGREGATED_REJECTIONS(21u), ROUTING_CHANGED(22u);
}

enum class AuditCategory(val tag: ULong) {
    UNKNOWN(0u), COMMAND(1u), ONE_PASSWORD_ACCESS(2u), ONE_PASSWORD_UNLOCK(3u),
    LITTLE_SNITCH(4u), ENROLLMENT(5u), AUTHORITY(6u), UPDATE(7u),
    ADB_BRIDGE(8u);
}

enum class AuditActionKind(val tag: ULong) {
    UNKNOWN(0u), DECLINE(1u), CANCEL_TARGET(2u), EXECUTE(3u),
    APPROVE_ACCESS(4u), UNLOCK_VAULT(5u), ALLOW(6u), DENY(7u),
    REMOVE_RULE(8u);
}

enum class AuditLifetime(val tag: ULong) {
    UNKNOWN(0u), CURRENT_REQUEST(1u), SESSION(2u), TIMED(3u),
    FOREVER(4u);
}

enum class AuditTargetScope(val tag: ULong) {
    UNKNOWN(0u), HOST(1u), DOMAIN(2u), ANY(3u);
}

enum class AuditAuthentication(val tag: ULong) {
    UNKNOWN(0u), UNVERIFIED(1u), DECISION_KEY(2u), BIOMETRIC_KEY(3u),
    LOCAL_ADMINISTRATOR(4u), SYSTEM(5u), LOCAL_USER(6u);
}

enum class AuditOutcome(val tag: ULong) {
    UNKNOWN(0u), PENDING(1u), ACCEPTED(2u), REJECTED(3u),
    NO_DISPATCH(4u), ATTEMPTED(5u), VERIFIED_SUCCESS(6u), VERIFIED_FAILURE(7u),
    UNRESOLVED(8u), CANCELLED(9u), EXPIRED(10u);
}

enum class AuditReason(val tag: ULong) {
    UNKNOWN(0u), NONE(1u), USER_DECLINED(2u), USER_CANCELLED(3u),
    AUTHORIZATION_EXPIRED(4u), TARGET_TIMED_OUT(5u), TARGET_DISAPPEARED(6u), REVOKED(7u),
    BINDING_MISMATCH(8u), REPLAY(9u), INCOMPATIBLE(10u), AUTHORITY_RESTARTED(11u),
    STORAGE_UNAVAILABLE(12u), OUTCOME_UNAVAILABLE(13u), UPDATE_INTERRUPTED(14u), PEER_DISCONNECTED(15u),
    MANUAL_STOP(16u);
}

/** Privacy projection only. It neither validates a decision nor retains a timed duration or target value. */
data class AuditActionMetadata(val kind: AuditActionKind, val lifetime: AuditLifetime, val target: AuditTargetScope?) {
    companion object {
        fun from(action: CapturedAction, target: AuditTargetScope? = null) = AuditActionMetadata(
            when (action.choice) {
                ActionChoice.DECLINE -> AuditActionKind.DECLINE
                ActionChoice.CANCEL_TARGET -> AuditActionKind.CANCEL_TARGET
                ActionChoice.EXECUTE -> AuditActionKind.EXECUTE
                ActionChoice.APPROVE_ACCESS -> AuditActionKind.APPROVE_ACCESS
                ActionChoice.UNLOCK_VAULT -> AuditActionKind.UNLOCK_VAULT
                ActionChoice.ALLOW_ONCE, ActionChoice.ALLOW_RULE -> AuditActionKind.ALLOW
                ActionChoice.DENY_ONCE, ActionChoice.DENY_RULE -> AuditActionKind.DENY
                ActionChoice.REMOVE_RULE -> AuditActionKind.REMOVE_RULE
            }, when (action.scope) {
                ActionScope.CurrentRequest -> AuditLifetime.CURRENT_REQUEST
                ActionScope.Session -> AuditLifetime.SESSION
                is ActionScope.Timed -> AuditLifetime.TIMED
                ActionScope.Forever -> AuditLifetime.FOREVER
            }, target)
    }
}

class AuditEventException : IllegalArgumentException("Invalid audit event metadata")

/** Unauthenticated metadata. Journal ordering, integrity, retention and event truth are external obligations. */
class AuditEventMetadata(
    eventID: ByteArray, macID: ByteArray, accountID: ByteArray, journalEpoch: ByteArray,
    val sequence: ULong, requestID: ByteArray?, val eventTimeMs: ULong?, val authorityReceiptTimeMs: ULong?,
    val kind: AuditEventKind, val category: AuditCategory, val action: AuditActionMetadata?,
    decisionPhoneID: ByteArray?, val authentication: AuditAuthentication, val outcome: AuditOutcome,
    val reason: AuditReason, val droppedEventCount: ULong?, peerDeviceID: ByteArray?,
) {
    init {
        if (listOf(eventID, macID, accountID, journalEpoch, requestID, decisionPhoneID, peerDeviceID)
                .any { it != null && it.size != 16 } || sequence == 0uL) throw AuditEventException()
        if ((kind == AuditEventKind.AGGREGATED_REJECTIONS) != (droppedEventCount != null) ||
            droppedEventCount == 0uL) throw AuditEventException()
    }
    private val ids = listOf(eventID, macID, accountID, journalEpoch, requestID, decisionPhoneID, peerDeviceID)
        .map { it?.let(CborValue::Bytes) }
    val eventID: ByteArray get() = ids[0]!!.copyBytes()
    val macID: ByteArray get() = ids[1]!!.copyBytes()
    val accountID: ByteArray get() = ids[2]!!.copyBytes()
    val journalEpoch: ByteArray get() = ids[3]!!.copyBytes()
    val requestID: ByteArray? get() = ids[4]?.copyBytes()
    val decisionPhoneID: ByteArray? get() = ids[5]?.copyBytes()
    val peerDeviceID: ByteArray? get() = ids[6]?.copyBytes()

    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to ids[0]!!, 2uL to ids[1]!!, 3uL to ids[2]!!, 4uL to ids[3]!!,
        5uL to CborValue.Unsigned(sequence), 6uL to (ids[4] ?: CborValue.Null),
        7uL to number(eventTimeMs), 8uL to number(authorityReceiptTimeMs), 9uL to number(kind.tag),
        10uL to number(category.tag), 11uL to number(action?.kind?.tag), 12uL to number(action?.lifetime?.tag),
        13uL to number(action?.target?.tag), 14uL to (ids[5] ?: CborValue.Null),
        15uL to number(authentication.tag), 16uL to number(outcome.tag), 17uL to number(reason.tag),
        18uL to number(droppedEventCount), 19uL to (ids[6] ?: CborValue.Null),
    )), limits)

    companion object {
        private fun number(value: ULong?) = value?.let(CborValue::Unsigned) ?: CborValue.Null
        fun decode(bytes: ByteArray, limits: CborLimits): AuditEventMetadata {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: throw AuditEventException()
            if (fields.keys != (0uL..19uL).toSet() || fields[0uL] != CborValue.Unsigned(1u)) throw AuditEventException()
            fun uint(key: ULong) = (fields[key] as? CborValue.Unsigned)?.value ?: throw AuditEventException()
            fun optional(key: ULong) = if (fields[key] == CborValue.Null) null else uint(key)
            fun data(key: ULong) = (fields[key] as? CborValue.Bytes)?.copyBytes() ?: throw AuditEventException()
            fun optionalData(key: ULong) = if (fields[key] == CborValue.Null) null else data(key)
            fun <T> tag(key: ULong, values: List<T>, code: (T) -> ULong): T =
                values.singleOrNull { code(it) == uint(key) } ?: throw AuditEventException()
            val action = if (fields[11uL] == CborValue.Null) {
                if (fields[12uL] != CborValue.Null || fields[13uL] != CborValue.Null) throw AuditEventException()
                null
            } else AuditActionMetadata(tag(11u, AuditActionKind.entries) { it.tag },
                tag(12u, AuditLifetime.entries) { it.tag },
                if (fields[13uL] == CborValue.Null) null else tag(13u, AuditTargetScope.entries) { it.tag })
            return AuditEventMetadata(data(1u), data(2u), data(3u), data(4u), uint(5u), optionalData(6u),
                optional(7u), optional(8u), tag(9u, AuditEventKind.entries) { it.tag },
                tag(10u, AuditCategory.entries) { it.tag }, action, optionalData(14u),
                tag(15u, AuditAuthentication.entries) { it.tag }, tag(16u, AuditOutcome.entries) { it.tag },
                tag(17u, AuditReason.entries) { it.tag }, optional(18u), optionalData(19u))
        }
    }
}
