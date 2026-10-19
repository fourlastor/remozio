package dev.remozio.protocol

enum class AuditEpochCause(val tag: ULong) {
    INITIAL(0u), RESTART(1u), REPLACEMENT(2u), RECOVERY(3u), RESTORATION(4u), UNKNOWN(5u),
}
enum class AuditHistoryDisposition(val tag: ULong) { DISCOVERY(0u), AVAILABLE(1u), UNAVAILABLE(2u), CURSOR_AHEAD(3u) }
class AuditHistoryException : IllegalArgumentException("Invalid audit history status")

private class AuditFields(bytes: ByteArray, limits: CborLimits, lastKey: ULong) {
    val value = DeterministicCbor.decode(bytes, limits) as? CborValue.Fields ?: throw AuditHistoryException()
    val fields = value.values
    init { if (fields.keys != (0uL..lastKey).toSet() || fields[0uL] != CborValue.Unsigned(1u)) throw AuditHistoryException() }
    fun uint(key: ULong) = (fields[key] as? CborValue.Unsigned)?.value ?: throw AuditHistoryException()
    fun optionalUInt(key: ULong) = if (fields[key] == CborValue.Null) null else uint(key)
    fun bytes(key: ULong): CborValue.Bytes = fields[key] as? CborValue.Bytes ?: throw AuditHistoryException()
    fun id(key: ULong, size: Int): CborValue.Bytes = bytes(key).also { if (it.size != size) throw AuditHistoryException() }
    fun optionalID(key: ULong, size: Int) = if (fields[key] == CborValue.Null) null else id(key, size)
}

/** Immutable epoch metadata. A prior boundary does not prove that no later records ever existed. */
class AuditEpochDescriptor private constructor(
    private val fields: CborValue.Fields,
    val generation: ULong,
    val cause: AuditEpochCause,
    val previousSequence: ULong?,
) {
    private fun data(key: ULong) = (fields.values.getValue(key) as CborValue.Bytes).copyBytes()
    val macID: ByteArray get() = data(1u)
    val accountID: ByteArray get() = data(2u)
    val epoch: ByteArray get() = data(3u)
    val previousEpoch: ByteArray? get() = if (fields.values[6uL] == CborValue.Null) null else data(6u)
    val previousEventDigest: ByteArray? get() = if (fields.values[8uL] == CborValue.Null) null else data(8u)
    fun encode(limits: CborLimits) = DeterministicCbor.encode(fields, limits)

    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits): AuditEpochDescriptor {
            val f = AuditFields(bytes, limits, 8u)
            f.id(1u, 16); f.id(2u, 16)
            val epoch = f.id(3u, 16); val generation = f.uint(4u)
            val cause = AuditEpochCause.entries.singleOrNull { it.tag == f.uint(5u) } ?: throw AuditHistoryException()
            val previous = f.optionalID(6u, 16); val sequence = f.optionalUInt(7u); val digest = f.optionalID(8u, 32)
            if ((previous == null) != (sequence == null) || previous == epoch ||
                (digest != null) != (sequence != null && sequence > 0uL) ||
                (cause == AuditEpochCause.INITIAL && previous != null)) throw AuditHistoryException()
            return AuditEpochDescriptor(f.value, generation, cause, sequence)
        }
    }
}

/** Query-bound discovery or reconciliation data. Signature, freshness and cached evidence checks are separate. */
class AuditHistoryStatus private constructor(
    private val fields: CborValue.Fields,
    val requestedAfter: ULong?,
    val disposition: AuditHistoryDisposition,
    val current: AuditEpochDescriptor,
    val currentRetainedAfter: ULong,
    val currentHead: ULong,
    val queried: AuditEpochDescriptor?,
    val queriedRetainedAfter: ULong?,
    val queriedHead: ULong?,
) {
    private fun data(key: ULong) = (fields.values.getValue(key) as CborValue.Bytes).copyBytes()
    val macID: ByteArray get() = data(1u)
    val accountID: ByteArray get() = data(2u)
    val queryNonce: ByteArray get() = data(3u)
    val requestedEpoch: ByteArray? get() = if (fields.values[4uL] == CborValue.Null) null else data(4u)
    fun encode(limits: CborLimits) = DeterministicCbor.encode(fields, limits)

    companion object {
        fun decode(bytes: ByteArray, limits: CborLimits, descriptorLimits: CborLimits): AuditHistoryStatus {
            val f = AuditFields(bytes, limits, 12u)
            val mac = f.id(1u, 16); val account = f.id(2u, 16); f.id(3u, 32)
            val requested = f.optionalID(4u, 16); val after = f.optionalUInt(5u)
            val disposition = AuditHistoryDisposition.entries.singleOrNull { it.tag == f.uint(6u) }
                ?: throw AuditHistoryException()
            fun descriptor(key: ULong): AuditEpochDescriptor {
                val body = f.bytes(key)
                if (body.size > descriptorLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
                return AuditEpochDescriptor.decode(body.copyBytes(), descriptorLimits).also {
                    if (CborValue.Bytes(it.macID) != mac || CborValue.Bytes(it.accountID) != account) throw AuditHistoryException()
                }
            }
            val current = descriptor(7u); val retained = f.uint(8u); val head = f.uint(9u)
            val queried = if (f.fields[10uL] == CborValue.Null) null else descriptor(10u)
            val queriedRetained = f.optionalUInt(11u); val queriedHead = f.optionalUInt(12u)
            if (retained > head || (requested == null) != (after == null) ||
                (queried == null) != (queriedRetained == null) || (queried == null) != (queriedHead == null)) throw AuditHistoryException()
            when (disposition) {
                AuditHistoryDisposition.DISCOVERY -> if (requested != null || queried != null) throw AuditHistoryException()
                AuditHistoryDisposition.UNAVAILABLE -> if (requested == null || queried != null ||
                    requested == CborValue.Bytes(current.epoch)) throw AuditHistoryException()
                AuditHistoryDisposition.AVAILABLE, AuditHistoryDisposition.CURSOR_AHEAD -> {
                    if (requested == null || after == null || queried == null || queriedRetained == null || queriedHead == null ||
                        requested != CborValue.Bytes(queried.epoch) || queriedRetained > queriedHead ||
                        (disposition == AuditHistoryDisposition.CURSOR_AHEAD) != (after > queriedHead)) throw AuditHistoryException()
                }
            }
            if (queried != null && queried.epoch.contentEquals(current.epoch) &&
                (f.fields[7uL] != f.fields[10uL] || retained != queriedRetained || head != queriedHead)) throw AuditHistoryException()
            return AuditHistoryStatus(f.value, after, disposition, current, retained, head, queried, queriedRetained, queriedHead)
        }
    }
}
