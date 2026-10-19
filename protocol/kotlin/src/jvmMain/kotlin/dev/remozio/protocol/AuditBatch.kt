package dev.remozio.protocol

import java.util.Collections

class AuditBatchException : IllegalArgumentException("Invalid audit batch")

/** One epoch's contiguous page. This value does not establish authenticity, freshness or trust continuity. */
class AuditBatch private constructor(
    private val fields: CborValue.Fields,
    val epochCreationGeneration: ULong,
    val requestedAfter: ULong,
    val retainedAfter: ULong,
    val head: ULong,
    records: List<AuditEventMetadata>,
) {
    val records: List<AuditEventMetadata> = Collections.unmodifiableList(ArrayList(records))
    val macID: ByteArray get() = data(1u)
    val accountID: ByteArray get() = data(2u)
    val journalEpoch: ByteArray get() = data(3u)
    val queryNonce: ByteArray get() = data(8u)
    val pageAfter: ULong get() = maxOf(requestedAfter, retainedAfter)
    val nextAfter: ULong get() = pageAfter + records.size.toULong()
    val hasMore: Boolean get() = nextAfter < head
    val retentionGap: Boolean get() = requestedAfter < retainedAfter
    private fun data(key: ULong) = (fields.values.getValue(key) as CborValue.Bytes).copyBytes()
    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(fields, limits)

    companion object {
        fun decode(bytes: ByteArray, batchLimits: CborLimits, recordLimits: CborLimits, maximumRecords: Int): AuditBatch {
            if (maximumRecords <= 0) throw AuditBatchException()
            val value = DeterministicCbor.decode(bytes, batchLimits) as? CborValue.Fields ?: throw AuditBatchException()
            val f = value.values
            if (f.keys != (0uL..9uL).toSet() || f[0uL] != CborValue.Unsigned(1u)) throw AuditBatchException()
            fun uint(key: ULong) = (f[key] as? CborValue.Unsigned)?.value ?: throw AuditBatchException()
            fun id(key: ULong, size: Int): CborValue.Bytes = (f[key] as? CborValue.Bytes)
                ?.takeIf { it.size == size } ?: throw AuditBatchException()
            val mac = id(1u, 16); val account = id(2u, 16); val epoch = id(3u, 16)
            id(8u, 32)
            val generation = uint(4u); val after = uint(5u); val retained = uint(6u); val head = uint(7u)
            val rows = (f[9uL] as? CborValue.ArrayValue)?.values ?: throw AuditBatchException()
            val start = maxOf(after, retained)
            if (after > head || retained > head || rows.size > maximumRecords ||
                rows.size.toULong() > head - start || (rows.isEmpty() && start != head)) throw AuditBatchException()
            val seen = HashSet<CborValue.Bytes>()
            val records = rows.mapIndexed { index, row ->
                val raw = row as? CborValue.Bytes ?: throw AuditBatchException()
                if (raw.size > recordLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
                val record = AuditEventMetadata.decode(raw.copyBytes(), recordLimits)
                if (CborValue.Bytes(record.macID) != mac || CborValue.Bytes(record.accountID) != account ||
                    CborValue.Bytes(record.journalEpoch) != epoch || record.sequence != start + index.toULong() + 1uL ||
                    !seen.add(CborValue.Bytes(record.eventID))) throw AuditBatchException()
                record
            }
            return AuditBatch(value, generation, after, retained, head, records)
        }
    }
}
