package dev.remozio.phone.push

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.security.MessageDigest

/** One exclusive owner supplies bounded reads and atomic replacement in private storage excluded from backups. */
interface PhonePushProofStorage {
    fun read(maximumBytes: Int): ByteArray?
    fun replace(bytes: ByteArray)
}

class PhonePushProofUnavailable : IllegalStateException("Push proof history unavailable")

/**
 * Commits a claim before any proof transmission. A lost result requires Root recovery, never automatic proof replay.
 * Callers check current enrollment, provider revision, attempt and deadline while holding their local locks.
 * No token or challenge enters this archive. Provider changes must not clear claims for a retained candidate.
 */
class PhonePushProofLedger(private val storage: PhonePushProofStorage, private val maximumEntries: Int) {
    private class Floor(val recordID: CborValue.Bytes, val namespace: CborValue.Bytes, val revision: ULong,
                        val candidateID: CborValue.Bytes, val fingerprint: CborValue.Bytes)
    private var floors = linkedMapOf<CborValue.Bytes, Floor>()
    private var unavailable = false
    private val limits: CborLimits

    init {
        require(maximumEntries in 1..8192)
        limits = CborLimits(MAXIMUM_BYTES, 4, maximumEntries * 8 + 16)
        try {
            storage.read(MAXIMUM_BYTES)?.let { bytes ->
                require(bytes.size in 1..MAXIMUM_BYTES)
                val fields = (DeterministicCbor.decode(bytes, limits) as CborValue.Fields).values
                require(fields.keys == setOf(0uL, 1uL, 2uL))
                require(fields[0u] == CborValue.Text(DOMAIN) && fields[1u] == CborValue.Unsigned(1u))
                val rows = (fields[2u] as CborValue.ArrayValue).values; require(rows.size <= maximumEntries)
                for (row in rows) {
                    val values = (row as CborValue.ArrayValue).values; require(values.size == 5)
                    fun bytes(i: Int, size: Int) = (values[i] as CborValue.Bytes).also { require(it.copyBytes().size == size) }
                    val revision = (values[2] as CborValue.Unsigned).value; require(revision > 0uL)
                    val floor = Floor(bytes(0, 16), bytes(1, 32), revision, bytes(3, 16), bytes(4, 32))
                    require(floors.put(floor.namespace, floor) == null)
                }
                require(encode(floors).contentEquals(bytes))
            }
        } catch (_: Exception) { throw PhonePushProofUnavailable() }
    }

    /** False requires recovery or a fresh candidate. It never authorizes another transmission. */
    @Synchronized fun claim(record: StoredPhoneEnrollment, metadata: PhonePushRegistrationMetadata,
                            offer: PhonePushTokenOffer): Boolean {
        checkAvailable()
        val e = record.enrollment
        require(record.phase == EnrollmentPhase.ACTIVE)
        require(metadata.scope == ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()))
        require(metadata.enrollmentTag.contentEquals(e.enrollmentTag.copyBytes()))
        require(metadata.tokenDigest.contentEquals(hash(offer.token.toByteArray(Charsets.UTF_8))))
        val namespaceBytes = listOf(e.recordID.copyBytes(), e.enrollmentTag.copyBytes(), metadata.ownerID, metadata.macID,
            metadata.accountID, metadata.gatewayID, metadata.lifecycleEpoch, metadata.phoneID, metadata.enrollmentEpoch)
        val namespace = CborValue.Bytes(hash(DeterministicCbor.encode(
            CborValue.ArrayValue(namespaceBytes.map { CborValue.Bytes(it) }), CborLimits(1024, 2, 16))))
        val fingerprint = CborValue.Bytes(hash(PhonePushRegistrationFrame.Prepared(ByteArray(16), metadata).encode()))
        val candidate = CborValue.Bytes(metadata.candidateID)
        val previous = floors[namespace]
        if (previous != null) {
            if (metadata.revision < previous.revision) return false
            if (metadata.revision == previous.revision) {
                require(previous.fingerprint == fingerprint)
                return false
            }
        }
        check(previous != null || floors.size < maximumEntries)
        val updated = LinkedHashMap(floors)
        updated[namespace] = Floor(e.recordID, namespace, metadata.revision, candidate, fingerprint)
        persist(updated)
        return previous?.candidateID != candidate
    }

    /** The application supplies the complete trusted active set, under its enrollment lock. */
    @Synchronized fun retainActiveRecords(activeRecordIDs: Set<CborValue.Bytes>) {
        checkAvailable(); require(activeRecordIDs.all { it.copyBytes().size == 16 })
        val updated = LinkedHashMap(floors.filterValues { it.recordID in activeRecordIDs })
        if (updated.size != floors.size) persist(updated)
    }
    private fun persist(updated: LinkedHashMap<CborValue.Bytes, Floor>) {
        val bytes = encode(updated)
        try { storage.replace(bytes) }
        catch (_: Exception) { unavailable = true; throw PhonePushProofUnavailable() }
        floors = updated
    }
    private fun encode(values: LinkedHashMap<CborValue.Bytes, Floor>): ByteArray = DeterministicCbor.encode(
        CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.ArrayValue(values.values.map { f -> CborValue.ArrayValue(listOf(
                f.recordID, f.namespace, CborValue.Unsigned(f.revision), f.candidateID, f.fingerprint)) }))), limits)
    private fun checkAvailable() { if (unavailable) throw PhonePushProofUnavailable() }
    override fun toString() = "PhonePushProofLedger(redacted)"
    companion object {
        private const val DOMAIN = "dev.remozio.phone.push.proof-attempts"
        private const val MAXIMUM_BYTES = 1_048_576
        private fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}
