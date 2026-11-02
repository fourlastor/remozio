package dev.remozio.phone.audit

import dev.remozio.protocol.*
import java.security.MessageDigest
import javax.crypto.SecretKey

/** A local phone-clock observation, never a Root statement, current trust, presence or action authority. */
data class AuditLocalSyncTime(val unixMilliseconds: Long, val proofID: CborValue.Bytes) {
    init { require(unixMilliseconds in 1..253_402_300_799_999L && proofID.size == 32) }
    override fun toString() = "AuditLocalSyncTime(redacted)"
}

data class AuditLocalSyncTimes(val lastResponse: AuditLocalSyncTime, val lastCompleted: AuditLocalSyncTime?) {
    override fun toString() = "AuditLocalSyncTimes(redacted)"
}

/**
 * Optional encrypted display metadata beside the unchanged signed-proof archive. The cache's exclusive file owner
 * also protects this sidecar. Failed metadata reads/writes do not erase evidence or establish fresh authority.
 */
class AuditLocalSyncArchive private constructor(
    private val storage: AuditCiphertextStorage,
    private val cipher: AuditArchiveCipher,
    private val binding: AuditCacheBinding,
    private val phoneClock: () -> Long,
    private var confirmed: AuditLocalSyncTimes?,
) : AutoCloseable {
    private var closed = false
    @Synchronized fun snapshot(): AuditLocalSyncTimes? { check(!closed); return confirmed }

    /** The caller supplies a retained verified proof from a fresh live receiver, after its durable cache append. */
    @Synchronized internal fun record(proof: StoredAuditProof, completed: Boolean) {
        check(!closed)
        try {
            require(!completed || proof.conflicts.isEmpty())
            val time = AuditLocalSyncTime(phoneClock(), fingerprint(proof))
            val candidate = AuditLocalSyncTimes(time, if (completed) time else confirmed?.lastCompleted)
            val plaintext = encode(candidate)
            val encrypted = try { cipher.encrypt(plaintext, binding) } finally { plaintext.fill(0) }
            storage.replace(encrypted)
            check(storage.read(cipher.maximumCiphertextBytes)?.contentEquals(encrypted) == true)
            confirmed = candidate
        } catch (_: Exception) {
            // The cache remains readable. An ambiguous metadata write cannot advance the displayed local time.
        }
    }

    @Synchronized override fun close() { if (!closed) { closed = true; storage.close() } }

    companion object {
        private val limits = CborLimits(1024, 3, 24)
        /** Loading checks retained proof references but never records the import as a fresh receipt or completed sync. */
        fun open(storage: AuditCiphertextStorage, key: SecretKey, binding: AuditCacheBinding,
                 verified: AuditEvidenceSnapshot, phoneClock: () -> Long): AuditLocalSyncArchive {
            require(verified.scope == AuditHistoryScope(CborValue.Bytes(binding.macID), CborValue.Bytes(binding.accountID)))
            val cipher = AuditArchiveCipher.localSync(key)
            val restored = try {
                storage.read(cipher.maximumCiphertextBytes)?.let { encrypted ->
                    val plaintext = cipher.decrypt(encrypted, binding)
                    val value = try { decode(plaintext) } finally { plaintext.fill(0) }
                    val proofs = verified.proofs.associateBy(::fingerprint)
                    require(value.lastResponse.proofID in proofs)
                    value.lastCompleted?.let { require(proofs[it.proofID]?.conflicts?.isEmpty() == true) }
                    value
                }
            } catch (_: Exception) { null }
            return AuditLocalSyncArchive(storage, cipher, binding, phoneClock, restored)
        }

        private fun fingerprint(proof: StoredAuditProof): CborValue.Bytes = CborValue.Bytes(
            MessageDigest.getInstance("SHA-256").run {
                update("dev.remozio.audit-local-proof/1".encodeToByteArray())
                update(if (proof.kind == AuditEvidenceKind.PAGE) 1.toByte() else 2.toByte())
                update(proof.canonicalBody.copyBytes()); update(proof.signature.copyBytes()); digest()
            })
        private fun value(time: AuditLocalSyncTime?): CborValue = time?.let {
            CborValue.ArrayValue(listOf(CborValue.Unsigned(it.unixMilliseconds.toULong()), it.proofID))
        } ?: CborValue.Null
        private fun encode(times: AuditLocalSyncTimes): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to value(times.lastResponse), 2uL to value(times.lastCompleted),
        )), limits)
        private fun decode(bytes: ByteArray): AuditLocalSyncTimes {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: error("Invalid local sync metadata")
            require(fields.keys == setOf(0uL, 1uL, 2uL) && fields[0uL] == CborValue.Unsigned(1u))
            fun time(value: CborValue?): AuditLocalSyncTime? {
                if (value == CborValue.Null) return null
                val row = (value as? CborValue.ArrayValue)?.values ?: error("Invalid local sync time")
                require(row.size == 2)
                val number = (row[0] as? CborValue.Unsigned)?.value ?: error("Invalid local sync time")
                require(number <= Long.MAX_VALUE.toULong())
                return AuditLocalSyncTime(number.toLong(), row[1] as? CborValue.Bytes ?: error("Invalid local sync proof"))
            }
            return AuditLocalSyncTimes(requireNotNull(time(fields[1uL])), time(fields[2uL]))
        }
    }
}
