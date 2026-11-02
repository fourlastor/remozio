package dev.remozio.phone.audit

import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CborValue
import javax.crypto.AEADBadTagException

/** The caller supplies bindings from retained trusted enrollment, never from an archive or network greeting. */
class LegacyAuditArchive(ciphertext: ByteArray, internal val cipher: AuditArchiveCipher, bindings: List<AuditCacheBinding>) {
    internal val ciphertext = CborValue.Bytes(ciphertext)
    internal val bindings = bindings.distinctBy { CborValue.Bytes(it.authorityPublicKey) }.toList()
    init {
        require(ciphertext.size in 36..cipher.maximumCiphertextBytes && bindings.size in 1..1024)
        val first = bindings.first()
        require(bindings.all { it.macID.contentEquals(first.macID) && it.accountID.contentEquals(first.accountID) })
    }
    override fun toString() = "LegacyAuditArchive(redacted)"
}

class AuditMigrationUnavailable : IllegalStateException("Legacy audit archive unavailable")

/** Copy verified legacy evidence into a separately owned archive. This never writes or deletes the legacy source. */
object AuditCacheMigration {
    fun open(storage: AuditCiphertextStorage, cipher: AuditArchiveCipher, binding: AuditCacheBinding,
             protocolLimits: AuditPageLimits, capacity: AuditEvidenceLimits, archiveLimits: CborLimits,
             legacy: LegacyAuditArchive? = null,
             localSync: (AuditEvidenceSnapshot) -> AuditLocalSyncArchive? = { null }): EncryptedAuditCache {
        require(cipher.maximumPlaintextBytes == archiveLimits.maxBytes)
        if (storage.read(cipher.maximumCiphertextBytes) != null || legacy == null) {
            return EncryptedAuditCache.open(storage, cipher, binding, protocolLimits, capacity, archiveLimits, localSync)
        }
        val first = legacy.bindings.first()
        require(binding.macID.contentEquals(first.macID) && binding.accountID.contentEquals(first.accountID))
        var source: AuditCacheBinding? = null
        for (candidate in legacy.bindings) {
            val memory = ReadOnlyCiphertext(legacy.ciphertext)
            try {
                EncryptedAuditCache.open(memory, legacy.cipher, candidate, protocolLimits, capacity, archiveLimits).use { it.snapshot() }
                source = candidate
                break
            } catch (_: AEADBadTagException) {
                // An authenticated removed enrollment may own the legacy ciphertext instead.
            } finally { memory.close() }
        }
        val verified = source ?: throw AuditMigrationUnavailable()
        if (verified.authorityPublicKey.contentEquals(binding.authorityPublicKey)) {
            val plaintext = legacy.cipher.decrypt(legacy.ciphertext.copyBytes(), verified)
            val replacement = try { cipher.encrypt(plaintext, binding) } finally { plaintext.fill(0) }
            storage.replace(replacement)
            if (storage.read(cipher.maximumCiphertextBytes)?.contentEquals(replacement) != true) throw AuditMigrationUnavailable()
        }
        // A verified archive for another retained Root stays independent; the new Root starts its own archive.
        return EncryptedAuditCache.open(storage, cipher, binding, protocolLimits, capacity, archiveLimits, localSync)
    }
    private class ReadOnlyCiphertext(private val bytes: CborValue.Bytes) : AuditCiphertextStorage {
        override fun read(maximumBytes: Int): ByteArray {
            require(bytes.size <= maximumBytes)
            return bytes.copyBytes()
        }
        override fun replace(ciphertext: ByteArray): Nothing = error("Legacy evidence is read-only")
        override fun close() = Unit
    }
}
