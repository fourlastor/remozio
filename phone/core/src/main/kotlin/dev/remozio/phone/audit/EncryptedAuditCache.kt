package dev.remozio.phone.audit

import dev.remozio.protocol.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AuditCacheException : IllegalArgumentException("Invalid audit cache")

/** The implementation owns exclusive file access and must bound reads and replace ciphertext atomically. */
interface AuditCiphertextStorage : AutoCloseable {
    fun read(maximumBytes: Int): ByteArray?
    fun replace(ciphertext: ByteArray)
}

/** Binds local ciphertext to the trusted enrollment. It does not establish that enrollment. */
class AuditCacheBinding(macID: ByteArray, accountID: ByteArray, authorityPublicKey: ByteArray) {
    init { require(macID.size == 16 && accountID.size == 16 && authorityPublicKey.size == 65 && authorityPublicKey[0] == 4.toByte()) }
    private val mac = CborValue.Bytes(macID)
    private val account = CborValue.Bytes(accountID)
    private val authority = CborValue.Bytes(authorityPublicKey)
    val macID: ByteArray get() = mac.copyBytes()
    val accountID: ByteArray get() = account.copyBytes()
    val authorityPublicKey: ByteArray get() = authority.copyBytes()
    internal fun associatedData(domain: String = "dev.remozio.audit-cache") = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Text(domain), 1uL to CborValue.Unsigned(1u),
        2uL to mac, 3uL to account, 4uL to authority,
    )), CborLimits(256, 2, 16))
}

/** Production supplies an Android Keystore key. This class never generates or exports key material. */
class AuditArchiveCipher private constructor(private val key: SecretKey, val maximumPlaintextBytes: Int,
    private val domain: String, private val magic: ByteArray) {
    constructor(key: SecretKey, maximumPlaintextBytes: Int) : this(key, maximumPlaintextBytes,
        "dev.remozio.audit-cache", "RMZAUD01".encodeToByteArray())
    internal companion object {
        fun localSync(key: SecretKey) = AuditArchiveCipher(key, 1024,
            "dev.remozio.audit-local-sync", "RMZAS001".encodeToByteArray())
    }
    init { require(maximumPlaintextBytes > 0 && maximumPlaintextBytes <= Int.MAX_VALUE - 36) }
    val maximumCiphertextBytes: Int get() = maximumPlaintextBytes + 36

    fun encrypt(plaintext: ByteArray, binding: AuditCacheBinding): ByteArray {
        if (plaintext.size > maximumPlaintextBytes) throw AuditCacheException()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        if (iv.size != 12 || cipher.parameters.getParameterSpec(GCMParameterSpec::class.java).tLen != 128) throw AuditCacheException()
        cipher.updateAAD(binding.associatedData(domain))
        val encrypted = cipher.doFinal(plaintext)
        if (encrypted.size != plaintext.size + 16) throw AuditCacheException()
        return magic + iv + encrypted
    }

    fun decrypt(envelope: ByteArray, binding: AuditCacheBinding): ByteArray {
        if (envelope.size !in 36..maximumCiphertextBytes || !envelope.copyOfRange(0, 8).contentEquals(magic)) throw AuditCacheException()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(8, 20)))
        cipher.updateAAD(binding.associatedData(domain))
        return cipher.doFinal(envelope, 20, envelope.size - 20)
    }
}

/**
 * Serial cache operations publish new evidence only after encrypted replacement succeeds.
 * The storage owner must retain exclusive access until close. All methods perform blocking I/O.
 */
class EncryptedAuditCache private constructor(
    private val storage: AuditCiphertextStorage,
    private val cipher: AuditArchiveCipher,
    internal val binding: AuditCacheBinding,
    internal val protocolLimits: AuditPageLimits,
    private val capacity: AuditEvidenceLimits,
    private val archiveLimits: CborLimits,
    private var evidence: AuditEvidenceStore,
    private val localSync: AuditLocalSyncArchive?,
) : AutoCloseable {
    private var closed = false
    private var writeFailed = false

    @Synchronized
    fun snapshot(): AuditEvidenceSnapshot { check(!closed) { "Audit cache is closed" }; return evidence.snapshot() }

    /** Local display metadata only. Missing or damaged metadata never changes the verified evidence snapshot. */
    @Synchronized
    fun localSyncTimes(): AuditLocalSyncTimes? { check(!closed); return localSync?.snapshot() }

    /** Only the live receiver path calls this, after durable proof acceptance. Offline import never records a sync. */
    @Synchronized
    internal fun recordLocalSync(kind: AuditEvidenceKind, body: ByteArray, completed: Boolean) {
        check(!closed && !writeFailed)
        val archive = localSync ?: return
        val bodyID = CborValue.Bytes(body)
        val selected = evidence.snapshot().proofs.single { it.kind == kind && it.canonicalBody == bodyID }
        archive.record(selected, completed)
    }

    @Synchronized
    fun append(receipt: ReceivedAuditPage): AuditEvidenceAcceptance = appendProof(AuditEvidenceKind.PAGE, receipt.canonicalBody, receipt.signature)

    @Synchronized
    fun append(receipt: ReceivedAuditHistory): AuditEvidenceAcceptance = appendProof(AuditEvidenceKind.HISTORY_STATUS, receipt.canonicalBody, receipt.signature)

    private fun appendProof(kind: AuditEvidenceKind, body: ByteArray, signature: ByteArray): AuditEvidenceAcceptance {
        check(!closed && !writeFailed) { "Reopen the audit cache before writing" }
        val candidate = newStore(binding, protocolLimits, capacity)
        for (proof in evidence.snapshot().proofs) candidate.importEvidence(proof.kind, proof.canonicalBody.copyBytes(), proof.signature.copyBytes())
        val result = candidate.importEvidence(kind, body, signature)
        if (result == AuditEvidenceAcceptance.DUPLICATE) return result
        val plaintext = encode(candidate.snapshot(), archiveLimits)
        val encrypted = try { cipher.encrypt(plaintext, binding) } finally { plaintext.fill(0) }
        try { storage.replace(encrypted) } catch (failure: Throwable) {
            writeFailed = true
            throw failure
        }
        evidence = candidate
        return result
    }

    @Synchronized
    override fun close() {
        if (!closed) { closed = true; try { localSync?.close() } finally { storage.close() } }
    }

    companion object {
        /** On failure, the caller still owns storage and must close it. No failed load resets or overwrites a cache. */
        fun open(storage: AuditCiphertextStorage, cipher: AuditArchiveCipher, binding: AuditCacheBinding,
                 protocolLimits: AuditPageLimits, capacity: AuditEvidenceLimits, archiveLimits: CborLimits,
                 localSync: (AuditEvidenceSnapshot) -> AuditLocalSyncArchive? = { null }): EncryptedAuditCache {
            require(cipher.maximumPlaintextBytes == archiveLimits.maxBytes)
            val bytes = storage.read(cipher.maximumCiphertextBytes)
            val restored = newStore(binding, protocolLimits, capacity)
            if (bytes != null) {
                val plaintext = cipher.decrypt(bytes, binding)
                try { restore(plaintext, restored, archiveLimits, capacity.maximumProofs) } finally { plaintext.fill(0) }
            }
            return EncryptedAuditCache(storage, cipher, binding, protocolLimits, capacity, archiveLimits, restored, localSync(restored.snapshot()))
        }

        private fun newStore(binding: AuditCacheBinding, limits: AuditPageLimits, capacity: AuditEvidenceLimits) =
            AuditEvidenceStore(binding.macID, binding.accountID, binding.authorityPublicKey, limits, capacity)

        private fun encode(snapshot: AuditEvidenceSnapshot, limits: CborLimits): ByteArray =
            DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to CborValue.ArrayValue(snapshot.proofs.map { proof ->
                    CborValue.Fields(mapOf(0uL to CborValue.Unsigned(if (proof.kind == AuditEvidenceKind.PAGE) 1u else 2u),
                        1uL to proof.canonicalBody, 2uL to proof.signature))
                }),
            )), limits)

        private fun restore(bytes: ByteArray, target: AuditEvidenceStore, limits: CborLimits, maximumProofs: Int) {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: throw AuditCacheException()
            if (fields.keys != setOf(0uL, 1uL) || fields[0uL] != CborValue.Unsigned(1u)) throw AuditCacheException()
            val rows = (fields[1uL] as? CborValue.ArrayValue)?.values ?: throw AuditCacheException()
            if (rows.size > maximumProofs) throw AuditCacheException()
            for (row in rows) {
                val proof = (row as? CborValue.Fields)?.values ?: throw AuditCacheException()
                if (proof.keys != setOf(0uL, 1uL, 2uL)) throw AuditCacheException()
                val kind = when (proof[0uL]) {
                    CborValue.Unsigned(1u) -> AuditEvidenceKind.PAGE
                    CborValue.Unsigned(2u) -> AuditEvidenceKind.HISTORY_STATUS
                    else -> throw AuditCacheException()
                }
                val body = proof[1uL] as? CborValue.Bytes ?: throw AuditCacheException()
                val signature = proof[2uL] as? CborValue.Bytes ?: throw AuditCacheException()
                if (signature.size != 64) throw AuditCacheException()
                if (target.importEvidence(kind, body.copyBytes(), signature.copyBytes()) == AuditEvidenceAcceptance.DUPLICATE) {
                    throw AuditCacheException()
                }
            }
        }
    }
}
