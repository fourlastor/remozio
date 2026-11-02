package dev.remozio.android.audit

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import dev.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.audit.*
import dev.remozio.protocol.CborLimits
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** Blocking I/O. The enrollment owner calls this off the main thread and closes the cache when it is retired. */
internal object AndroidAuditCache {
    /** Read retained evidence only. Absence means no cached history, not an empty Mac journal. */
    fun openExisting(context: Context, binding: AuditCacheBinding, protocol: AuditPageLimits,
                     capacity: AuditEvidenceLimits, archiveLimits: CborLimits): EncryptedAuditCache? {
        val app = context.applicationContext
        check(!app.isDeviceProtectedStorage)
        val directory = File(app.noBackupFilesDir, "audit")
        if (!directory.exists()) return null
        if (!directory.isDirectory) throw IOException("Audit directory unavailable")
        val current = AuditCacheIdentity.current(binding)
        val currentStorage = AndroidAuditStorage(File(directory, "v2-$current.cache"), requireArchive = true)
        try {
            if (currentStorage.hasArchive()) {
                val key = AuditCacheKey.load("remozio.audit-cache.v2.$current", allowCreation = false)
                return EncryptedAuditCache.open(currentStorage, AuditArchiveCipher(key, archiveLimits.maxBytes), binding,
                    protocol, capacity, archiveLimits,
                    localSync = { verified -> localSync(directory, current, key, binding, verified) })
            }
        } catch (failure: Throwable) { currentStorage.close(); throw failure }
        currentStorage.close()
        val legacy = AuditCacheIdentity.legacy(binding)
        val storage = AndroidAuditStorage(File(directory, "$legacy.cache"), requireArchive = true)
        try {
            if (!storage.hasArchive()) { storage.close(); return null }
            val key = AuditCacheKey.load("remozio.audit-cache.v1.$legacy", allowCreation = false)
            return EncryptedAuditCache.open(storage, AuditArchiveCipher(key, archiveLimits.maxBytes), binding,
                protocol, capacity, archiveLimits)
        } catch (failure: Throwable) { storage.close(); throw failure }
    }

    fun open(context: Context, binding: AuditCacheBinding, protocol: AuditPageLimits,
             capacity: AuditEvidenceLimits, archiveLimits: CborLimits,
             retainedBindings: List<AuditCacheBinding> = listOf(binding)): EncryptedAuditCache {
        val app = context.applicationContext
        check(!app.isDeviceProtectedStorage)
        val identity = AuditCacheIdentity.current(binding)
        val directory = File(app.noBackupFilesDir, "audit")
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Audit directory unavailable")
        val storage = AndroidAuditStorage(File(directory, "v2-$identity.cache"))
        try {
            val existing = storage.hasArchive()
            val legacy = if (existing) null else readLegacy(directory, binding, retainedBindings, archiveLimits)
            val key = AuditCacheKey.load("remozio.audit-cache.v2.$identity", allowCreation = !existing)
            return AuditCacheMigration.open(storage, AuditArchiveCipher(key, archiveLimits.maxBytes), binding,
                protocol, capacity, archiveLimits, legacy,
                localSync = { verified -> localSync(directory, identity, key, binding, verified) })
        } catch (failure: Throwable) { storage.close(); throw failure }
    }

    /** The already-held v2 cache lock protects the sidecar for the same Mac/account/Root until both close. */
    private fun localSync(directory: File, identity: String, key: SecretKey, binding: AuditCacheBinding,
                          verified: AuditEvidenceSnapshot): AuditLocalSyncArchive = AuditLocalSyncArchive.open(
        AndroidAuditStorage(File(directory, "v2-$identity.local-sync"), parentOwnsFileAccess = true),
        key, binding, verified, System::currentTimeMillis)

    private fun readLegacy(directory: File, binding: AuditCacheBinding, retainedBindings: List<AuditCacheBinding>,
                           archiveLimits: CborLimits): LegacyAuditArchive? {
        val identity = AuditCacheIdentity.legacy(binding)
        AndroidAuditStorage(File(directory, "$identity.cache"), requireArchive = true).use { storage ->
            if (!storage.hasArchive()) return null
            val key = AuditCacheKey.load("remozio.audit-cache.v1.$identity", allowCreation = false)
            val cipher = AuditArchiveCipher(key, archiveLimits.maxBytes)
            return LegacyAuditArchive(storage.readForMigration(cipher.maximumCiphertextBytes), cipher, retainedBindings)
        }
    }
}

/** One process-wide key operation at a time. Existing aliases are never overwritten or silently repaired. */
private object AuditCacheKey {
    @Synchronized
    fun load(alias: String, allowCreation: Boolean): SecretKey {
        fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store().containsAlias(alias)) {
            check(allowCreation) { "Audit encryption key unavailable" }
            try { generate(alias, strongBox = true) }
            catch (_: StrongBoxUnavailableException) {
                if (!store().containsAlias(alias)) generate(alias, strongBox = false)
            }
        }
        val key = checkNotNull(store().getKey(alias, null) as? SecretKey) { "Audit encryption key unavailable" }
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        check(key.algorithm == KeyProperties.KEY_ALGORITHM_AES && key.encoded == null && info.keySize == 256)
        check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX || info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
        check(info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT))
        check(info.blockModes.toSet() == setOf(KeyProperties.BLOCK_MODE_GCM))
        check(info.encryptionPaddings.toSet() == setOf(KeyProperties.ENCRYPTION_PADDING_NONE))
        check(!info.isUserAuthenticationRequired && !info.isUnlockedDeviceRequired)
        return key
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .setUnlockedDeviceRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }
}

/** Holds an OS file lock for the whole cache lifetime. AtomicFile itself provides no mutual exclusion. */
private class AndroidAuditStorage(private val base: File, private val requireArchive: Boolean = false,
                                  parentOwnsFileAccess: Boolean = false) : AuditCiphertextStorage {
    private val owner = if (parentOwnsFileAccess) null else ExclusiveFileOwner.acquire(File(base.path + ".lock"))
    private val atomic = AtomicFile(base)
    private var closed = false

    @Synchronized
    fun hasArchive(): Boolean = listOf(base, File(base.path + ".bak"), File(base.path + ".new")).any { it.exists() }

    @Synchronized
    override fun read(maximumBytes: Int): ByteArray? {
        check(!closed)
        require(maximumBytes > 0)
        val archiveWasPresent = hasArchive()
        val input = try { atomic.openRead() } catch (failure: FileNotFoundException) {
            if (!requireArchive && !archiveWasPresent && !hasArchive()) return null
            throw failure
        }
        return readBounded(input, maximumBytes)
    }

    /** AtomicFile recovery can alter sidecars. Migration only copies a stable source and never invokes recovery. */
    @Synchronized
    fun readForMigration(maximumBytes: Int): ByteArray {
        check(!closed)
        require(maximumBytes > 0)
        if (File(base.path + ".bak").exists() || File(base.path + ".new").exists()) {
            throw IOException("Legacy audit archive requires recovery before migration")
        }
        return readBounded(base.inputStream(), maximumBytes)
    }

    private fun readBounded(input: java.io.InputStream, maximumBytes: Int): ByteArray = input.use {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = it.read(buffer)
            if (count < 0) break
            if (count > maximumBytes - output.size()) throw IOException("Audit cache exceeds configured size")
            output.write(buffer, 0, count)
        }
        output.toByteArray()
    }

    @Synchronized
    override fun replace(ciphertext: ByteArray) {
        check(!closed)
        val output = atomic.startWrite()
        try {
            output.write(ciphertext)
            output.fd.sync()
            atomic.finishWrite(output)
        } catch (failure: Throwable) {
            atomic.failWrite(output)
            throw failure
        }
        if (read(ciphertext.size)?.contentEquals(ciphertext) != true) throw IOException("Audit cache replacement was not verified")
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            owner?.close()
        }
    }
}
