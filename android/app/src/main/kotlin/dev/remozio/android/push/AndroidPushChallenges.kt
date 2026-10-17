package dev.remozio.android.push

import android.content.Context
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import androidx.annotation.WorkerThread
import dev.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.push.PendingPushChallenges
import dev.remozio.phone.push.PendingPushChallengeTicket
import dev.remozio.phone.push.PushChallengeCipher
import dev.remozio.phone.push.PushChallengeStorage
import dev.remozio.protocol.PhonePushRegistrationMetadata
import dev.remozio.protocol.PushData
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

/** Private encrypted buffers retain provider deliveries, never approval authority or proof-consumption history. */
internal class AndroidPushChallenges private constructor(private val storage: PushChallengeFile,
                                                         private val journal: PendingPushChallenges) : PushChallengeOwner {
    private var closed = false
    @Synchronized override fun selectGeneration(generation: UUID, moment: PushChallengeMoment) {
        check(!closed); journal.selectGeneration(generation, moment.bootEpoch, moment.milliseconds)
    }
    @Synchronized override fun admit(generation: UUID, challenge: PushData.TokenChallenge, moment: PushChallengeMoment): PendingPushChallengeTicket? {
        check(!closed); return journal.admit(generation, challenge, moment.bootEpoch, moment.milliseconds)
    }
    @Synchronized override fun pending(generation: UUID, moment: PushChallengeMoment): List<PendingPushChallengeTicket> {
        check(!closed); return journal.pending(generation, moment.bootEpoch, moment.milliseconds)
    }
    @Synchronized override fun match(generation: UUID, metadata: PhonePushRegistrationMetadata, moment: PushChallengeMoment): PushData.TokenChallenge? {
        check(!closed); return journal.match(generation, metadata, moment.bootEpoch, moment.milliseconds)
    }
    @Synchronized override fun discard(ticket: PendingPushChallengeTicket, moment: PushChallengeMoment): Boolean {
        check(!closed); return journal.discard(ticket, moment.bootEpoch, moment.milliseconds)
    }
    @Synchronized override fun close() { if (!closed) { closed = true; storage.close() } }
    companion object {
        private const val KEY_ALIAS = "remozio.push-challenge-storage.v1"
        fun moment(context: Context): PushChallengeMoment {
            val boot = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT)
            val elapsed = SystemClock.elapsedRealtime(); check(boot >= 0 && elapsed >= 0)
            return PushChallengeMoment(boot.toULong(), elapsed.toULong())
        }
        @WorkerThread fun open(context: Context, maximumEntries: Int = 128, lifetimeMilliseconds: ULong = 120_000u): AndroidPushChallenges {
            require(maximumEntries in 1..1024 && lifetimeMilliseconds in 1uL..3_600_000uL)
            val app = context.applicationContext; check(!app.isDeviceProtectedStorage)
            val directory = File(app.noBackupFilesDir, "push-challenges")
            if (!directory.isDirectory) { check(directory.mkdirs()); syncChallengeDirectory(app.noBackupFilesDir) }
            val storage = PushChallengeFile(File(directory, "state"))
            try {
                val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                if (!keys.containsAlias(KEY_ALIAS)) {
                    check(!storage.hasArchive())
                    try { generate(strongBox = true) }
                    catch (_: StrongBoxUnavailableException) { check(!keys.containsAlias(KEY_ALIAS)); generate(strongBox = false) }
                }
                val key = keys.getKey(KEY_ALIAS, null) as? SecretKey ?: error("Push challenge key unavailable")
                val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
                check(key.algorithm == KeyProperties.KEY_ALGORITHM_AES && key.encoded == null && key.format == null)
                check(info.keystoreAlias == KEY_ALIAS && info.origin == KeyProperties.ORIGIN_GENERATED && info.keySize == 256)
                check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX || info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
                check(info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT))
                check(info.blockModes.toSet() == setOf(KeyProperties.BLOCK_MODE_GCM))
                check(info.encryptionPaddings.toSet() == setOf(KeyProperties.ENCRYPTION_PADDING_NONE))
                check(!info.isUserAuthenticationRequired && !info.isUnlockedDeviceRequired)
                return AndroidPushChallenges(storage, PendingPushChallenges(storage, PushChallengeCipher(key), maximumEntries, lifetimeMilliseconds))
            } catch (failure: Throwable) { storage.close(); throw failure }
        }
        private fun generate(strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).setIsStrongBoxBacked(strongBox)
                .setUserAuthenticationRequired(false).setUnlockedDeviceRequired(false).build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
        }
    }
}

private class PushChallengeFile(private val file: File) : PushChallengeStorage, AutoCloseable {
    private val owner = ExclusiveFileOwner.acquire(File(file.path + ".lock"))
    private val atomic = AtomicFile(file)
    private var closed = false

    fun hasArchive() = listOf(file, File(file.path + ".bak"), File(file.path + ".new")).any { it.exists() }

    @Synchronized override fun read(maximumBytes: Int): ByteArray? {
        check(!closed); require(maximumBytes in 1..PushChallengeCipher.MAXIMUM_CIPHERTEXT_BYTES)
        val input = try { atomic.openRead() } catch (failure: FileNotFoundException) {
            if (listOf(file, File(file.path + ".bak"), File(file.path + ".new")).none { it.exists() }) return null
            throw failure
        }
        return input.use {
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = it.read(buffer)
                if (count < 0) break
                check(count <= maximumBytes - output.size())
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
    }
    @Synchronized override fun replace(ciphertext: ByteArray) {
        check(!closed); require(ciphertext.size in 1..PushChallengeCipher.MAXIMUM_CIPHERTEXT_BYTES)
        val output = atomic.startWrite()
        try { output.write(ciphertext); output.fd.sync(); atomic.finishWrite(output) }
        catch (failure: Exception) { atomic.failWrite(output); throw failure }
        syncChallengeDirectory(requireNotNull(file.parentFile))
        check(read(ciphertext.size)?.contentEquals(ciphertext) == true)
    }
    @Synchronized override fun close() {
        if (!closed) { closed = true; owner.close() }
    }
}

private fun syncChallengeDirectory(directory: File) {
    val descriptor = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
    try { check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)); Os.fsync(descriptor) }
    finally { Os.close(descriptor) }
}
