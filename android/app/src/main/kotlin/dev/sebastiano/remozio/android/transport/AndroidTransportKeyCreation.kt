package dev.sebastiano.remozio.android.transport

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.WorkerThread
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal

/** A new local transport key. Persist its reference only through the authorized enrollment transaction. */
class CreatedTransportIdentity internal constructor(
    val alias: String,
    publicKey: ByteArray,
    val identity: AndroidTransportIdentity,
) : AutoCloseable {
    private val encodedPublicKey = publicKey.copyOf()
    fun publicKey(): ByteArray = encodedPublicKey.copyOf()
    override fun close() = identity.close()
    override fun toString(): String = "CreatedTransportIdentity(redacted)"
}

/** Creates fresh transport keys only. Existing identities and approval keys are never replaced. */
object AndroidTransportKeyCreation {
    private val random = SecureRandom()

    @WorkerThread
    @Synchronized
    fun create(context: Context, certificateNotBefore: Instant, certificateNotAfter: Instant): CreatedTransportIdentity {
        try {
            val validity = TransportCertificateValidity(certificateNotBefore.toEpochMilli(), certificateNotAfter.toEpochMilli())
            validity.validateAt(System.currentTimeMillis())
            val directory = File(context.noBackupFilesDir, "transport")
            check(directory.isDirectory || directory.mkdirs())
            RandomAccessFile(File(directory, "creation.lock"), "rw").use { lockFile ->
                val lock = lockFile.channel.tryLock() ?: throw TransportIdentityUnavailable()
                lock.use {
                    val alias = "remozio.transport.v1." + ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it) }
                    val publicKey = createTransportKey(PlatformTransportKeys, alias, validity)
                    val identity = AndroidTransportIdentities.load(alias, publicKey)
                    try {
                        check(!identity.requiresUnlockedDevice)
                        return CreatedTransportIdentity(alias, publicKey, identity)
                    } catch (failure: Exception) { identity.close(); throw failure }
                }
            }
        } catch (_: Exception) { throw TransportIdentityUnavailable() }
    }
}

internal data class TransportCertificateValidity(val notBeforeMillis: Long, val notAfterMillis: Long) {
    fun validateAt(nowMillis: Long) {
        require(notBeforeMillis <= nowMillis && nowMillis < notAfterMillis)
    }
}

internal class StrongBoxNotAvailable : Exception()
internal interface TransportKeyCreationBackend {
    fun contains(alias: String): Boolean
    fun generate(alias: String, strongBox: Boolean, validity: TransportCertificateValidity): ByteArray
}

/** The caller holds the creation lock across this operation and subsequent custody validation. */
internal fun createTransportKey(backend: TransportKeyCreationBackend, alias: String, validity: TransportCertificateValidity): ByteArray {
    require(Regex("remozio\\.transport\\.v1\\.[0-9a-f]{32}").matches(alias))
    check(!backend.contains(alias))
    return try { backend.generate(alias, true, validity) }
    catch (_: StrongBoxNotAvailable) {
        // A provider can fail after creating an entry. Never overwrite an uncertain result.
        check(!backend.contains(alias))
        backend.generate(alias, false, validity)
    }
}

private object PlatformTransportKeys : TransportKeyCreationBackend {
    override fun contains(alias: String): Boolean = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)

    override fun generate(alias: String, strongBox: Boolean, validity: TransportCertificateValidity): ByteArray {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .setUserAuthenticationRequired(false)
            .setUserConfirmationRequired(false)
            .setUserPresenceRequired(false)
            .setUnlockedDeviceRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .setCertificateSubject(X500Principal("CN=Remozio Transport"))
            .setCertificateNotBefore(Date(validity.notBeforeMillis))
            .setCertificateNotAfter(Date(validity.notAfterMillis))
            .build()
        try {
            val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            return pair.public.encoded.copyOf()
        } catch (_: StrongBoxUnavailableException) { throw StrongBoxNotAvailable() }
    }
}
