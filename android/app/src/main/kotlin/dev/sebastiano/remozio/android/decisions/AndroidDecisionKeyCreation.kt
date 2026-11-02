package dev.sebastiano.remozio.android.decisions

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.enrollment.EnrollmentKeyReference
import dev.remozio.phone.enrollment.EnrollmentKeyRole
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Fresh local keys only. The authorized enrollment flow must persist and register the returned reference. */
object AndroidDecisionKeyCreation {
    @WorkerThread
    fun create(context: Context): EnrollmentKeyReference {
        try {
            val directory = File(context.noBackupFilesDir, "decisions")
            check(directory.isDirectory || directory.mkdirs())
            ExclusiveFileOwner.acquire(File(directory, "creation.lock")).use {
                val id = ByteArray(16).also(SecureRandom()::nextBytes)
                val alias = "remozio.decision.v1." + id.joinToString("") { "%02x".format(it) }
                val point = createDecisionKey(PlatformDecisionKeys, alias)
                val reference = EnrollmentKeyReference(EnrollmentKeyRole.DECISION, id, alias, point)
                loadDecisionKey(reference)
                return reference
            }
        } catch (_: Exception) { throw DecisionIdentityUnavailable() }
    }
}

internal class DecisionStrongBoxUnavailable : Exception()
internal interface DecisionKeyCreationBackend {
    fun contains(alias: String): Boolean
    fun generate(alias: String, strongBox: Boolean): ByteArray
}

/** The caller holds the creation lock through generation and the subsequent custody check. */
internal fun createDecisionKey(backend: DecisionKeyCreationBackend, alias: String): ByteArray {
    require(Regex("remozio\\.decision\\.v1\\.[0-9a-f]{32}").matches(alias))
    check(!backend.contains(alias))
    return try { backend.generate(alias, true) }
    catch (_: DecisionStrongBoxUnavailable) {
        check(!backend.contains(alias))
        backend.generate(alias, false)
    }
}

private object PlatformDecisionKeys : DecisionKeyCreationBackend {
    override fun contains(alias: String) = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)
    override fun generate(alias: String, strongBox: Boolean): ByteArray {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setUserConfirmationRequired(false)
            .setUserPresenceRequired(false)
            .setUnlockedDeviceRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        try {
            val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            return decisionPublicPoint(pair.public as ECPublicKey)
        } catch (_: StrongBoxUnavailableException) { throw DecisionStrongBoxUnavailable() }
    }
}
