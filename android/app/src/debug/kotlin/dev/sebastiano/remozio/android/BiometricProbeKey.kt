package dev.sebastiano.remozio.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher

/** Disposable debug alias only. The serial worker also spans Activity recreation. */
internal object BiometricProbeKey {
    val worker = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private const val ALIAS = "remozio.debug.biometric-probe.v1"
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun create(): String {
        if (store().containsAlias(ALIAS)) return inspect()
        try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            // A failed generation must not overwrite an alias that did get created.
            if (!store().containsAlias(ALIAS)) generate(strongBox = false)
        }
        return inspect()
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(false)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }.generateKeyPair()
    }

    private fun checkedKey(): PrivateKey {
        val key = checkNotNull(store().getKey(ALIAS, null) as? PrivateKey) { "Create the probe key first" }
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java)
        val policy = BiometricProbePolicy(
            hardwareBacked = info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            securityLevel = info.securityLevel,
            nonExportable = key.encoded == null,
            authenticationRequired = info.isUserAuthenticationRequired,
            hardwareAuthentication = info.isUserAuthenticationRequirementEnforcedBySecureHardware,
            validitySeconds = info.userAuthenticationValidityDurationSeconds,
            authenticationType = info.userAuthenticationType,
            strongBiometricType = KeyProperties.AUTH_BIOMETRIC_STRONG,
            unlockedDeviceRequired = info.isUnlockedDeviceRequired,
            invalidatedByEnrollment = info.isInvalidatedByBiometricEnrollment,
        )
        if (!policy.accepted) throw BiometricProbePolicyException(policy)
        return key
    }

    fun inspect(): String {
        val key = checkedKey()
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        val level = if (info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) "StrongBox" else "TEE"
        val publicKey = checkNotNull(store().getCertificate(ALIAS)).publicKey
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
            .joinToString("") { "%02x".format(it) }
        return "$level · P-256 · SHA-256\n$fingerprint\n" +
            "Enrollment retention is unproven. Reported invalidation: ${info.isInvalidatedByBiometricEnrollment}"
    }

    fun signature(): Signature = Signature.getInstance("SHA256withECDSA").apply { initSign(checkedKey()) }

    fun verify(challenge: ByteArray, signature: ByteArray): Boolean {
        val publicKey = checkNotNull(store().getCertificate(ALIAS)).publicKey
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(challenge)
            verify(signature)
        }
    }

    fun delete() { store().deleteEntry(ALIAS) }
}
