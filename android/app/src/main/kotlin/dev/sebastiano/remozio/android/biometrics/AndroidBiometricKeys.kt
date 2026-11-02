package dev.sebastiano.remozio.android.biometrics

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.decisions.decisionPublicPoint
import dev.remozio.phone.enrollment.EnrollmentKeyReference
import dev.remozio.phone.enrollment.EnrollmentKeyRole
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey

enum class BiometricKeySecurity { STRONGBOX, TRUSTED_ENVIRONMENT }
class BiometricIdentityUnavailable : IllegalStateException("Biometric identity unavailable")

/** Reported enrollment invalidation is diagnostic. Actual retention still requires a device experiment. */
data class BiometricKeyInspection(val security: BiometricKeySecurity, val reportedEnrollmentInvalidation: Boolean)

internal data class BiometricKeyFacts(
    val securityLevel: Int,
    val origin: Int,
    val keySize: Int,
    val purposes: Int,
    val digests: Set<String>,
    val authenticationRequired: Boolean,
    val hardwareAuthentication: Boolean,
    val authenticationType: Int,
    val validitySeconds: Int,
    val unlockedDeviceRequired: Boolean,
    val presenceRequired: Boolean,
    val confirmationRequired: Boolean,
)

internal fun biometricKeySecurity(facts: BiometricKeyFacts): BiometricKeySecurity {
    val security = when (facts.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> BiometricKeySecurity.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> BiometricKeySecurity.TRUSTED_ENVIRONMENT
        else -> throw BiometricIdentityUnavailable()
    }
    val allowed = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    require(facts.origin == KeyProperties.ORIGIN_GENERATED && facts.keySize == 256 &&
        facts.purposes and KeyProperties.PURPOSE_SIGN != 0 && facts.purposes and allowed.inv() == 0 &&
        facts.digests == setOf(KeyProperties.DIGEST_SHA256) && facts.authenticationRequired &&
        facts.hardwareAuthentication && facts.authenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG &&
        facts.validitySeconds in -1..0 && facts.unlockedDeviceRequired &&
        !facts.presenceRequired && !facts.confirmationRequired)
    return security
}

/** Inspects existing custody only. Missing or invalid keys require explicit recovery; this never generates a replacement. */
object AndroidBiometricKeys {
    @WorkerThread
    fun inspect(reference: EnrollmentKeyReference): BiometricKeyInspection {
        try { return loadBiometricKey(reference).inspection }
        catch (_: Exception) { throw BiometricIdentityUnavailable() }
    }
}

internal class BiometricKeyMaterial(val key: PrivateKey, val publicKey: PublicKey, val inspection: BiometricKeyInspection)

internal fun loadBiometricKey(reference: EnrollmentKeyReference): BiometricKeyMaterial {
    require(reference.role == EnrollmentKeyRole.BIOMETRIC)
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val key = store.getKey(reference.alias, null) as? PrivateKey ?: throw BiometricIdentityUnavailable()
    require(key.algorithm == KeyProperties.KEY_ALGORITHM_EC && key.encoded == null && key.format == null)
    val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
    require(info.keystoreAlias == reference.alias)
    val security = biometricKeySecurity(BiometricKeyFacts(info.securityLevel, info.origin, info.keySize, info.purposes,
        info.digests.toSet(), info.isUserAuthenticationRequired, info.isUserAuthenticationRequirementEnforcedBySecureHardware,
        info.userAuthenticationType, info.userAuthenticationValidityDurationSeconds, info.isUnlockedDeviceRequired,
        info.isTrustedUserPresenceRequired, info.isUserConfirmationRequired))
    val publicKey = store.getCertificate(reference.alias)?.publicKey as? ECPublicKey
        ?: throw BiometricIdentityUnavailable()
    val point = decisionPublicPoint(publicKey)
    require(MessageDigest.isEqual(reference.publicKey.copyBytes(), point))
    checkBiometricKeyOperation(key, publicKey)
    return BiometricKeyMaterial(key, publicKey, BiometricKeyInspection(security, info.isInvalidatedByBiometricEnrollment))
}

/** Initializes no data or prompt. Switching to verification releases the disposable signing operation. */
internal fun checkBiometricKeyOperation(
    key: PrivateKey,
    publicKey: PublicKey,
    operation: Signature = Signature.getInstance("SHA256withECDSA"),
) {
    try { operation.initSign(key) }
    finally { operation.initVerify(publicKey) }
}
