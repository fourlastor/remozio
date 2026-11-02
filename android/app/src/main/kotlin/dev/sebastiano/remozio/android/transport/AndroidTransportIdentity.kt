package dev.sebastiano.remozio.android.transport

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.WorkerThread
import dev.remozio.phone.transport.ClientTLSKeyManager
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate

enum class TransportKeySecurity { STRONGBOX, TRUSTED_ENVIRONMENT }
class TransportIdentityUnavailable : IllegalStateException("Transport identity unavailable")

/** Local custody evidence only. This does not establish remote attestation or enrollment authority. */
class AndroidTransportIdentity internal constructor(
    val keyManager: ClientTLSKeyManager,
    val security: TransportKeySecurity,
    val requiresUnlockedDevice: Boolean,
) : AutoCloseable {
    override fun close() = keyManager.close()
    override fun toString(): String = "AndroidTransportIdentity(redacted)"
}

internal data class TransportKeyFacts(
    val securityLevel: Int,
    val origin: Int,
    val keySize: Int,
    val purposes: Int,
    val sha256Allowed: Boolean,
    val rawSigningAllowed: Boolean,
    val authenticationRequired: Boolean,
    val presenceRequired: Boolean,
    val confirmationRequired: Boolean,
)

internal fun transportKeySecurity(facts: TransportKeyFacts): TransportKeySecurity {
    val security = when (facts.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> TransportKeySecurity.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> TransportKeySecurity.TRUSTED_ENVIRONMENT
        else -> throw TransportIdentityUnavailable()
    }
    val allowedPurposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    if (facts.origin != KeyProperties.ORIGIN_GENERATED || facts.keySize != 256 || !facts.sha256Allowed || !facts.rawSigningAllowed ||
        facts.purposes and KeyProperties.PURPOSE_SIGN == 0 || facts.purposes and allowedPurposes.inv() != 0 ||
        facts.authenticationRequired || facts.presenceRequired || facts.confirmationRequired) throw TransportIdentityUnavailable()
    return security
}

/** Reads an existing local alias. Never creates, replaces, deletes, or silently recovers a key. */
object AndroidTransportIdentities {
    @WorkerThread
    fun load(alias: String, expectedLocalPublicKey: ByteArray): AndroidTransportIdentity {
        var manager: ClientTLSKeyManager? = null
        try {
            require(Regex("remozio\\.transport\\.v1\\.[0-9a-f]{32}").matches(alias))
            require(expectedLocalPublicKey.size == 91)
            val expected = expectedLocalPublicKey.copyOf()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = store.getKey(alias, null) as? PrivateKey ?: throw TransportIdentityUnavailable()
            require(key.algorithm == KeyProperties.KEY_ALGORITHM_EC && key.encoded == null && key.format == null)
            val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java)
            require(info.keystoreAlias == alias)
            val security = transportKeySecurity(TransportKeyFacts(
                securityLevel = info.securityLevel,
                origin = info.origin,
                keySize = info.keySize,
                purposes = info.purposes,
                sha256Allowed = KeyProperties.DIGEST_SHA256 in info.digests,
                rawSigningAllowed = KeyProperties.DIGEST_NONE in info.digests,
                authenticationRequired = info.isUserAuthenticationRequired,
                presenceRequired = info.isTrustedUserPresenceRequired,
                confirmationRequired = info.isUserConfirmationRequired,
            ))
            val stored = store.getCertificateChain(alias) ?: throw TransportIdentityUnavailable()
            require(stored.size in 1..8)
            val chain = stored.map { it as? X509Certificate ?: throw TransportIdentityUnavailable() }.toTypedArray()
            require(MessageDigest.isEqual(expected, chain.first().publicKey.encoded))
            chain.first().checkValidity()
            manager = ClientTLSKeyManager(key, chain)
            return AndroidTransportIdentity(manager, security, info.isUnlockedDeviceRequired)
        } catch (_: Exception) {
            manager?.close()
            throw TransportIdentityUnavailable()
        }
    }
}
