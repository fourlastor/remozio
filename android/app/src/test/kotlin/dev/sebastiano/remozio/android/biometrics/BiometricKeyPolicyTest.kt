package dev.sebastiano.remozio.android.biometrics

import android.security.keystore.KeyProperties
import org.junit.Test
import java.security.*
import kotlin.test.*

class BiometricKeyPolicyTest {
    private val facts = BiometricKeyFacts(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.ORIGIN_GENERATED,
        256, KeyProperties.PURPOSE_SIGN, setOf(KeyProperties.DIGEST_SHA256), true, true, KeyProperties.AUTH_BIOMETRIC_STRONG, 0, true, false, false)
    private val alias = "remozio.biometric.v1.${"a".repeat(32)}"

    @Test fun acceptsHardwareSigningWithPerUseBiometrics() {
        assertEquals(BiometricKeySecurity.STRONGBOX, biometricKeySecurity(facts))
        assertEquals(BiometricKeySecurity.STRONGBOX, biometricKeySecurity(facts.copy(validitySeconds = -1)))
        assertEquals(BiometricKeySecurity.TRUSTED_ENVIRONMENT,
            biometricKeySecurity(facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)))
    }

    @Test fun rejectsSoftwareImportedRawSigningAndIncompatiblePolicies() {
        listOf(facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_SOFTWARE), facts.copy(securityLevel = -99),
            facts.copy(origin = KeyProperties.ORIGIN_IMPORTED), facts.copy(keySize = 384),
            facts.copy(purposes = KeyProperties.PURPOSE_VERIFY),
            facts.copy(purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY),
            facts.copy(digests = emptySet()), facts.copy(digests = setOf(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)),
            facts.copy(authenticationRequired = false), facts.copy(hardwareAuthentication = false),
            facts.copy(authenticationType = KeyProperties.AUTH_DEVICE_CREDENTIAL),
            facts.copy(authenticationType = KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL),
            facts.copy(validitySeconds = 1), facts.copy(validitySeconds = -2),
            facts.copy(unlockedDeviceRequired = false), facts.copy(presenceRequired = true), facts.copy(confirmationRequired = true)
        ).forEach { assertFails { biometricKeySecurity(it) } }
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    private class ProbeSignature(private val invalid: Boolean) : Signature("probe") {
        var released = false
        override fun engineInitSign(key: PrivateKey) {
            if (invalid) throw InvalidKeyException("invalidated")
        }
        override fun engineInitVerify(key: PublicKey) { released = true }
        override fun engineUpdate(value: Byte) { error("No data may be supplied") }
        override fun engineUpdate(value: ByteArray, offset: Int, length: Int) { error("No data may be supplied") }
        override fun engineSign(): ByteArray = error("No signature may be requested")
        override fun engineVerify(value: ByteArray): Boolean = error("No verification may be requested")
        override fun engineSetParameter(name: String, value: Any) = error("No parameter mutation")
        override fun engineGetParameter(name: String): Any = error("No parameter access")
    }

    @Test fun operationProbeRejectsInvalidKeysAndReleasesTheOperationWithoutSigning() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val valid = ProbeSignature(false)
        checkBiometricKeyOperation(pair.private, pair.public, valid)
        assertTrue(valid.released)
        val invalid = ProbeSignature(true)
        assertFailsWith<InvalidKeyException> { checkBiometricKeyOperation(pair.private, pair.public, invalid) }
        assertTrue(invalid.released)
    }

    private class Backend : BiometricKeyCreationBackend {
        var exists = false
        var deleted = false
        override fun delete(alias: String) { deleted = true; exists = false }
        var failure: Exception? = null
        var createsBeforeFailure = false
        val calls = mutableListOf<Boolean>()
        override fun contains(alias: String) = exists
        override fun generate(alias: String, strongBox: Boolean): ByteArray {
            calls.add(strongBox)
            if (strongBox && failure != null) {
                exists = createsBeforeFailure
                throw checkNotNull(failure)
            }
            exists = true
            return byteArrayOf(4)
        }
    }

    @Test fun strongBoxFallbackRequiresTypedUnavailabilityAndAnAbsentAlias() {
        val success = Backend()
        assertContentEquals(byteArrayOf(4), createBiometricKey(success, alias))
        assertEquals(listOf(true), success.calls)
        val fallback = Backend().apply { failure = BiometricStrongBoxUnavailable() }
        createBiometricKey(fallback, alias)
        assertEquals(listOf(true, false), fallback.calls)
        for (failure in listOf(BiometricStrongBoxUnavailable(), IllegalStateException("provider failure"))) {
            val uncertain = Backend().apply { this.failure = failure; createsBeforeFailure = true }
            assertFails { createBiometricKey(uncertain, alias) }
            assertEquals(listOf(true), uncertain.calls)
        }
        val unexpected = Backend().apply { failure = IllegalStateException("provider failure") }
        assertFails { createBiometricKey(unexpected, alias) }
        assertEquals(listOf(true), unexpected.calls)
    }

    @Test fun validationFailureDeletesOnlyTheNewlyGeneratedUnpublishedKey() {
        val rejected = Backend()
        assertFails { createValidatedBiometricKey(rejected, alias) { error("invalid custody") } }
        assertTrue(rejected.deleted)
        assertFalse(rejected.exists)
        val accepted = Backend()
        assertEquals("reference", createValidatedBiometricKey(accepted, alias) { "reference" })
        assertFalse(accepted.deleted)
        val existing = Backend().apply { exists = true }
        assertFails { createValidatedBiometricKey(existing, alias) { "unreachable" } }
        assertFalse(existing.deleted)
        val uncertain = Backend().apply { failure = BiometricStrongBoxUnavailable(); createsBeforeFailure = true }
        assertFails { createValidatedBiometricKey(uncertain, alias) { "unreachable" } }
        assertFalse(uncertain.deleted)
    }

    @Test fun existingKeysAndOtherRoleAliasesNeverReachGeneration() {
        val existing = Backend().apply { exists = true }
        assertFails { createBiometricKey(existing, alias) }
        assertTrue(existing.calls.isEmpty())
        val other = Backend()
        assertFails { createBiometricKey(other, alias.replace("biometric", "transport")) }
        assertTrue(other.calls.isEmpty())
    }
}
