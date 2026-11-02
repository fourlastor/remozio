package dev.sebastiano.remozio.android.transport

import android.security.keystore.KeyProperties
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TransportKeySecurityTest {
    private val facts = TransportKeyFacts(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.ORIGIN_GENERATED,
        256, KeyProperties.PURPOSE_SIGN, true, true, false, false, false)

    @Test fun acceptsGeneratedHardwareSigningKeys() {
        assertEquals(TransportKeySecurity.STRONGBOX, transportKeySecurity(facts))
        assertEquals(TransportKeySecurity.TRUSTED_ENVIRONMENT,
            transportKeySecurity(facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)))
        assertEquals(TransportKeySecurity.STRONGBOX,
            transportKeySecurity(facts.copy(purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)))
    }

    @Test fun rejectsSha256OnlyKeysWithoutRawTlsSigningAuthorization() {
        assertFailsWith<TransportIdentityUnavailable> {
            transportKeySecurity(facts.copy(rawSigningAllowed = false))
        }
    }

    @Test fun rejectsSoftwareUnknownImportedAndIncompatibleKeys() {
        val rejected = listOf(
            facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_SOFTWARE),
            facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE),
            facts.copy(securityLevel = -999),
            facts.copy(origin = KeyProperties.ORIGIN_IMPORTED),
            facts.copy(origin = KeyProperties.ORIGIN_UNKNOWN),
            facts.copy(keySize = 384), facts.copy(sha256Allowed = false),
            facts.copy(purposes = KeyProperties.PURPOSE_VERIFY),
            facts.copy(purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY),
            facts.copy(authenticationRequired = true), facts.copy(presenceRequired = true),
            facts.copy(confirmationRequired = true),
        )
        rejected.forEach { candidate ->
            val failure = assertFailsWith<TransportIdentityUnavailable> { transportKeySecurity(candidate) }
            assertEquals("Transport identity unavailable", failure.message)
        }
    }
}
