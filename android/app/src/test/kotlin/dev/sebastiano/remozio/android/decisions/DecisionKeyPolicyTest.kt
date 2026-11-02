package dev.sebastiano.remozio.android.decisions

import android.security.keystore.KeyProperties
import org.junit.Test
import kotlin.test.*

class DecisionKeyPolicyTest {
    private val facts = DecisionKeyFacts(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.ORIGIN_GENERATED,
        256, KeyProperties.PURPOSE_SIGN, setOf(KeyProperties.DIGEST_SHA256), false, false, false)
    private val alias = "remozio.decision.v1.${"a".repeat(32)}"

    @Test fun acceptsHardwareSha256SigningWithoutAnAuthenticationPrompt() {
        assertEquals(DecisionKeySecurity.STRONGBOX, decisionKeySecurity(facts))
        assertEquals(DecisionKeySecurity.TRUSTED_ENVIRONMENT,
            decisionKeySecurity(facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)))
    }

    @Test fun rejectsSoftwareImportedRawSigningAndIncompatiblePolicies() {
        listOf(facts.copy(securityLevel = KeyProperties.SECURITY_LEVEL_SOFTWARE), facts.copy(securityLevel = -99),
            facts.copy(origin = KeyProperties.ORIGIN_IMPORTED), facts.copy(keySize = 384),
            facts.copy(purposes = KeyProperties.PURPOSE_VERIFY),
            facts.copy(purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_AGREE_KEY),
            facts.copy(digests = emptySet()), facts.copy(digests = setOf(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)),
            facts.copy(authenticationRequired = true), facts.copy(presenceRequired = true), facts.copy(confirmationRequired = true)
        ).forEach { assertFails { decisionKeySecurity(it) } }
    }

    private class Backend : DecisionKeyCreationBackend {
        var exists = false
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
        assertContentEquals(byteArrayOf(4), createDecisionKey(success, alias))
        assertEquals(listOf(true), success.calls)
        val fallback = Backend().apply { failure = DecisionStrongBoxUnavailable() }
        createDecisionKey(fallback, alias)
        assertEquals(listOf(true, false), fallback.calls)
        for (failure in listOf(DecisionStrongBoxUnavailable(), IllegalStateException("provider failure"))) {
            val uncertain = Backend().apply { this.failure = failure; createsBeforeFailure = true }
            assertFails { createDecisionKey(uncertain, alias) }
            assertEquals(listOf(true), uncertain.calls)
        }
        val unexpected = Backend().apply { failure = IllegalStateException("provider failure") }
        assertFails { createDecisionKey(unexpected, alias) }
        assertEquals(listOf(true), unexpected.calls)
    }

    @Test fun existingKeysAndOtherRoleAliasesNeverReachGeneration() {
        val existing = Backend().apply { exists = true }
        assertFails { createDecisionKey(existing, alias) }
        assertTrue(existing.calls.isEmpty())
        val other = Backend()
        assertFails { createDecisionKey(other, alias.replace("decision", "transport")) }
        assertTrue(other.calls.isEmpty())
    }
}
