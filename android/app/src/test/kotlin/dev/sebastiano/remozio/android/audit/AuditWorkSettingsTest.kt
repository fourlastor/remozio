package dev.sebastiano.remozio.android.audit

import org.junit.Assert.*
import org.junit.Test

class AuditWorkSettingsTest {
    @Test fun failedPersistenceCannotChangeTheNextRoundPolicyEvenIfThePreferenceBackendMutatesMemory() {
        val original = AuditWorkPolicy(32, 30)
        var backend = original
        var succeeds = false
        val settings = AuditWorkSettings(original) { backend = it; succeeds }
        val requested = AuditWorkPolicy(64, 45)
        assertFalse(settings.save(requested))
        assertEquals(requested, backend)
        assertEquals(original, settings.read())
        assertEquals(original, settings.state.value)
        succeeds = true
        assertTrue(settings.save(requested))
        assertEquals(requested, settings.read())
        assertEquals(requested, settings.state.value)
    }

    @Test fun aThrowingSaveKeepsTheLastConfirmedPolicyAndAllowsRetry() {
        var fail = false
        val settings = AuditWorkSettings(AuditWorkPolicy()) {
            if (fail) throw java.io.IOException("disposable fixture write failure")
            true
        }
        val confirmed = AuditWorkPolicy(4096, 60)
        assertTrue(settings.save(confirmed))
        fail = true
        assertFalse(settings.save(AuditWorkPolicy(1, 1)))
        assertEquals(confirmed, settings.read())
        assertEquals(confirmed, settings.state.value)
        fail = false
        assertTrue(settings.save(AuditWorkPolicy(1, 1)))
        assertEquals(AuditWorkPolicy(1, 1), settings.read())
    }
}
