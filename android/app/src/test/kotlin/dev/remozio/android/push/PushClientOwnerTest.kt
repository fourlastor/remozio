package dev.remozio.android.push

import java.util.UUID
import org.junit.Test
import kotlin.test.*

internal class MemoryPushConfigurationStorage : PushConfigurationStorage {
    var record: StoredPushConfiguration? = null
    var writes = 0
    var fails = false
    override fun read() = record
    override fun replace(configuration: StoredPushConfiguration) {
        if (fails) error("synthetic-storage-secret")
        record = configuration; writes++
    }
}
internal class TestPushClientDriver : PushClientDriver {
    class Attempt(val token: (String) -> Unit, val failed: () -> Unit)
    val attempts = mutableListOf<Attempt>()
    var stops = 0
    var throws = false
    override fun start(configuration: FCMClientConfiguration, token: (String) -> Unit, failed: () -> Unit) {
        if (throws) error("synthetic-driver-secret")
        attempts += Attempt(token, failed)
    }
    override fun stop() { stops++ }
}
internal class PushClientFixture {
    val storage = MemoryPushConfigurationStorage()
    val driver = TestPushClientDriver()
    val owner = PushClientOwner("dev.remozio.android.debug", storage, driver)
    fun enable() { assertEquals(PushConfigurationResult.IMPORTED, owner.import(publicFCMConfiguration())) }
}

class PushClientOwnerTest {
    @Test fun absentAndDisabledConfigurationNeverInitializeTheSdk() {
        val f = PushClientFixture(); f.owner.restore(); f.owner.restore()
        assertEquals(PushClientStatus.UNCONFIGURED, f.owner.status.value)
        assertTrue(f.driver.attempts.isEmpty()); assertNull(f.owner.generation()); assertNull(f.owner.tokenCandidate())
        f.storage.record = StoredPushConfiguration(UUID.randomUUID(), FCMClientConfiguration.import(publicFCMConfiguration(), "dev.remozio.android.debug"), false)
        val restored = PushClientOwner("dev.remozio.android.debug", f.storage, f.driver)
        restored.restore(); assertEquals(PushClientStatus.DISABLED, restored.status.value); assertTrue(f.driver.attempts.isEmpty())
    }
    @Test fun explicitImportStartsOneClientAndIdenticalImportDoesNotResetIt() {
        val f = PushClientFixture(); f.enable()
        assertEquals(1, f.storage.writes); assertEquals(1, f.driver.attempts.size)
        val generation = f.owner.generation()
        f.driver.attempts.single().token("synthetic-token-1")
        val candidate = assertNotNull(f.owner.tokenCandidate())
        assertEquals(PushClientStatus.CLIENT_READY, f.owner.status.value)
        assertEquals(generation, candidate.generation); assertEquals("synthetic-token-1", candidate.token)
        assertFalse(candidate.toString().contains(candidate.token))
        assertTrue(f.owner.acceptsSender("12345")); assertFalse(f.owner.acceptsSender("67890")); assertFalse(f.owner.acceptsSender(null))
        assertEquals(PushConfigurationResult.UNCHANGED, f.owner.import(publicFCMConfiguration()))
        assertEquals(1, f.storage.writes); assertSame(candidate, f.owner.tokenCandidate()); assertEquals(1, f.driver.attempts.size)
    }
    @Test fun invalidImportPreservesTheCurrentClientAndDoesNotWrite() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().token("synthetic-token-1")
        val candidate = f.owner.tokenCandidate()
        assertEquals(PushConfigurationResult.INVALID, f.owner.import("synthetic-secret".encodeToByteArray()))
        assertEquals(1, f.storage.writes); assertSame(candidate, f.owner.tokenCandidate())
        assertEquals(PushClientStatus.CLIENT_READY, f.owner.status.value)
    }
    @Test fun disableBlocksOldCallbacksAndReenableDoesNotRequireAProcessRestart() {
        val f = PushClientFixture(); f.enable(); val old = f.driver.attempts.single(); val before = f.owner.generation()
        assertTrue(f.owner.setEnabled(false)); old.token("old-token")
        assertEquals(PushClientStatus.DISABLED, f.owner.status.value); assertNull(f.owner.generation()); assertNull(f.owner.tokenCandidate())
        assertNull(f.owner.withCurrent(assertNotNull(before)) { error("disabled publication") })
        assertTrue(f.owner.setEnabled(true)); val next = f.driver.attempts.last()
        assertEquals(2, f.driver.attempts.size); assertNotEquals(before, f.owner.generation())
        old.token("old-token"); old.failed(); assertEquals(PushClientStatus.INITIALIZING, f.owner.status.value)
        next.token("current-token"); assertEquals("current-token", f.owner.tokenCandidate()?.token)
    }
    @Test fun anotherProjectIsSavedForRestartAndOldMessagesCannotSelectItsGeneration() {
        val f = PushClientFixture(); f.enable(); val old = f.driver.attempts.single(); val generation = assertNotNull(f.owner.generation())
        assertEquals(PushConfigurationResult.RESTART_REQUIRED, f.owner.import(publicFCMConfiguration(sender = "67890", project = "other-project")))
        assertEquals(PushClientStatus.RESTART_REQUIRED, f.owner.status.value)
        assertNull(f.owner.generation()); assertNull(f.owner.withCurrent(generation) { error("retired provider") })
        old.token("old-token"); old.failed(); f.owner.tokenChanged()
        assertNull(f.owner.tokenCandidate()); assertEquals(1, f.driver.attempts.size)
        val driver = TestPushClientDriver(); val restarted = PushClientOwner("dev.remozio.android.debug", f.storage, driver)
        restarted.restore(); driver.attempts.single().token("new-project-token")
        assertEquals("other-project", restarted.tokenCandidate()?.projectID)
        assertTrue(restarted.acceptsSender("67890")); assertFalse(restarted.acceptsSender("12345"))
    }
    @Test fun retryFencesOlderResultsEvenWithinTheSameProviderGeneration() {
        val f = PushClientFixture(); f.enable(); val first = f.driver.attempts.single(); val generation = f.owner.generation()
        f.owner.retry(); val second = f.driver.attempts.last()
        second.token("current-token"); first.token("obsolete-token"); first.failed()
        assertEquals("current-token", f.owner.tokenCandidate()?.token); assertEquals(generation, f.owner.generation())
        f.owner.tokenChanged(); assertNull(f.owner.tokenCandidate())
        val refreshed = f.driver.attempts.last(); second.token("obsolete-token")
        assertNull(f.owner.tokenCandidate()); refreshed.token("rotated-token")
        assertEquals("rotated-token", f.owner.tokenCandidate()?.token)
    }
    @Test fun storageAndSynchronousSdkFailuresRetireTrafficWithoutExposingTheirErrors() {
        val f = PushClientFixture(); f.enable(); val old = f.driver.attempts.single(); f.storage.fails = true
        assertFalse(f.owner.setEnabled(false)); old.token("obsolete-token")
        assertEquals(PushClientStatus.UNAVAILABLE, f.owner.status.value); assertNull(f.owner.generation()); assertNull(f.owner.tokenCandidate())
        assertFalse(f.owner.status.value.toString().contains("secret"))
        val g = PushClientFixture(); g.driver.throws = true; g.enable()
        assertEquals(PushClientStatus.UNAVAILABLE, g.owner.status.value); assertNull(g.owner.generation())
    }
    @Test fun failedRegistrationCanRetryAndMalformedTokensNeverBecomeCandidates() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().failed()
        assertEquals(PushClientStatus.REGISTRATION_FAILED, f.owner.status.value)
        f.owner.retry(); val latest = f.driver.attempts.last()
        for (bad in listOf("", "secret token", "secret\n", "x".repeat(4097))) {
            latest.token(bad); assertNull(f.owner.tokenCandidate()); assertEquals(PushClientStatus.REGISTRATION_FAILED, f.owner.status.value)
        }
        latest.token("valid-token"); assertEquals(PushClientStatus.CLIENT_READY, f.owner.status.value)
    }
}
