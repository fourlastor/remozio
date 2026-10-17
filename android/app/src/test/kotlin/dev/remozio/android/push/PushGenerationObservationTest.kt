package dev.remozio.android.push

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class PushGenerationObservationTest {
    @Test fun absentAndDisabledStoragePublishNoActiveGeneration() {
        val f = PushClientFixture()
        assertNull(f.owner.generationState.value); f.owner.restore()
        assertNull(f.owner.generationState.value); f.enable()
        assertEquals(f.owner.generation(), f.owner.generationState.value)
        f.owner.setEnabled(false); assertNull(f.owner.generationState.value)
        val restarted = PushClientOwner("dev.remozio.android.debug", f.storage, TestPushClientDriver())
        restarted.restore(); assertNull(restarted.generationState.value)
    }
    @Test fun rapidDisableAndReenableCannotLookLikeTheOldReadyGeneration() = runTest {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.last().token("synthetic-token")
        val old = assertNotNull(f.owner.generationState.value)
        val observed = mutableListOf<java.util.UUID?>()
        backgroundScope.launch { f.owner.generationState.collect { observed += it } }
        runCurrent(); assertEquals(listOf<java.util.UUID?>(old), observed)
        f.owner.setEnabled(false); f.owner.setEnabled(true)
        f.driver.attempts.last().token("synthetic-token")
        assertEquals(PushClientStatus.CLIENT_READY, f.owner.status.value)
        val next = assertNotNull(f.owner.generationState.value); assertNotEquals(old, next)
        runCurrent(); assertEquals(listOf<java.util.UUID?>(old, next), observed)
        assertNull(f.owner.withCurrent(old) { error("stale provider") })
    }
    @Test fun generationObservationCancelsAnOlderSuspendedOperation() = runTest {
        val f = PushClientFixture(); f.enable()
        val old = assertNotNull(f.owner.generationState.value)
        val started = mutableListOf<java.util.UUID>(); val cancelled = mutableListOf<java.util.UUID>()
        backgroundScope.launch { f.owner.generationState.collectLatest { generation ->
            if (generation != null) {
                started += generation
                try { awaitCancellation() } finally { cancelled += generation }
            }
        } }
        runCurrent(); assertEquals(listOf(old), started)
        f.owner.setEnabled(false); f.owner.setEnabled(true)
        val next = assertNotNull(f.owner.generationState.value); runCurrent()
        assertEquals(listOf(old, next), started); assertEquals(listOf(old), cancelled)
    }
    @Test fun projectReplacementRetiresObservationUntilProcessRestart() {
        val f = PushClientFixture(); f.enable(); val old = f.driver.attempts.single()
        assertEquals(PushConfigurationResult.RESTART_REQUIRED,
            f.owner.import(publicFCMConfiguration(sender = "67890", project = "other-project")))
        assertNull(f.owner.generationState.value)
        old.token("synthetic-obsolete-token"); old.failed(); assertNull(f.owner.generationState.value)
        val restarted = PushClientOwner("dev.remozio.android.debug", f.storage, TestPushClientDriver())
        restarted.restore(); assertEquals(f.storage.record?.generation, restarted.generationState.value)
    }
    @Test fun uncertainStorageAndSynchronousDriverFailuresClearObservation() {
        val f = PushClientFixture(); f.enable(); f.storage.fails = true
        assertFalse(f.owner.setEnabled(false)); assertNull(f.owner.generationState.value)
        val g = PushClientFixture(); g.driver.throws = true; g.enable()
        assertEquals(PushClientStatus.UNAVAILABLE, g.owner.status.value); assertNull(g.owner.generationState.value)
    }
    @Test fun tokenRetryAndOldCallbacksCannotReplaceTheSelectedGeneration() {
        val f = PushClientFixture(); f.enable(); val old = f.driver.attempts.single()
        val first = assertNotNull(f.owner.generationState.value)
        old.failed(); f.owner.retry(); assertEquals(first, f.owner.generationState.value)
        f.owner.setEnabled(false); f.owner.setEnabled(true)
        val next = assertNotNull(f.owner.generationState.value)
        old.token("obsolete-token"); old.failed(); assertEquals(next, f.owner.generationState.value)
        f.driver.attempts.last().token("current-token"); assertEquals(next, f.owner.generationState.value)
    }
}
