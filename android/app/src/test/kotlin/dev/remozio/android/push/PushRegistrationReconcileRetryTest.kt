package dev.remozio.android.push

import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class PushRegistrationReconcileRetryTest {
    @Test fun fullIngressWakesTheIdleSchedulerAndRetriesBeforeTheChallengeExpires() = runTest {
        val owner = PushRegistrationReconcileRetry()
        var reads = 0
        var capacity = true
        backgroundScope.launch { owner.run { reads++; capacity } }
        runCurrent(); assertEquals(1, reads)
        capacity = false
        assertFalse(owner.enqueue { false })
        runCurrent(); assertEquals(2, reads)
        advanceTimeBy(9_999); runCurrent(); assertEquals(2, reads)
        capacity = true
        advanceTimeBy(1); runCurrent(); assertEquals(3, reads)
        advanceTimeBy(120_000); runCurrent(); assertEquals(3, reads)
    }

    @Test fun failedAdmissionBeforeStartupIsRetainedAndABurstUsesOneSignal() = runTest {
        val owner = PushRegistrationReconcileRetry()
        repeat(1_000) { assertFalse(owner.enqueue { false }) }
        var reads = 0
        backgroundScope.launch { owner.run { reads++; true } }
        runCurrent(); assertEquals(2, reads)
        assertTrue(owner.enqueue { true })
        runCurrent(); assertEquals(2, reads)
    }

    @Test fun signalDuringReconciliationIsNotLost() = runTest {
        val owner = PushRegistrationReconcileRetry()
        val entered = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        var reads = 0
        backgroundScope.launch { owner.run {
            reads++
            if (reads == 1) { entered.complete(Unit); finish.await() }
            true
        } }
        runCurrent(); entered.await()
        owner.enqueue { false }; finish.complete(Unit)
        runCurrent(); assertEquals(2, reads)
    }

    @Test fun platformAdmissionExceptionAlsoWakesTheScheduler() = runTest {
        val owner = PushRegistrationReconcileRetry()
        var reads = 0
        backgroundScope.launch { owner.run { reads++; true } }
        runCurrent()
        assertFailsWith<IllegalStateException> { owner.enqueue { error("platform unavailable") } }
        runCurrent(); assertEquals(2, reads)
    }

    @Test fun reconciliationFailureRetriesAndAnObsoleteCollectorCancelsImmediately() = runTest {
        val owner = PushRegistrationReconcileRetry()
        var reads = 0
        val old = backgroundScope.launch { owner.run { reads++; error("platform unavailable") } }
        runCurrent(); assertEquals(1, reads)
        old.cancelAndJoin()
        advanceTimeBy(10_000); runCurrent(); assertEquals(1, reads)
        backgroundScope.launch { owner.run { reads++; true } }
        runCurrent(); assertEquals(2, reads)
    }
}
