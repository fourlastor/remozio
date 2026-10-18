package dev.remozio.android.push

import dev.remozio.protocol.CborValue
import java.util.concurrent.CompletableFuture
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class PushRegistrationWorkSweepTest {
    private fun id(n: Int) = CborValue.Bytes(ByteArray(16) { n.toByte() })

    private class Fixture {
        val retry = PushRegistrationReconcileRetry()
        val sweep = PushRegistrationWorkSweep()
        val records = (1..3).map { CborValue.Bytes(ByteArray(16) { _ -> it.toByte() }) }
        val active = mutableSetOf<CborValue.Bytes>()
        val admissions = mutableListOf<CborValue.Bytes>()
        var reads = 0
        private val queue = BoundedWakeWorkAdmission<CborValue.Bytes>(1, { active.size }, {
            active += it; admissions += it; CompletableFuture.completedFuture(Unit)
        })
        suspend fun run() = retry.run {
            reads++
            var complete = true
            for (record in sweep.pending(records)) {
                if (queue.admit(record) != WakeWorkAdmission.QUEUED) { complete = false; break }
                sweep.admitted(record)
            }
            if (complete) sweep.reset()
            complete
        }
    }

    @Test fun moreMacsThanSlotsFinishOneSweepAndThenIdle() = runTest {
        val f = Fixture()
        backgroundScope.launch { f.run() }
        runCurrent(); assertEquals(listOf(f.records[0]), f.admissions)
        f.active.clear(); advanceTimeBy(10_000); runCurrent()
        assertEquals(f.records.take(2), f.admissions)
        f.active.clear(); advanceTimeBy(10_000); runCurrent()
        assertEquals(f.records, f.admissions)
        f.active.clear(); advanceTimeBy(120_000); runCurrent()
        assertEquals(f.records, f.admissions); assertEquals(3, f.reads)
    }

    @Test fun aChallengeDuringAPartialSweepStartsAnotherSweepAfterItCompletes() = runTest {
        val f = Fixture()
        backgroundScope.launch { f.run() }
        runCurrent()
        assertFalse(f.retry.enqueue { false })
        repeat(2) { f.active.clear(); advanceTimeBy(10_000); runCurrent() }
        assertEquals(f.records, f.admissions)
        repeat(3) { f.active.clear(); advanceTimeBy(10_000); runCurrent() }
        assertEquals(f.records + f.records, f.admissions)
        val reads = f.reads
        f.active.clear(); advanceTimeBy(120_000); runCurrent()
        assertEquals(reads, f.reads)
    }

    @Test fun removedRecordsReleaseMemoryAndReenrollmentIsEligible() {
        val sweep = PushRegistrationWorkSweep()
        val first = id(1); val second = id(2)
        sweep.admitted(first)
        assertEquals(listOf(second), sweep.pending(listOf(first, second)))
        assertEquals(listOf(second), sweep.pending(listOf(second)))
        assertEquals(listOf(first, second), sweep.pending(listOf(first, second)))
    }

    @Test fun onlyConfirmedAdmissionsAreRetiredAndAFreshCollectorStartsANewSweep() {
        val sweep = PushRegistrationWorkSweep()
        val records = listOf(id(1), id(2))
        assertEquals(records, sweep.pending(records))
        assertEquals(records, sweep.pending(records))
        sweep.admitted(records[0])
        assertEquals(listOf(records[1]), sweep.pending(records))
        assertEquals(records, PushRegistrationWorkSweep().pending(records))
        sweep.reset(); assertEquals(records, sweep.pending(records))
    }
}
