package dev.remozio.android.push

import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Test
import kotlin.test.*

class BoundedWakeWorkAdmissionTest {
    @Test fun persistedCapacityRefusesBeforeStartingAnotherEnqueue() {
        var calls = 0
        val owner = BoundedWakeWorkAdmission<Unit>(2, { 2 }, { calls++; CompletableFuture.completedFuture(Unit) })
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit)); assertEquals(0, calls)
    }
    @Test fun uncommittedEnqueuesReserveCapacityEvenWhenDatabaseObservationIsEmpty() {
        var calls = 0
        val owner = BoundedWakeWorkAdmission<Unit>(2, { 0 }, { calls++; CompletableFuture<Unit>() }, 1)
        repeat(2) { assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit)) }
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit)); assertEquals(2, calls)
    }
    @Test fun completedFutureIsReplacedByItsPersistedWorkCount() {
        var persisted = 0; val first = CompletableFuture<Unit>(); var calls = 0
        val owner = BoundedWakeWorkAdmission<Unit>(2, { persisted }, {
            calls++; if (calls == 1) first else CompletableFuture.completedFuture(Unit)
        }, 1)
        assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit))
        persisted = 1; first.complete(Unit)
        assertEquals(WakeWorkAdmission.QUEUED, owner.admit(Unit)); assertEquals(2, calls)
    }
    @Test fun failedFutureCanReleaseReservationAfterFreshDatabaseInspection() {
        val first = CompletableFuture<Unit>(); var calls = 0
        val owner = BoundedWakeWorkAdmission<Unit>(1, { 0 }, {
            calls++; if (calls == 1) first else CompletableFuture.completedFuture(Unit)
        }, 1)
        assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit))
        first.completeExceptionally(IllegalStateException("synthetic-secret"))
        assertEquals(WakeWorkAdmission.QUEUED, owner.admit(Unit)); assertEquals(2, calls)
    }
    @Test fun unknownEnqueueOutcomeCannotCreateUnboundedNewWork() {
        var calls = 0
        val owner = BoundedWakeWorkAdmission<Unit>(1, { 0 }, { calls++; error("synthetic-secret") })
        assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit))
        repeat(10) { assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit)) }
        assertEquals(1, calls)
    }
    @Test fun databaseFailureAndNegativeObservationNeverStartAnEnqueue() {
        for (invalid in listOf(false, true)) {
            var calls = 0
            val owner = BoundedWakeWorkAdmission<Unit>(2, { if (invalid) -1 else error("synthetic-secret") },
                { calls++; CompletableFuture.completedFuture(Unit) })
            assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit)); assertEquals(0, calls)
        }
    }
    @Test fun concurrentCallersShareTheSameBoundBeforeAnyCommit() {
        val calls = AtomicInteger(); val start = CountDownLatch(1); val pool = Executors.newFixedThreadPool(8)
        val owner = BoundedWakeWorkAdmission<Unit>(2, { 0 }, { calls.incrementAndGet(); CompletableFuture<Unit>() }, 1)
        try {
            val results = (1..8).map { pool.submit<WakeWorkAdmission> { start.await(); owner.admit(Unit) } }
            start.countDown(); val values = results.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(2, calls.get()); assertEquals(2, values.count { it == WakeWorkAdmission.UNAVAILABLE })
            assertEquals(6, values.count { it == WakeWorkAdmission.CAPACITY_LIMIT })
        } finally { start.countDown(); pool.shutdownNow(); assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS)) }
    }
    @Test fun interruptionIsPreservedAndDoesNotReleaseUnfinishedWork() {
        val interrupted = AtomicBoolean(); val future = object : Future<Unit> {
            override fun cancel(interrupt: Boolean) = false
            override fun isCancelled() = false
            override fun isDone() = false
            override fun get(): Unit = throw InterruptedException()
            override fun get(timeout: Long, unit: TimeUnit): Unit = throw InterruptedException()
        }
        val owner = BoundedWakeWorkAdmission<Unit>(1, { 0 }, { future })
        val thread = Thread {
            assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit))
            interrupted.set(Thread.currentThread().isInterrupted)
        }
        thread.start(); thread.join(5_000); assertFalse(thread.isAlive); assertTrue(interrupted.get())
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit))
    }
    @Test fun largePersistedCountCannotOverflowIntoAnAdmission() {
        val owner = BoundedWakeWorkAdmission<Unit>(2, { Int.MAX_VALUE }, { error("must not enqueue") })
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit))
    }
    @Test fun invalidBoundsAreRejectedBeforeTouchingPlatformState() {
        for (maximum in listOf(0, 4097)) assertFailsWith<IllegalArgumentException> {
            BoundedWakeWorkAdmission<Unit>(maximum, { error("must not query") }, { error("must not enqueue") })
        }
        for (timeout in listOf(0L, 10_001L)) assertFailsWith<IllegalArgumentException> {
            BoundedWakeWorkAdmission<Unit>(1, { error("must not query") }, { error("must not enqueue") }, timeout)
        }
    }
    @Test fun oneOwnerAcceptsDifferentRequestsWithoutSharedMutableInput() {
        val seen = mutableListOf<Int>()
        val owner = BoundedWakeWorkAdmission<Int>(2, { seen.size }, {
            seen += it; CompletableFuture.completedFuture(Unit)
        })
        assertEquals(WakeWorkAdmission.QUEUED, owner.admit(11))
        assertEquals(WakeWorkAdmission.QUEUED, owner.admit(22))
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(33))
        assertEquals(listOf(11, 22), seen)
    }

    @Test fun resizingKeepsUncertainReservationsAndExistingQueueCounts() {
        var queued = 0
        val pending = java.util.concurrent.CompletableFuture<Unit>()
        val owner = BoundedWakeWorkAdmission<Unit>(2, { queued }, { pending }, 1)
        assertEquals(WakeWorkAdmission.UNAVAILABLE, owner.admit(Unit))
        owner.setMaximumQueued(1)
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit))
        pending.complete(Unit); queued = 1
        assertEquals(WakeWorkAdmission.CAPACITY_LIMIT, owner.admit(Unit))
        queued = 0
        assertEquals(WakeWorkAdmission.QUEUED, owner.admit(Unit))
    }

}
