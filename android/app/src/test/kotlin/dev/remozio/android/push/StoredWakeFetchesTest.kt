package dev.remozio.android.push

import dev.remozio.android.requests.*
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.*
import dev.remozio.protocol.CborLimits
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Test
import kotlin.test.*

class StoredWakeFetchesTest {
    private class Fixture {
        val client = PushClientFixture().also { it.enable() }
        val disk = WakeTestJournal()
        val demand = ApplicationWakeDemand(client.owner, disk::open)
        val archive = WakeTestArchive()
        val record = wakeTestRecord(1).also { archive.activate(it) }
        val mutex = Mutex()
        var receives = 0; var closes = 0
        var receive: suspend () -> Unit = {}
        val bounds = CborLimits(65_536, 32, 8192)
        val limits = RequestLimits(bounds, bounds, bounds, bounds)
        val connections = StoredCommandConnections(archive::open, { row ->
            CommandConnection(row, limits, open = { _, _ -> wire { awaitCancellation() } },
                clock = { ElapsedInstant(1, 0u) }, dispatcher = Dispatchers.Unconfined,
                openSnapshot = { _, _ -> wire { receives++; receive() } })
        }, mutex, Dispatchers.Unconfined)
        val fetches = StoredWakeFetches(archive::open, mutex, client.owner, demand,
            connections::acquire, { 1000 }, Dispatchers.Unconfined)
        val generation get() = assertNotNull(client.owner.generation())
        val tag get() = record.enrollmentTag
        fun mark() = demand.admit(generation, tag, archive.active().map { it.enrollment.enrollmentTag }.toSet())
        fun pending() = demand.pending(generation, archive.active().map { it.enrollment.enrollmentTag }.toSet())
        private fun wire(body: suspend () -> Unit) = object : CommandConnectionWire {
            override suspend fun receive() = body()
            override suspend fun send(bytes: ByteArray) { error("No background decision") }
            private var closed = false
            override fun close() { if (!closed) { closed = true; closes++ } }
        }
    }
    @Test fun completedSnapshotConsumesDemandAndASecondGuardPerformsNoNetwork() = runBlocking {
        val f = Fixture(); f.mark()
        assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag)); assertTrue(f.pending().isEmpty())
        assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag)); assertEquals(1, f.receives); assertEquals(1, f.closes)
    }
    @Test fun newWakeDuringFetchSurvivesOldCompletionAndItsGuardFetchesAgain() = runBlocking {
        val f = Fixture(); f.mark(); val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        f.receive = { entered.complete(Unit); release.await() }
        val first = async { f.fetches.fetch(f.generation, f.tag) }; entered.await(); f.mark()
        assertEquals(WakeFetchResult.RETRY, f.fetches.fetch(f.generation, f.tag))
        release.complete(Unit)
        assertEquals(WakeFetchResult.RETRY, first.await())
        assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag))
        assertEquals(2, f.receives); assertTrue(f.pending().isEmpty())
    }
    @Test fun aWakeAfterClearCanStartBeforeThePreviousWorkerTerminates() = runBlocking {
        val f = Fixture(); f.mark(); assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag))
        f.mark(); assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag))
        assertEquals(2, f.receives); assertTrue(f.pending().isEmpty())
    }
    @Test fun incompleteSnapshotAndFailedCompletionKeepDemandForRetry() = runBlocking {
        val f = Fixture(); f.mark(); f.receive = { error("incomplete authenticated set") }
        assertEquals(WakeFetchResult.RETRY, f.fetches.fetch(f.generation, f.tag)); assertEquals(1, f.pending().size)
        f.receive = { f.disk.failure = true }
        assertEquals(WakeFetchResult.RETRY, f.fetches.fetch(f.generation, f.tag)); f.disk.failure = false
        assertEquals(1, f.pending().size)
        f.receive = {}; assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag))
    }
    @Test fun foregroundOwnershipDefersFetchAndRetainsDemand() = runBlocking {
        val f = Fixture(); f.mark(); val connection = f.connections.acquire(f.record.recordID)
        val foreground = launch(start = CoroutineStart.UNDISPATCHED) { connection.run() }
        assertEquals(WakeFetchResult.RETRY, f.fetches.fetch(f.generation, f.tag)); assertEquals(0, f.receives)
        assertEquals(1, f.pending().size); foreground.cancelAndJoin()
        assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag))
    }
    @Test fun rapidProviderReplacementCancelsSuspendedFetchAndCannotClearNewDemand() = runBlocking {
        val f = Fixture(); f.mark(); val old = f.generation; val entered = CompletableDeferred<Unit>()
        f.receive = { entered.complete(Unit); awaitCancellation() }
        val fetch = async { f.fetches.fetch(old, f.tag) }; entered.await()
        f.client.owner.setEnabled(false); f.client.owner.setEnabled(true); f.mark()
        assertEquals(WakeFetchResult.OBSOLETE, fetch.await()); assertEquals(1, f.pending().size); assertEquals(1, f.closes)
        assertEquals(WakeFetchResult.OBSOLETE, f.fetches.fetch(old, f.tag)); assertEquals(1, f.receives)
    }
    @Test fun removalCancelsFetchBeforeTrustCommitAndPrunesOnlyRemovedDemand() = runBlocking {
        val f = Fixture(); f.mark(); val other = wakeTestRecord(2); f.archive.activate(other)
        f.demand.admit(f.generation, other.enrollmentTag, setOf(f.tag, other.enrollmentTag))
        val entered = CompletableDeferred<Unit>(); f.receive = { entered.complete(Unit); awaitCancellation() }
        val fetch = async { f.fetches.fetch(f.generation, f.tag) }; entered.await()
        f.mutex.withLock {
            f.connections.invalidateRecordsLocked(setOf(f.record.recordID)); f.fetches.invalidateRecordsLocked(setOf(f.record.recordID)); f.archive.remove(f.record)
        }
        assertTrue(runCatching { fetch.await() }.exceptionOrNull() is CancellationException)
        assertEquals(other.enrollmentTag, f.fetches.pending(f.generation).single().tag); assertEquals(1, f.closes)
    }
    @Test fun unreadableArchiveNeverConsumesJournalOrStartsNetwork() = runBlocking {
        val f = Fixture(); f.mark(); f.archive.unavailable = true
        assertFails { f.fetches.pending(f.generation) }
        assertFails { f.fetches.fetch(f.generation, f.tag) }
        f.archive.unavailable = false; assertEquals(1, f.pending().size); assertEquals(0, f.receives)
    }
    @Test fun cancelledGuardWaitsForRealTransportCleanupBeforeSuccessorRuns() = runBlocking {
        val f = Fixture(); f.mark(); val entered = CompletableDeferred<Unit>(); val cleaning = CompletableDeferred<Unit>(); val finish = CompletableDeferred<Unit>()
        var calls = 0
        f.receive = { if (++calls == 1) try { entered.complete(Unit); awaitCancellation() }
            finally { withContext(NonCancellable) { cleaning.complete(Unit); finish.await() } } }
        val first = async { f.fetches.fetch(f.generation, f.tag) }; entered.await(); first.cancel(); cleaning.await()
        assertEquals(WakeFetchResult.RETRY, f.fetches.fetch(f.generation, f.tag)); assertEquals(1, f.receives)
        finish.complete(Unit); assertTrue(runCatching { first.await() }.isFailure)
        assertEquals(WakeFetchResult.COMPLETE, f.fetches.fetch(f.generation, f.tag)); assertEquals(2, f.receives)
    }
}
