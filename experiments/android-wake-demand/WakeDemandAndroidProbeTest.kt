package dev.remozio.android.push

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.*
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import dev.remozio.phone.push.WakeDemandTicket
import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

private class ProbeGate(
    val mutex: Mutex? = null,
    val holdTerminal: Boolean = false,
    val capture: () -> Unit = {},
    val complete: () -> Unit = {},
) {
    val launched = CompletableDeferred<Unit>()
    val entered = CompletableDeferred<Unit>()
    val release = CompletableDeferred<Unit>()
    val completed = CompletableDeferred<Unit>()
    val finish = CompletableDeferred<Unit>()
    val ended = CompletableDeferred<Unit>()
}
private object ProbeGates { val entries = ConcurrentHashMap<String, ProbeGate>() }

class WakeProbeWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val gate = checkNotNull(ProbeGates.entries[inputData.getString("probe")])
        gate.launched.complete(Unit)
        suspend fun perform(): Result {
            gate.capture(); gate.entered.complete(Unit)
            gate.release.await()
            gate.complete(); gate.completed.complete(Unit)
            if (gate.holdTerminal) gate.finish.await()
            return Result.success()
        }
        return try { gate.mutex?.withLock { perform() } ?: perform() }
        finally { gate.ended.complete(Unit) }
    }
}
private class ProbeFactory : WorkerFactory() {
    override fun createWorker(context: Context, workerClassName: String, parameters: WorkerParameters): ListenableWorker? =
        if (workerClassName == WakeProbeWorker::class.java.name) WakeProbeWorker(context, parameters) else null
}

@RunWith(AndroidJUnit4::class)
class WakeDemandAndroidProbeTest {
    private val owners = mutableListOf<AndroidWakeDemand>()
    private val generation = UUID.fromString("11111111-1111-4111-8111-111111111111")
    private val tag = ByteArray(32) { 7 }

    @Before fun cleanJournal() {
        assertFalse(context.isDeviceProtectedStorage)
        manager.cancelAllWork().result.get(10, TimeUnit.SECONDS)
        ProbeGates.entries.clear()
        assertTrue(!directory.exists() || directory.deleteRecursively())
    }
    @After fun clean() = runBlocking {
        ProbeGates.entries.values.forEach { it.release.complete(Unit); it.finish.complete(Unit) }
        manager.cancelAllWork().result.get(10, TimeUnit.SECONDS)
        withTimeout(10_000) { ProbeGates.entries.values.filter { it.launched.isCompleted }.forEach { it.ended.await() } }
        owners.forEach { it.close() }
        assertTrue(!directory.exists() || directory.deleteRecursively())
    }
    private val directory get() = File(context.noBackupFilesDir, "wake-demand")
    private fun open() = AndroidWakeDemand.open(context).also { owners.add(it) }
    private fun request(gate: ProbeGate): OneTimeWorkRequest {
        val id = UUID.randomUUID().toString(); ProbeGates.entries[id] = gate
        return OneTimeWorkRequestBuilder<WakeProbeWorker>().setInputData(workDataOf("probe" to id)).build()
    }
    private suspend fun finished(request: OneTimeWorkRequest, expected: WorkInfo.State) {
        withTimeout(10_000) {
            while (manager.getWorkInfoById(request.id).get(10, TimeUnit.SECONDS)?.state != expected) delay(10)
        }
    }
    private suspend fun entered(gate: ProbeGate) = withTimeout(10_000) { gate.entered.await() }
    private fun gateFor(owner: AndroidWakeDemand, mutex: Mutex, cleared: AtomicBoolean, hold: Boolean = false): ProbeGate {
        val ticket = AtomicReference<WakeDemandTicket>()
        return ProbeGate(mutex, hold,
            capture = { ticket.set(owner.pending(generation).single()) },
            complete = { cleared.set(owner.complete(checkNotNull(ticket.get()))) })
    }

    @Test fun journalReopenPreservesDemandAndExactRevisionCompletion() {
        val first = open(); first.selectGeneration(generation); first.mark(generation, tag); first.close()
        val second = open(); val old = second.pending(generation).single()
        assertArrayEquals(tag, old.tag.copyBytes())
        val latest = second.mark(generation, tag)
        assertFalse(second.complete(old)); assertEquals(1, second.pending(generation).size)
        second.close()
        val third = open(); assertEquals(1, third.pending(generation).size)
        assertTrue(third.complete(latest)); third.close()
        assertTrue(open().pending(generation).isEmpty())
    }
    @Test fun exclusiveOwnerAndClosedFacadeRefuseUse() {
        val first = open(); first.selectGeneration(generation); val ticket = first.mark(generation, tag)
        assertThrows(IllegalStateException::class.java) { AndroidWakeDemand.open(context) }
        first.close()
        assertThrows(IllegalStateException::class.java) { first.selectGeneration(generation) }
        assertThrows(IllegalStateException::class.java) { first.mark(generation, tag) }
        assertThrows(IllegalStateException::class.java) { first.pending(generation) }
        assertThrows(IllegalStateException::class.java) { first.complete(ticket) }
        assertEquals(1, open().pending(generation).size)
    }
    @Test fun malformedOversizedAndIncompleteArchivesAreNotReset() {
        for ((suffix, bytes) in listOf("" to byteArrayOf(-1), "" to ByteArray(262_145), ".new" to byteArrayOf(1))) {
            if (directory.exists()) assertTrue(directory.deleteRecursively())
            assertTrue(directory.mkdirs())
            val file = File(directory, "state$suffix"); file.writeBytes(bytes)
            assertThrows(Exception::class.java) { AndroidWakeDemand.open(context) }
            assertArrayEquals(bytes, file.readBytes())
        }
        assertTrue(directory.deleteRecursively())
        open().selectGeneration(generation)
    }
    @Test fun persistedGenerationReplacementRejectsOldTickets() {
        val first = open(); first.selectGeneration(generation); val old = first.mark(generation, tag); first.close()
        val next = UUID.fromString("22222222-2222-4222-8222-222222222222")
        val second = open(); second.selectGeneration(next); second.mark(next, tag)
        assertFalse(second.complete(old)); assertTrue(second.pending(generation).isEmpty()); second.close()
        assertEquals(1, open().pending(next).size)
    }
    @Test fun keepIgnoresNewWorkWhileTheOldWorkerIsActive() = runBlocking {
        val a = ProbeGate(); val first = request(a); val name = UUID.randomUUID().toString()
        manager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, first).result.get(10, TimeUnit.SECONDS); entered(a)
        val b = ProbeGate(); val second = request(b)
        manager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, second).result.get(10, TimeUnit.SECONDS)
        assertNull(manager.getWorkInfoById(second.id).get(10, TimeUnit.SECONDS)); assertFalse(b.entered.isCompleted)
        a.release.complete(Unit); finished(first, WorkInfo.State.SUCCEEDED)
    }
    @Test fun appendOrReplaceDoesNotProtectANewDependentFromLaterCancellation() = runBlocking {
        val a = ProbeGate(); val first = request(a); val name = UUID.randomUUID().toString()
        manager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, first).result.get(10, TimeUnit.SECONDS); entered(a)
        val b = ProbeGate(); val second = request(b)
        manager.enqueueUniqueWork(name, ExistingWorkPolicy.APPEND_OR_REPLACE, second).result.get(10, TimeUnit.SECONDS)
        assertEquals(WorkInfo.State.BLOCKED, manager.getWorkInfoById(second.id).get(10, TimeUnit.SECONDS)?.state)
        manager.cancelWorkById(first.id).result.get(10, TimeUnit.SECONDS)
        finished(first, WorkInfo.State.CANCELLED); finished(second, WorkInfo.State.CANCELLED)
        assertFalse(b.entered.isCompleted)
    }
    @Test fun anIndependentGuardSurvivesCancellationOfTheOlderWorker() = runBlocking {
        val a = ProbeGate(); val first = request(a); manager.enqueue(first).result.get(10, TimeUnit.SECONDS); entered(a)
        val b = ProbeGate(); val second = request(b); manager.enqueue(second).result.get(10, TimeUnit.SECONDS); entered(b)
        manager.cancelWorkById(first.id).result.get(10, TimeUnit.SECONDS); finished(first, WorkInfo.State.CANCELLED)
        assertEquals(WorkInfo.State.RUNNING, manager.getWorkInfoById(second.id).get(10, TimeUnit.SECONDS)?.state)
        b.release.complete(Unit); finished(second, WorkInfo.State.SUCCEEDED)
    }
    @Test fun aNewWakeDuringTheOlderFetchRemainsForTheIndependentSuccessor() = runBlocking {
        val owner = open(); owner.selectGeneration(generation); owner.mark(generation, tag)
        val mutex = Mutex(); val oldCleared = AtomicBoolean(); val newCleared = AtomicBoolean()
        val a = gateFor(owner, mutex, oldCleared); val first = request(a)
        manager.enqueue(first).result.get(10, TimeUnit.SECONDS); entered(a)
        owner.mark(generation, tag)
        val b = gateFor(owner, mutex, newCleared); val second = request(b)
        manager.enqueue(second).result.get(10, TimeUnit.SECONDS)
        a.release.complete(Unit); finished(first, WorkInfo.State.SUCCEEDED); entered(b)
        assertFalse(oldCleared.get()); assertEquals(1, owner.pending(generation).size)
        b.release.complete(Unit); finished(second, WorkInfo.State.SUCCEEDED)
        assertTrue(newCleared.get()); assertTrue(owner.pending(generation).isEmpty())
    }
    @Test fun aWakeAfterJournalClearAndBeforeWorkerTerminationStillHasRunnableWork() = runBlocking {
        val owner = open(); owner.selectGeneration(generation); owner.mark(generation, tag)
        val mutex = Mutex(); val oldCleared = AtomicBoolean(); val newCleared = AtomicBoolean()
        val a = gateFor(owner, mutex, oldCleared, hold = true); val first = request(a)
        manager.enqueue(first).result.get(10, TimeUnit.SECONDS); entered(a)
        a.release.complete(Unit); withTimeout(10_000) { a.completed.await() }
        assertTrue(oldCleared.get()); assertTrue(owner.pending(generation).isEmpty())
        assertEquals(WorkInfo.State.RUNNING, manager.getWorkInfoById(first.id).get(10, TimeUnit.SECONDS)?.state)
        owner.mark(generation, tag)
        val b = gateFor(owner, mutex, newCleared); val second = request(b)
        manager.enqueue(second).result.get(10, TimeUnit.SECONDS)
        a.finish.complete(Unit); finished(first, WorkInfo.State.SUCCEEDED); entered(b)
        b.release.complete(Unit); finished(second, WorkInfo.State.SUCCEEDED)
        assertTrue(newCleared.get()); assertTrue(owner.pending(generation).isEmpty())
    }
    companion object {
        private lateinit var context: Context
        private lateinit var manager: WorkManager
        private val pool = Executors.newFixedThreadPool(2)
        @BeforeClass @JvmStatic fun initialize() {
            context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
            val config = Configuration.Builder().setMinimumLoggingLevel(Log.ERROR).setExecutor(pool)
                .setTaskExecutor(SynchronousExecutor()).setWorkerFactory(ProbeFactory()).build()
            WorkManagerTestInitHelper.initializeTestWorkManager(context, config,
                WorkManagerTestInitHelper.ExecutorsMode.PRESERVE_EXECUTORS)
            manager = WorkManager.getInstance(context)
        }
        @AfterClass @JvmStatic fun shutdown() {
            manager.cancelAllWork().result.get(10, TimeUnit.SECONDS)
            InstrumentationRegistry.getInstrumentation().runOnMainSync { }
            pool.submit { }.get(10, TimeUnit.SECONDS)
            WorkManagerTestInitHelper.closeWorkDatabase()
            pool.shutdown(); assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        }
    }
}
