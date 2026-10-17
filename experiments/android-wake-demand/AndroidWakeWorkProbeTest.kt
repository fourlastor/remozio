package dev.remozio.android.push

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.*
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import dev.remozio.protocol.PushData
import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith

private object WorkProbeGates { val active = ConcurrentHashMap<UUID, CompletableDeferred<Unit>>() }
private class ScheduledProbeWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val gate = CompletableDeferred<Unit>(); WorkProbeGates.active[id] = gate
        try { gate.await(); return Result.success() } finally { WorkProbeGates.active.remove(id) }
    }
}
private class SchedulingProbeFactory : WorkerFactory() {
    override fun createWorker(context: Context, workerClassName: String, parameters: WorkerParameters): ListenableWorker? =
        if (workerClassName in setOf(FCMWakeWorker::class.java.name, WakeSnapshotWorker::class.java.name, WakeReconcileWorker::class.java.name))
            ScheduledProbeWorker(context, parameters) else null
}

/** Actual AndroidWakeWork scheduling, with gated worker bodies and synthetic trust. No FCM or network proof. */
@RunWith(AndroidJUnit4::class)
class AndroidWakeWorkProbeTest {
    private lateinit var journal: AndroidWakeDemand
    private lateinit var client: PushClientOwner
    private lateinit var demand: ApplicationWakeDemand
    private lateinit var work: AndroidWakeWork
    private lateinit var settings: WakeWorkSettings
    private lateinit var record: dev.remozio.phone.enrollment.PhoneEnrollment
    private val statuses = mutableListOf<PushDeliveryStatus>()
    private val generation get() = checkNotNull(client.generation())
    private val ingressTag = "remozio.fcm.ingress.v2"
    private val fetchTag = "remozio.wake.snapshot.v1"
    private fun infos(tag: String) = manager.getWorkInfosByTag(tag).get(10, TimeUnit.SECONDS).filter { !it.state.isFinished }
    private fun wake(n: Int) = PushData.Wake(ByteArray(32) { n.toByte() }, record.enrollmentTag.copyBytes())
    private fun mark() = demand.admit(generation, record.enrollmentTag, setOf(record.enrollmentTag))

    @Before fun prepare() {
        manager.cancelAllWork().result.get(10, TimeUnit.SECONDS)
        File(context.noBackupFilesDir, "wake-demand").deleteRecursively()
        journal = AndroidWakeDemand.open(context)
        settings = WakeWorkSettings(context); assertTrue(settings.save(WakeWorkPolicy()))
        var config = StoredPushConfiguration(UUID.randomUUID(),
            FCMClientConfiguration("dev.remozio.android.wakeprobe", "synthetic-project", "12345", "1:12345:android:abcdef", "A" + "x".repeat(38)), true)
        client = PushClientOwner("dev.remozio.android.wakeprobe", object : PushConfigurationStorage {
            override fun read() = config
            override fun replace(configuration: StoredPushConfiguration) { config = configuration }
        }, object : PushClientDriver {
            override fun start(configuration: FCMClientConfiguration, token: (String) -> Unit, failed: () -> Unit) = Unit
            override fun stop() = Unit
        })
        client.restore(); demand = ApplicationWakeDemand(client) { journal }
        val archive = WakeTestArchive(); record = wakeTestRecord(1); archive.activate(record)
        val fetches = StoredWakeFetches(archive::open, Mutex(), client, demand,
            { error("Scheduling probe cannot open a transport") }, { 1000 }, Dispatchers.Unconfined)
        work = AndroidWakeWork(context, client, settings, fetches) { _, status -> synchronized(statuses) { statuses += status } }
    }
    @After fun clean() = runBlocking {
        manager.cancelAllWork().result.get(10, TimeUnit.SECONDS)
        withTimeout(10_000) { while (WorkProbeGates.active.isNotEmpty()) delay(10) }
        demand.close(); journal.close()
        assertTrue(File(context.noBackupFilesDir, "wake-demand").deleteRecursively())
    }
    @Test fun sameMacHintsArePersistedIndependentlyBeforeWorkerCoalescing() {
        work.accept(generation, wake(1)); work.accept(generation, wake(2))
        assertEquals(2, infos(ingressTag).size)
        assertEquals(listOf(PushDeliveryStatus.QUEUED, PushDeliveryStatus.QUEUED), statuses)
    }
    @Test fun sameRevisionCoalescesButNewRevisionSurvivesOlderCancellation() = runBlocking {
        mark(); assertTrue(work.reconcile(generation)); val first = infos(fetchTag).single()
        assertEquals(NetworkType.NOT_REQUIRED, first.constraints.requiredNetworkType)
        assertTrue(work.reconcile(generation)); assertEquals(1, infos(fetchTag).size)
        mark(); assertTrue(work.reconcile(generation)); val both = infos(fetchTag); assertEquals(2, both.size)
        val second = both.single { it.id != first.id }
        manager.cancelWorkById(first.id).result.get(10, TimeUnit.SECONDS)
        assertEquals(listOf(second.id), infos(fetchTag).map { it.id })
        assertEquals(1, demand.pending(generation, setOf(record.enrollmentTag)).size)
    }
    @Test fun capacityAndSettingsChangesUseTheSameAdmissionOwner() {
        assertTrue(settings.save(WakeWorkPolicy(ingressLimit = 1)))
        work.accept(generation, wake(1)); work.accept(generation, wake(2))
        assertEquals(1, infos(ingressTag).size); assertEquals(PushDeliveryStatus.CAPACITY_LIMIT, statuses.last())
        assertTrue(settings.save(WakeWorkPolicy(ingressLimit = 2)))
        work.accept(generation, wake(2)); assertEquals(2, infos(ingressTag).size)
        assertEquals(PushDeliveryStatus.QUEUED, statuses.last())
    }
    @Test fun retainedLegacyIngressSharesTheUpgradeCapacityAndSurvivesStartup() = runBlocking {
        assertTrue(settings.save(WakeWorkPolicy(ingressLimit = 2)))
        val fields = wake(1).encode()
        val legacy = OneTimeWorkRequestBuilder<FCMWakeWorker>()
            .setInputData(workDataOf(WAKE_GENERATION to generation.toString(),
                WAKE_IDENTIFIER to fields["wake_v1"], WAKE_ENROLLMENT to fields["enrollment_v1"]))
            .addTag("remozio.fcm.ingress.v1").setInitialDelay(1, TimeUnit.DAYS).build()
        manager.enqueueUniqueWork("remozio.fcm.legacy.upgrade", ExistingWorkPolicy.KEEP, legacy)
            .result.get(10, TimeUnit.SECONDS)
        work.accept(generation, wake(2)); work.accept(generation, wake(3))
        assertEquals(1, infos(ingressTag).size)
        assertEquals(PushDeliveryStatus.CAPACITY_LIMIT, statuses.last())
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val owner = work.start(scope)
        try {
            withTimeout(10_000) {
                while (manager.getWorkInfosForUniqueWork("remozio.wake.reconcile.v1")
                    .get(10, TimeUnit.SECONDS).none { !it.state.isFinished }) delay(10)
            }
            assertEquals(listOf(legacy.id), infos("remozio.fcm.ingress.v1").map { it.id })
            manager.cancelWorkById(legacy.id).result.get(10, TimeUnit.SECONDS)
            work.accept(generation, wake(3))
            assertEquals(2, infos(ingressTag).size)
            assertEquals(PushDeliveryStatus.QUEUED, statuses.last())
        } finally { owner.cancelAndJoin(); scope.cancel() }
    }
    @Test fun startupReconcilesSavedDemandAndRetiresOldGenerationJobs() = runBlocking {
        mark(); work.accept(generation, wake(1)); val old = infos(ingressTag).single().id
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val owner = work.start(scope)
        try {
            withTimeout(10_000) { while (infos(fetchTag).isEmpty()) delay(10) }
            assertTrue(client.setEnabled(false)); assertTrue(client.setEnabled(true))
            withTimeout(10_000) {
                while (manager.getWorkInfoById(old).get(10, TimeUnit.SECONDS)?.state != WorkInfo.State.CANCELLED) delay(10)
            }
            work.accept(generation, wake(2)); assertEquals(1, infos(ingressTag).size)
            assertNotEquals(old, infos(ingressTag).single().id)
        } finally { owner.cancelAndJoin(); scope.cancel() }
    }
    companion object {
        private lateinit var context: Context
        private lateinit var manager: WorkManager
        private val pool = Executors.newFixedThreadPool(4)
        @BeforeClass @JvmStatic fun initialize() {
            context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
            val config = Configuration.Builder().setMinimumLoggingLevel(Log.ERROR).setExecutor(pool)
                .setTaskExecutor(SynchronousExecutor()).setWorkerFactory(SchedulingProbeFactory()).build()
            WorkManagerTestInitHelper.initializeTestWorkManager(context, config,
                WorkManagerTestInitHelper.ExecutorsMode.PRESERVE_EXECUTORS)
            manager = WorkManager.getInstance(context)
        }
        @AfterClass @JvmStatic fun shutdown() {
            manager.cancelAllWork().result.get(10, TimeUnit.SECONDS)
            InstrumentationRegistry.getInstrumentation().runOnMainSync { }
            WorkManagerTestInitHelper.closeWorkDatabase(); pool.shutdown()
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        }
    }
}
