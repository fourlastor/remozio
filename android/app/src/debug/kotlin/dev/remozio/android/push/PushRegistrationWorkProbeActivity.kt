package dev.remozio.android.push

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.work.*
import dev.remozio.protocol.CborValue
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject

/** Real WorkManager queues with synthetic provider state and blocked worker bodies. No keys, pairing or network are used. */
class PushRegistrationWorkProbeActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        check(applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope.launch { runProbe(); withContext(Dispatchers.Main) { finish() }; scope.cancel() }
    }
    private suspend fun runProbe() {
        val namespace = "remozio.probe.registration." + UUID.randomUUID()
        val manager = WorkManager.getInstance(applicationContext)
        val attemptTag = "$namespace.attempt.v1"
        val ingressTag = "$namespace.ingress.v1"
        val selectionPrefix = "$namespace.selection."
        val reconcileName = "$namespace.reconcile.v1"
        val context = object : ContextWrapper(applicationContext) {
            override fun getApplicationContext(): Context = this
            override fun getSharedPreferences(name: String, mode: Int) =
                baseContext.getSharedPreferences("$namespace.$name", mode)
        }
        val policy = PushRegistrationWorkSettings(context)
        val reads = AtomicInteger()
        val records = (1..3).map { CborValue.Bytes(ByteArray(16) { _ -> it.toByte() }) }
        val controls = mutableListOf<String>()
        var failure: String? = null
        var cleaned = false
        val configuration = StoredPushConfiguration(UUID.randomUUID(),
            FCMClientConfiguration(packageName, "synthetic-project", "123", "1:123:android:ab", "A" + "b".repeat(38)), true)
        val driver = ProbeProviderDriver()
        val provider = PushClientOwner(packageName, object : PushConfigurationStorage {
            var value = configuration
            override fun read() = value
            override fun replace(configuration: StoredPushConfiguration) { value = configuration }
        }, driver).also { it.restore() }
        val jobs = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        fun scheduler() = AndroidPushRegistrationWork(context, provider, policy, { _, _, tag ->
            check(tag == null); reads.incrementAndGet(); records
        }, RegistrationHoldingWorker::class.java, namespace)
        fun work() = manager.getWorkInfosByTag(attemptTag).get(5, TimeUnit.SECONDS)
        suspend fun await(test: () -> Boolean) = withTimeout(10_000) { while (!test()) delay(50) }
        suspend fun cancelAttempts() {
            manager.cancelAllWorkByTag(attemptTag).result.get(5, TimeUnit.SECONDS)
            await { work().all { it.state.isFinished } && RegistrationProbeWorkers.active.values.none { it.namespace == namespace } }
        }
        try {
            withTimeout(60_000) {
                val clock = AndroidPushChallenges.moment(context)
                val laterClock = AndroidPushChallenges.moment(context)
                check(clock.bootEpoch == laterClock.bootEpoch && laterClock.milliseconds >= clock.milliseconds)
                controls += "boot-counter-and-elapsed-clock"
                check(policy.save(PushRegistrationWorkPolicy(queueLimit = 1, maximumConcurrent = 1)))
                val first = checkNotNull(provider.tokenCandidate())
                var owner = scheduler()
                check(!owner.reconcile(first.generation, first.revision))
                await { RegistrationProbeWorkers.active.values.any { it.namespace == namespace } }
                check(work().count { !it.state.isFinished } == 1)
                check(RegistrationProbeWorkers.active.values.single { it.namespace == namespace }.record == records[0].hex())
                controls += "queue-capacity-and-initial-cursor"

                cancelAttempts(); owner = scheduler()
                check(!owner.reconcile(first.generation, first.revision))
                await { RegistrationProbeWorkers.active.values.any { it.namespace == namespace && it.record == records[1].hex() } }
                check(work().count { !it.state.isFinished } == 1)
                controls += "cursor-survives-owner-recreation"

                val active = RegistrationProbeWorkers.active.values.single { it.namespace == namespace }
                check(active.keys == setOf(REGISTRATION_GENERATION, REGISTRATION_REVISION, REGISTRATION_RECORD))
                check(active.identifiersOnly)
                controls += "work-data-holds-identifiers-only"

                val before = reads.get(); val count = work().size
                driver.token?.invoke("synthetic-token-replacement")
                val next = checkNotNull(provider.tokenCandidate()); check(next.revision != first.revision)
                check(owner.reconcile(first.generation, first.revision))
                check(reads.get() == before && work().size == count)
                controls += "obsolete-token-cannot-read-or-enqueue"

                val oldTag = "$selectionPrefix${first.generation}.${first.revision}"
                owner.start(jobs)
                await { manager.getWorkInfosByTag(oldTag).get(5, TimeUnit.SECONDS).all { it.state.isFinished } }
                await { RegistrationProbeWorkers.active.values.any { it.namespace == namespace && it.revision == next.revision.toString() } }
                check(provider.setEnabled(false))
                await { work().all { it.state.isFinished } && RegistrationProbeWorkers.active.values.none { it.namespace == namespace } }
                await { manager.getWorkInfosForUniqueWork(reconcileName).get(5, TimeUnit.SECONDS).all { it.state.isFinished } }
                controls += "token-change-and-disable-retire-work"
            }
        } catch (problem: Throwable) { failure = problem.javaClass.simpleName }
        finally {
            withContext(NonCancellable) {
                jobs.cancel(); jobs.coroutineContext.job.join()
                try {
                    manager.cancelAllWorkByTag(attemptTag).result.get(5, TimeUnit.SECONDS)
                    manager.cancelAllWorkByTag(ingressTag).result.get(5, TimeUnit.SECONDS)
                    manager.cancelUniqueWork(reconcileName).result.get(5, TimeUnit.SECONDS)
                    await { work().all { it.state.isFinished } && RegistrationProbeWorkers.active.values.none { it.namespace == namespace } }
                    cleaned = manager.getWorkInfosByTag(ingressTag).get(5, TimeUnit.SECONDS).all { it.state.isFinished } &&
                        manager.getWorkInfosForUniqueWork(reconcileName).get(5, TimeUnit.SECONDS).all { it.state.isFinished }
                } catch (problem: Throwable) { failure = failure ?: problem.javaClass.simpleName }
            }
            val report = JSONObject().put("experiment", "android-push-registration-scheduling").put("api", Build.VERSION.SDK_INT)
                .put("status", if (failure == null && controls.size == 6 && cleaned) "passed" else "failed")
                .put("cases", JSONArray(controls)).put("failureType", failure).put("ownedWorkRetired", cleaned)
                .put("hardwareKeysCreated", false).put("providerDeliveryTested", false).put("pairingCreated", false)
                .put("networkWorkerBodiesBlocked", true).put("productionConfigurationChanged", false)
            Log.i("RemozioRegistrationProbe", report.toString())
        }
    }
}
private class ProbeProviderDriver : PushClientDriver {
    var token: ((String) -> Unit)? = null
    override fun start(configuration: FCMClientConfiguration, token: (String) -> Unit, failed: () -> Unit) {
        this.token = token; token("synthetic-token-initial")
    }
    override fun stop() { token = null }
}
private class ProbeWorkerInput(val namespace: String, val record: String, val revision: String, val keys: Set<String>, val identifiersOnly: Boolean)
private object RegistrationProbeWorkers { val active = ConcurrentHashMap<UUID, ProbeWorkerInput>() }

/** WorkManager starts and stops this body. It never reaches an enrollment, provider or network owner. */
class RegistrationHoldingWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val selection = tags.single { it.startsWith("remozio.probe.registration.") && it.contains(".selection.") }
        val namespace = selection.substringBefore(".selection.")
        val generation = inputData.getString(REGISTRATION_GENERATION)
        val revision = inputData.getString(REGISTRATION_REVISION)
        val record = checkNotNull(inputData.getString(REGISTRATION_RECORD))
        val identifiersOnly = runCatching {
            check(UUID.fromString(generation).toString() == generation && UUID.fromString(revision).toString() == revision)
            check(registrationIdentifier(record, 16) != null)
        }.isSuccess
        RegistrationProbeWorkers.active[id] = ProbeWorkerInput(namespace, record, revision.orEmpty(), inputData.keyValueMap.keys, identifiersOnly)
        try { awaitCancellation() } finally { RegistrationProbeWorkers.active.remove(id) }
    }
}
