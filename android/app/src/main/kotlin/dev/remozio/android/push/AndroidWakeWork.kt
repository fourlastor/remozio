package dev.remozio.android.push

import android.content.Context
import androidx.work.*
import dev.remozio.phone.push.WakeDemandTicket
import dev.remozio.protocol.PushData
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine

internal const val WAKE_GENERATION = "provider_generation"
internal const val WAKE_IDENTIFIER = "wake"
internal const val WAKE_ENROLLMENT = "enrollment"

/** Independent revision guards have no prerequisite that an older worker can cancel. */
internal class AndroidWakeWork(
    context: Context,
    private val provider: PushClientOwner,
    private val settings: WakeWorkSettings,
    private val fetches: StoredWakeFetches,
    private val report: (UUID, PushDeliveryStatus) -> Unit,
) {
    private val app = context.applicationContext
    private val manager by lazy { WorkManager.getInstance(app) }
    private val ingress = BoundedWakeWorkAdmission<OneTimeWorkRequest>(256,
        { count(INGRESS_TAG, LEGACY_INGRESS_TAG) }, { manager.enqueue(it).result })
    private val guards = BoundedWakeWorkAdmission<Pair<String, OneTimeWorkRequest>>(256,
        { count(FETCH_TAG) }, { (name, request) -> manager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, request).result })

    /** Firebase calls this on its callback thread. No network or enrollment storage is accessed. */
    fun accept(generation: UUID, wake: PushData.Wake) {
        try {
            provider.withCurrent(generation) {
                val policy = settings.read()
                ingress.setMaximumQueued(policy.ingressLimit)
                val fields = wake.encode()
                val request = OneTimeWorkRequestBuilder<FCMWakeWorker>()
                    .setInputData(workDataOf(WAKE_GENERATION to generation.toString(),
                        WAKE_IDENTIFIER to fields["wake_v1"], WAKE_ENROLLMENT to fields["enrollment_v1"]))
                    .addTag(INGRESS_TAG).addTag(generationTag(generation))
                    .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, policy.backoffSeconds.toLong(), TimeUnit.SECONDS)
                    .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST).build()
                reportAdmission(generation, ingress.admit(request))
            }
        } catch (_: Exception) { report(generation, PushDeliveryStatus.UNAVAILABLE) }
    }

    /** False retains the original ingress job for a bounded retry. The journal is never cleared here. */
    suspend fun reconcile(generation: UUID): Boolean = withContext(Dispatchers.IO) {
        if (provider.generation() != generation) return@withContext true
        val pending = fetches.pending(generation)
        pending.allScheduled(generation)
    }
    private fun List<WakeDemandTicket>.allScheduled(generation: UUID): Boolean {
        var complete = true
        for (ticket in this) {
            val admitted = provider.withCurrent(generation) {
                val policy = settings.read(); guards.setMaximumQueued(policy.fetchLimit)
                val fields = PushData.Wake(ByteArray(32), ticket.tag.copyBytes()).encode()
                val request = OneTimeWorkRequestBuilder<WakeSnapshotWorker>()
                    .setInputData(workDataOf(WAKE_GENERATION to generation.toString(), WAKE_ENROLLMENT to fields["enrollment_v1"]))
                    .addTag(FETCH_TAG).addTag(generationTag(generation))
                    .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, policy.backoffSeconds.toLong(), TimeUnit.SECONDS).build()
                val name = "remozio.wake." + generation + "." + ticket.tag.hex() + "." + ticket.revision.hex()
                guards.admit(name to request)
            } ?: return true
            if (admitted != WakeWorkAdmission.QUEUED) { complete = false; reportAdmission(generation, admitted) }
        }
        return complete
    }

    /** Durable periodic recovery covers journal commit followed by a process or enqueue failure. */
    fun start(scope: CoroutineScope) = scope.launch(Dispatchers.IO) {
        combine(provider.generationState, settings.state) { generation, policy -> generation to policy }
            .collectLatest { (generation, _) ->
            while (isActive) {
                try {
                    // Cancellation by a stale collector must not race installing a newer generation.
                    provider.withCurrentOrDisabled(generation) {
                        retireOldWork(generation)
                        if (generation == null) {
                            manager.cancelUniqueWork(RECONCILE_NAME).result.get(1, TimeUnit.SECONDS)
                        } else {
                            val policy = settings.read()
                            val request = PeriodicWorkRequestBuilder<WakeReconcileWorker>(policy.reconcileMinutes.toLong(), TimeUnit.MINUTES)
                                .setInputData(workDataOf(WAKE_GENERATION to generation.toString()))
                                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, policy.backoffSeconds.toLong(), TimeUnit.SECONDS)
                                .addTag(generationTag(generation)).build()
                            manager.enqueueUniquePeriodicWork(RECONCILE_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
                                .result.get(1, TimeUnit.SECONDS)
                        }
                    }
                    if (generation != null) reconcile(generation)
                    break
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { generation?.let { report(it, PushDeliveryStatus.UNAVAILABLE) }; delay(10_000) }
            }
        }
    }
    private fun retireOldWork(generation: UUID?) {
        val current = generation?.let(::generationTag)
        val stale = listOf(INGRESS_TAG, FETCH_TAG).flatMap { manager.getWorkInfosByTag(it).get(1, TimeUnit.SECONDS) }
            .filter { !it.state.isFinished }.flatMap { it.tags }
            .filter { it.startsWith(GENERATION_PREFIX) && it != current }.toSet()
        for (tag in stale) manager.cancelAllWorkByTag(tag).result.get(1, TimeUnit.SECONDS)
    }
    private fun count(vararg tags: String) = tags.flatMap { manager.getWorkInfosByTag(it).get(1, TimeUnit.SECONDS) }
        .distinctBy { it.id }.count { !it.state.isFinished }
    private fun reportAdmission(generation: UUID, admission: WakeWorkAdmission) = report(generation, when (admission) {
        WakeWorkAdmission.QUEUED -> PushDeliveryStatus.QUEUED
        WakeWorkAdmission.CAPACITY_LIMIT -> PushDeliveryStatus.CAPACITY_LIMIT
        WakeWorkAdmission.UNAVAILABLE -> PushDeliveryStatus.UNAVAILABLE
    })
    private fun generationTag(generation: UUID) = GENERATION_PREFIX + generation
    private fun dev.remozio.protocol.CborValue.Bytes.hex() = copyBytes().joinToString("") { "%02x".format(it.toInt() and 255) }
    companion object {
        private const val GENERATION_PREFIX = "remozio.wake.generation."
        private const val INGRESS_TAG = "remozio.fcm.ingress.v2"
        // Legacy jobs lack generation tags. Preserve their hints and count them until their worker retires them.
        private const val LEGACY_INGRESS_TAG = "remozio.fcm.ingress.v1"
        private const val FETCH_TAG = "remozio.wake.snapshot.v1"
        private const val RECONCILE_NAME = "remozio.wake.reconcile.v1"
    }
}
