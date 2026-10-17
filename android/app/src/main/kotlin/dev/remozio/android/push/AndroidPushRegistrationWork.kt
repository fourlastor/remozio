package dev.remozio.android.push

import android.content.Context
import android.annotation.SuppressLint
import androidx.work.*
import dev.remozio.phone.push.PendingPushChallengeTicket
import dev.remozio.protocol.CborValue
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collectLatest

internal const val REGISTRATION_GENERATION = "provider_generation"
internal const val REGISTRATION_REVISION = "token_revision"
internal const val REGISTRATION_RECORD = "record"
internal const val REGISTRATION_TAG = "enrollment"
internal const val REGISTRATION_TRIGGER = "trigger"

/** Work data contains opaque identifiers only. Provider tokens and challenges remain with their private owners. */
internal class AndroidPushRegistrationWork(
    context: Context,
    private val provider: PushClientOwner,
    private val settings: PushRegistrationWorkSettings,
    private val records: suspend (UUID, UUID, CborValue.Bytes?) -> List<CborValue.Bytes>,
    private val workerClass: Class<out ListenableWorker> = PushRegistrationWorker::class.java,
    private val namespace: String = "remozio.push.registration",
) {
    init { require(namespace.length in 1..128 && namespace.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' }) }
    private val app = context.applicationContext
    private val attemptTag = "$namespace.attempt.v1"
    private val ingressTag = "$namespace.ingress.v1"
    private val selectionPrefix = "$namespace.selection."
    private val reconcileName = "$namespace.reconcile.v1"
    private val manager by lazy { WorkManager.getInstance(app) }
    private val retry = PushRegistrationReconcileRetry()
    private val cursor = app.getSharedPreferences("$namespace.cursor.v1", Context.MODE_PRIVATE)
    private val attempts = BoundedWakeWorkAdmission<Pair<String, OneTimeWorkRequest>>(256,
        { count(attemptTag) }, { (name, work) -> manager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, work).result })
    private val ingress = BoundedWakeWorkAdmission<Pair<String, OneTimeWorkRequest>>(256,
        { count(ingressTag) }, { (name, work) -> manager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, work).result })

    /** The provider callback invokes this only after encrypted challenge admission succeeds. */
    fun accept(ticket: PendingPushChallengeTicket): Boolean {
        val selected = provider.tokenCandidate() ?: return true
        if (selected.generation != ticket.generation) return true
        return enqueueReconcile(selected.generation, selected.revision, ticket.tag, ticket.revision.hex())
    }
    /** Pairing invokes this after the archive commit and outside the enrollment lock. */
    fun changed(): Boolean {
        val selected = provider.tokenCandidate() ?: return true
        return enqueueReconcile(selected.generation, selected.revision, null, "changed")
    }
    private fun enqueueReconcile(generation: UUID, revision: UUID, tag: CborValue.Bytes?, trigger: String): Boolean = retry.enqueue {
        provider.withCurrentToken(generation, revision) {
            val policy = settings.read(); ingress.setMaximumQueued(policy.queueLimit)
            val fields = mutableMapOf<String, Any>(REGISTRATION_GENERATION to generation.toString(),
                REGISTRATION_REVISION to revision.toString(), REGISTRATION_TRIGGER to trigger)
            tag?.let { fields[REGISTRATION_TAG] = it.hex() }
            val request = OneTimeWorkRequestBuilder<PushRegistrationReconcileWorker>()
                .setInputData(Data.Builder().putAll(fields).build()).addTag(ingressTag).addTag(selectionTag(generation, revision))
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, policy.backoffSeconds.toLong(), TimeUnit.SECONDS)
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST).build()
            ingress.admit("$namespace.ingress.$generation.$revision.$trigger" to request) == WakeWorkAdmission.QUEUED
        } ?: true
    }

    /** A retained cursor keeps a small queue fair across more independently enrolled Macs. */
    @SuppressLint("UseKtx")
    suspend fun reconcile(generation: UUID, revision: UUID, tag: CborValue.Bytes? = null, trigger: String = "refresh"): Boolean =
        withContext(Dispatchers.IO) {
            val selected = provider.tokenCandidate()
            if (selected?.generation != generation || selected.revision != revision) return@withContext true
            val selectedRecords = records(generation, revision, tag)
            val after = provider.withCurrentToken(generation, revision) {
                if (tag == null && cursor.getString("selection", null) == selectionTag(generation, revision))
                    Cursor(registrationIdentifier(cursor.getString("after", null), 16)) else Cursor(null)
            } ?: return@withContext true
            for (recordID in registrationWorkOrder(selectedRecords, after.value)) {
                val admitted = provider.withCurrentToken(generation, revision) {
                    val policy = settings.read(); attempts.setMaximumQueued(policy.queueLimit)
                    val request = OneTimeWorkRequest.Builder(workerClass)
                        .setInputData(workDataOf(REGISTRATION_GENERATION to generation.toString(),
                            REGISTRATION_REVISION to revision.toString(), REGISTRATION_RECORD to recordID.hex()))
                        .addTag(attemptTag).addTag(selectionTag(generation, revision))
                        .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, policy.backoffSeconds.toLong(), TimeUnit.SECONDS).build()
                    val queued = attempts.admit("$namespace.$generation.$revision.${recordID.hex()}.$trigger" to request)
                    if (queued != WakeWorkAdmission.QUEUED) false
                    else tag != null || cursor.edit().putString("selection", selectionTag(generation, revision))
                        .putString("after", recordID.hex()).commit()
                } ?: return@withContext true
                if (!admitted) return@withContext false
            }
            true
        }

    /** Restart and provider changes reconcile retained state. Every obsolete collector is fenced again before mutation. */
    fun start(scope: CoroutineScope) = scope.launch(Dispatchers.IO) {
        combine(provider.generationState, provider.tokenRevisionState, settings.state) { generation, revision, policy ->
            Triple(generation, revision, policy)
        }.collectLatest { (generation, revision, policy) ->
            retry.run {
                provider.withCurrentTokenOrDisabled(generation, revision) {
                    retireOldWork(generation, revision)
                    if (generation == null || revision == null) manager.cancelUniqueWork(reconcileName).result.get(1, TimeUnit.SECONDS)
                    else {
                        val request = PeriodicWorkRequestBuilder<PushRegistrationReconcileWorker>(policy.reconcileMinutes.toLong(), TimeUnit.MINUTES)
                            .setInputData(workDataOf(REGISTRATION_GENERATION to generation.toString(), REGISTRATION_REVISION to revision.toString()))
                            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, policy.backoffSeconds.toLong(), TimeUnit.SECONDS)
                            .addTag(selectionTag(generation, revision)).build()
                        manager.enqueueUniquePeriodicWork(reconcileName, ExistingPeriodicWorkPolicy.UPDATE, request).result.get(1, TimeUnit.SECONDS)
                    }
                }
                generation == null || revision == null || reconcile(generation, revision)
            }
        }
    }
    private class Cursor(val value: CborValue.Bytes?)
    private fun retireOldWork(generation: UUID?, revision: UUID?) {
        val current = if (generation != null && revision != null) selectionTag(generation, revision) else null
        val obsolete = listOf(attemptTag, ingressTag).flatMap { manager.getWorkInfosByTag(it).get(1, TimeUnit.SECONDS) }
            .filter { !it.state.isFinished }.flatMap { it.tags }.filter { it.startsWith(selectionPrefix) && it != current }.toSet()
        for (tag in obsolete) manager.cancelAllWorkByTag(tag).result.get(1, TimeUnit.SECONDS)
    }
    private fun count(tag: String) = manager.getWorkInfosByTag(tag).get(1, TimeUnit.SECONDS).count { !it.state.isFinished }
    private fun selectionTag(generation: UUID, revision: UUID) = "$selectionPrefix$generation.$revision"

}

internal fun CborValue.Bytes.hex() = copyBytes().joinToString("") { "%02x".format(it.toInt() and 255) }
internal fun registrationIdentifier(text: String?, bytes: Int): CborValue.Bytes? {
    if (text == null || text.length != bytes * 2 || text.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
    return CborValue.Bytes(ByteArray(bytes) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() })
}
internal fun registrationWorkOrder(records: List<CborValue.Bytes>, after: CborValue.Bytes?): List<CborValue.Bytes> {
    val ordered = records.distinct().sortedBy { it.hex() }
    val point = after?.hex() ?: return ordered
    val index = ordered.indexOfFirst { it.hex() > point }.takeIf { it >= 0 } ?: 0
    return ordered.drop(index) + ordered.take(index)
}
