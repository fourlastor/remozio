package dev.remozio.android.push

import dev.remozio.android.requests.CommandConnection
import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.push.WakeDemandTicket
import dev.remozio.protocol.CborValue
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class WakeFetchResult { COMPLETE, RETRY, OBSOLETE }

/** Shares the foreground connection owner. No background decision transport exists. */
internal class StoredWakeFetches(
    private val open: () -> EncryptedEnrollmentStore?,
    private val enrollmentAccess: Mutex,
    private val provider: PushClientOwner,
    private val demand: ApplicationWakeDemand,
    private val acquire: suspend (CborValue.Bytes) -> CommandConnection,
    private val timeoutMillis: () -> Long,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private class Entry(val record: StoredPhoneEnrollment) {
        val mutex = Mutex()
        val jobs = mutableSetOf<Job>()
        @Volatile var retired = false
    }
    private val entries = mutableMapOf<CborValue.Bytes, Entry>()

    suspend fun pending(generation: UUID): List<WakeDemandTicket> = withContext(dispatcher) {
        enrollmentAccess.withLock {
            val active = activeLocked()
            demand.pending(generation, active.map { it.enrollment.enrollmentTag }.toSet())
        }
    }

    suspend fun fetch(generation: UUID, tag: CborValue.Bytes): WakeFetchResult = withContext(dispatcher) {
        if (provider.generation() != generation) return@withContext WakeFetchResult.OBSOLETE
        val job = currentCoroutineContext().job
        val entry = enrollmentAccess.withLock {
            val active = activeLocked()
            val record = active.singleOrNull { it.enrollment.enrollmentTag == tag } ?: return@withLock null
            val selected = entries.getOrPut(record.enrollment.recordID) { Entry(record) }
            selected.jobs += job
            selected
        } ?: return@withContext WakeFetchResult.OBSOLETE
        try {
            coroutineScope {
                val owner = currentCoroutineContext().job
                val retirement = launch(start = CoroutineStart.UNDISPATCHED) {
                    provider.generationState.first { it != generation }
                    owner.cancel()
                }
                try {
                    if (!entry.mutex.tryLock()) WakeFetchResult.RETRY
                    else try { fetchLocked(entry, generation, tag) } finally { entry.mutex.unlock() }
                }
                finally { retirement.cancel() }
            }
        } catch (cancelled: CancellationException) {
            currentCoroutineContext().ensureActive()
            if (provider.generation() != generation || entry.retired) WakeFetchResult.OBSOLETE else WakeFetchResult.RETRY
        } catch (_: Exception) { WakeFetchResult.RETRY }
        finally { withContext(NonCancellable) { enrollmentAccess.withLock { entry.jobs -= job } } }
    }

    private suspend fun fetchLocked(entry: Entry, generation: UUID, tag: CborValue.Bytes): WakeFetchResult {
        val ticket = enrollmentAccess.withLock {
            val active = activeLocked()
            if (!current(entry, active)) return@withLock null
            demand.pending(generation, active.map { it.enrollment.enrollmentTag }.toSet()).singleOrNull { it.tag == tag }
        } ?: return WakeFetchResult.COMPLETE
        val connection = acquire(entry.record.enrollment.recordID)
        val valid = enrollmentAccess.withLock {
            current(entry, activeLocked()) && entry.record.sameConnectionAs(connection.record) && provider.generation() == generation
        }
        if (!valid) return WakeFetchResult.OBSOLETE
        if (!connection.fetchSnapshot(timeoutMillis())) return WakeFetchResult.RETRY
        currentCoroutineContext().ensureActive()
        return enrollmentAccess.withLock {
            val active = activeLocked()
            if (!current(entry, active) || provider.generation() != generation) return@withLock WakeFetchResult.OBSOLETE
            if (demand.complete(ticket)) WakeFetchResult.COMPLETE else WakeFetchResult.RETRY
        }
    }
    private fun current(entry: Entry, active: List<StoredPhoneEnrollment>) = !entry.retired &&
        active.any { it.enrollment.recordID == entry.record.enrollment.recordID && it.sameConnectionAs(entry.record) }

    private fun activeLocked(): List<StoredPhoneEnrollment> {
        val active = open()?.use { it.snapshot().entries.filter { row -> row.phase == EnrollmentPhase.ACTIVE } } ?: emptyList()
        val rows = active.associateBy { it.enrollment.recordID }
        invalidateRecordsLocked(entries.filter { (id, entry) -> rows[id]?.sameConnectionAs(entry.record) != true }.keys.toSet())
        return active
    }
    /** Pairing calls this before committing trust changes, under enrollmentAccess. */
    fun invalidateRecordsLocked(ids: Set<CborValue.Bytes>) {
        ids.forEach { id -> entries.remove(id)?.let { entry ->
            entry.retired = true
            entry.jobs.forEach { it.cancel() }
        } }
    }
}
