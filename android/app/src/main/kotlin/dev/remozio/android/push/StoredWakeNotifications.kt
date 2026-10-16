package dev.remozio.android.push

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.push.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborValue
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Reads the trusted archive before each hint. A provider can select a saved tag, never supply a route or identity. */
internal class StoredWakeNotifications(
    private val open: () -> EncryptedEnrollmentStore?,
    private val enrollmentAccess: Mutex,
    private val provider: PushClientOwner,
    private val clock: () -> ElapsedInstant,
    private val post: (CborValue.Bytes, Boolean) -> WakeNotificationResult,
    private val cancel: (CborValue.Bytes) -> Unit,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private class Entry(val record: StoredPhoneEnrollment, val wake: WakeEnrollment)
    private val entries = mutableMapOf<CborValue.Bytes, Entry>()
    private var router = router()

    suspend fun receive(generation: UUID, data: Map<String, String>): WakeReceipt? = withContext(dispatcher) {
        enrollmentAccess.withLock {
            try {
                val active = open()?.use { it.snapshot().entries.filter { row -> row.phase == EnrollmentPhase.ACTIVE } } ?: emptyList()
                val current = active.associateBy { it.enrollment.recordID }
                invalidateRecordsLocked(entries.filter { (id, entry) -> current[id]?.sameConnectionAs(entry.record) != true }.keys)
                active.forEach { record ->
                    val e = record.enrollment
                    if (e.recordID !in entries) entries[e.recordID] = Entry(record,
                        router.add(e.macID.copyBytes(), e.accountID.copyBytes(), e.epoch.copyBytes(), e.enrollmentTag.copyBytes()))
                }
                provider.withCurrent(generation) { router.receive(data, clock) { wake, alert ->
                    val entry = entries.values.single { it.wake === wake }
                    post(entry.record.enrollment.recordID, alert)
                } }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { invalidateAllLocked(); null }
        }
    }

    /** Pairing changes call this before durable publication, while holding the shared enrollment mutex. */
    fun invalidateRecordsLocked(recordIDs: Set<CborValue.Bytes>) {
        recordIDs.forEach { id ->
            entries.remove(id)?.let { router.remove(it.wake) }
            try { cancel(id) } catch (_: Exception) { }
        }
    }
    private fun invalidateAllLocked() {
        invalidateRecordsLocked(entries.keys.toSet())
        router.close(); router = router()
    }
    private fun router() = PushWakeRouter(1024, 4096, 4096, 86_400_000uL, 30_000uL)
}
