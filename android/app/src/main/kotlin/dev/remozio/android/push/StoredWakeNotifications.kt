package dev.remozio.android.push

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.push.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PushData
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal enum class WakeDemandAdmission { NONE, CHECK_JOURNAL, FAILED }
internal class StoredWakeReceipt(val receipt: WakeReceipt, val demand: WakeDemandAdmission)

/** Reads the trusted archive before each hint. A provider can select a saved tag, never supply a route or identity. */
internal class StoredWakeNotifications(
    private val open: () -> EncryptedEnrollmentStore?,
    private val enrollmentAccess: Mutex,
    private val provider: PushClientOwner,
    private val clock: () -> ElapsedInstant,
    private val post: (CborValue.Bytes, Boolean) -> WakeNotificationResult,
    private val cancel: (CborValue.Bytes) -> Unit,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val admit: ((UUID, StoredPhoneEnrollment, List<StoredPhoneEnrollment>) -> Unit)? = null,
) {
    private class Entry(val record: StoredPhoneEnrollment, val wake: WakeEnrollment)
    private val entries = mutableMapOf<CborValue.Bytes, Entry>()
    private var router = router()

    suspend fun receive(generation: UUID, data: Map<String, String>): WakeReceipt? =
        receiveInternal(generation, data, markDemand = false)?.receipt

    /** Notification publication precedes durable marking. Failure never withdraws a posted alert. */
    suspend fun receiveAndAdmit(generation: UUID, data: Map<String, String>): StoredWakeReceipt? =
        receiveInternal(generation, data, markDemand = true)

    private suspend fun receiveInternal(generation: UUID, data: Map<String, String>, markDemand: Boolean): StoredWakeReceipt? = withContext(dispatcher) {
        val decoded = try { PushData.decode(data) } catch (_: IllegalArgumentException) { null }
        val retained = decoded?.encode() ?: emptyMap()
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
                provider.withCurrent(generation) {
                    val receipt = router.receive(retained, clock) { wake, alert ->
                        val entry = entries.values.single { it.wake === wake }
                        post(entry.record.enrollment.recordID, alert)
                    }
                    var demand = WakeDemandAdmission.NONE
                    if (markDemand && receipt.reception == WakeReception.ACCEPTED) {
                        val wake = checkNotNull(receipt.enrollment)
                        val entry = entries.values.single { it.wake === wake }
                        try {
                            checkNotNull(admit).invoke(generation, entry.record, active)
                            demand = WakeDemandAdmission.CHECK_JOURNAL
                        } catch (failure: Exception) {
                            router.retryWake(wake, (decoded as PushData.Wake).identifier)
                            if (failure is CancellationException) throw failure
                            demand = WakeDemandAdmission.FAILED
                        }
                    } else if (markDemand && receipt.reception == WakeReception.DUPLICATE) {
                        demand = WakeDemandAdmission.CHECK_JOURNAL
                    }
                    StoredWakeReceipt(receipt, demand)
                }
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
