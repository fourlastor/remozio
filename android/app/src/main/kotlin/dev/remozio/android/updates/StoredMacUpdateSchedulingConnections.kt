package dev.remozio.android.updates

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Retires changed enrollment incarnations before another owner can use their Mac and account scope. */
internal class StoredMacUpdateSchedulingConnections(
    private val open: () -> EncryptedEnrollmentStore?,
    private val create: (StoredPhoneEnrollment, suspend () -> StoredPhoneEnrollment) -> MacUpdateSchedulingConnection,
    private val enrollmentAccess: Mutex,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val closeConnection: (MacUpdateSchedulingConnection) -> Unit = { it.close() },
) {
    private data class Scope(val macID: CborValue.Bytes, val accountID: CborValue.Bytes)
    private fun scope(record: StoredPhoneEnrollment) = Scope(record.enrollment.macID, record.enrollment.accountID)
    private val owners = mutableMapOf<CborValue.Bytes, MacUpdateSchedulingConnection>()
    private val retiring = mutableMapOf<CborValue.Bytes, MacUpdateSchedulingConnection>()
    private val failedRecords = mutableSetOf<CborValue.Bytes>()
    private val failedScopes = mutableSetOf<Scope>()

    suspend fun acquire(recordID: CborValue.Bytes): MacUpdateSchedulingConnection = withContext(dispatcher) {
        val context = currentCoroutineContext()
        enrollmentAccess.withLock {
            val active = activeLocked()
            retireChangedLocked(active)
            val record = active[recordID] ?: throw MacUpdateSchedulingEnrollmentUnavailable()
            requireAvailable(record)
            owners[recordID] ?: run {
                context.ensureActive()
                val owner = try { create(record) { current(record) } }
                catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { throw MacUpdateSchedulingRegistryUnavailable() }
                try {
                    context.ensureActive()
                    if (!owner.record.sameConnectionAs(record)) throw MacUpdateSchedulingRegistryUnavailable()
                    owners[recordID] = owner
                    owner
                } catch (failure: Throwable) {
                    retiring[recordID] = owner
                    try { closeConnection(owner) } catch (_: Exception) {
                        failedRecords.add(recordID); failedScopes.add(scope(record))
                    }
                    throw failure
                }
            }
        }
    }

    /** Network and signing work never hold the archive mutex. Every check reopens the current archive. */
    private suspend fun current(expected: StoredPhoneEnrollment): StoredPhoneEnrollment = withContext(dispatcher) {
        enrollmentAccess.withLock {
            val active = activeLocked()
            retireChangedLocked(active)
            val current = active[expected.enrollment.recordID] ?: throw MacUpdateSchedulingEnrollmentUnavailable()
            if (!current.sameConnectionAs(expected)) throw MacUpdateSchedulingEnrollmentUnavailable()
            requireAvailable(expected)
            current
        }
    }

    private fun activeLocked(): Map<CborValue.Bytes, StoredPhoneEnrollment> = try {
        (open()?.use { it.snapshot().entries } ?: emptyList()).filter { it.phase == EnrollmentPhase.ACTIVE }
            .associateBy { it.enrollment.recordID }
    } catch (cancelled: CancellationException) { throw cancelled }
    catch (_: Exception) {
        try { invalidateLocked() } catch (_: MacUpdateSchedulingRegistryUnavailable) { }
        throw MacUpdateSchedulingRegistryUnavailable()
    }

    private fun requireAvailable(record: StoredPhoneEnrollment) {
        settleRetirementsLocked()
        if (record.enrollment.recordID in failedRecords || scope(record) in failedScopes ||
            retiring.values.any { scope(it.record) == scope(record) })
            throw MacUpdateSchedulingRegistryUnavailable()
    }

    private fun settleRetirementsLocked() {
        retiring.keys.toList().forEach { id ->
            val owner = checkNotNull(retiring[id])
            try {
                if (owner.retirementSettled()) retiring.remove(id)
            } catch (_: Exception) {
                failedRecords.add(id); failedScopes.add(scope(owner.record))
            }
        }
    }

    private fun retireChangedLocked(active: Map<CborValue.Bytes, StoredPhoneEnrollment>) {
        owners.filter { (id, owner) -> active[id]?.sameConnectionAs(owner.record) != true }.keys.toList().forEach { id ->
            try { invalidateRecordsLocked(setOf(id)) } catch (_: MacUpdateSchedulingRegistryUnavailable) { }
        }
    }

    /** The enrollment host holds the shared mutex and calls this before it commits a change. */
    internal fun invalidateRecordsLocked(recordIDs: Set<CborValue.Bytes>) {
        recordIDs.forEach { id ->
            val owner = owners.remove(id)
            if (owner != null) {
                retiring[id] = owner
                try { closeConnection(owner) } catch (_: Exception) {
                    failedRecords.add(id); failedScopes.add(scope(owner.record))
                }
            }
        }
        settleRetirementsLocked()
        if (recordIDs.any { it in failedRecords }) throw MacUpdateSchedulingRegistryUnavailable()
    }

    internal fun invalidateLocked() = invalidateRecordsLocked(owners.keys.toSet() + retiring.keys + failedRecords)

    suspend fun invalidate() = withContext(dispatcher) {
        enrollmentAccess.withLock { invalidateLocked() }
    }
}

internal class MacUpdateSchedulingEnrollmentUnavailable : IllegalStateException("Enrollment is not active")
internal class MacUpdateSchedulingRegistryUnavailable : IllegalStateException("Update scheduling storage unavailable")
