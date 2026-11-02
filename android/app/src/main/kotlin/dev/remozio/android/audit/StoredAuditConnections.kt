package dev.remozio.android.audit

import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** One coherent retained snapshot. Local times never change the meaning of its signed history. */
internal class AuditRetainedSnapshot(val history: AuditEvidenceSnapshot, val localTimes: AuditLocalSyncTimes?) {
    override fun toString() = "AuditRetainedSnapshot(redacted)"
}
internal typealias AuditSnapshotRead = suspend (AuditCacheBinding, () -> AuditRetainedSnapshot?) -> AuditRetainedSnapshot?
internal typealias AuditEnrollmentGate = suspend ((StoredPhoneEnrollment) -> Unit) -> Boolean
internal class AuditEnrollmentUnavailable : IllegalStateException("Audit enrollment is not active")
internal class AuditRegistryUnavailable : IllegalStateException("Audit storage unavailable")

/** Application-owned cache loading does not hold the enrollment mutex or depend on a screen's lifetime. */
internal class StoredAuditConnections(
    private val parent: CoroutineScope,
    private val openEnrollments: () -> EncryptedEnrollmentStore?,
    private val create: (StoredPhoneEnrollment, List<AuditCacheBinding>, AuditEnrollmentGate) -> PhoneAuditSyncConnection,
    private val enrollmentAccess: Mutex,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val closeConnection: suspend (PhoneAuditSyncConnection) -> Unit = { it.closeAndJoin() },
) {
    private data class Scope(val macID: CborValue.Bytes, val accountID: CborValue.Bytes)
    private fun scope(record: StoredPhoneEnrollment) = Scope(record.enrollment.macID, record.enrollment.accountID)
    private class Entry(val record: StoredPhoneEnrollment) {
        val owner = AtomicReference<PhoneAuditSyncConnection?>()
        val openingFailed = AtomicBoolean(false)
        lateinit var opening: Deferred<Unit>
        var valid = true // The enrollment mutex protects admission and retirement flags.
        var blocked = false
    }
    private val entries = mutableMapOf<CborValue.Bytes, Entry>()
    private val cacheAccess = ConcurrentHashMap<Scope, Mutex>()
    private val mutableChanges = MutableStateFlow(0uL)
    val changes = mutableChanges.asStateFlow()

    /** An authenticated inventory only. The foreground host loads each active cache independently. */
    suspend fun activeRecords(): List<StoredPhoneEnrollment> = withContext(dispatcher) {
        enrollmentAccess.withLock {
            if (!parent.isActive) throw AuditRegistryUnavailable()
            val rows = readOrRetireLocked()
            retireStaleLocked(rows)
            Collections.unmodifiableList(rows.filter { it.phase == EnrollmentPhase.ACTIVE })
        }
    }

    /** Only explicit work acquires an owner. Listing Macs does not open every retained archive. */
    suspend fun acquire(recordID: CborValue.Bytes): PhoneAuditSyncConnection = withContext(dispatcher) {
        val expected = enrollmentAccess.withLock {
            if (!parent.isActive) throw AuditRegistryUnavailable()
            readOrRetireLocked().singleOrNull { it.phase == EnrollmentPhase.ACTIVE && it.enrollment.recordID == recordID }
                ?: throw AuditEnrollmentUnavailable()
        }
        val entry = cacheAccess.computeIfAbsent(scope(expected)) { Mutex() }.withLock {
          enrollmentAccess.withLock {
            if (!parent.isActive) throw AuditRegistryUnavailable()
            val rows = readOrRetireLocked()
            retireStaleLocked(rows)
            val record = rows.singleOrNull { it.phase == EnrollmentPhase.ACTIVE && it.enrollment.recordID == recordID }
                ?: throw AuditEnrollmentUnavailable()
            if (!record.sameConnectionAs(expected)) throw AuditEnrollmentUnavailable()
            if (entries.values.any { it.blocked && scope(it.record) == scope(record) }) throw AuditRegistryUnavailable()
            entries[recordID] ?: reserveLocked(record, rows)
          }
        }
        // The application owns opening. A cancelled screen waiter cannot discard its cache or release its file lock.
        entry.opening.start()
        try { entry.opening.await() }
        catch (cancelled: CancellationException) { currentCoroutineContext().ensureActive(); throw AuditRegistryUnavailable() }
        catch (_: Exception) {
            enrollmentAccess.withLock { if (entries[recordID] === entry) retireLocked(setOf(recordID)) }
            throw AuditRegistryUnavailable()
        }
        enrollmentAccess.withLock {
            if (!parent.isActive) throw AuditRegistryUnavailable()
            val rows = readOrRetireLocked()
            val active = rows.singleOrNull { it.enrollment.recordID == recordID && it.phase == EnrollmentPhase.ACTIVE }
            if (entries[recordID] !== entry || !entry.valid || active?.sameConnectionAs(entry.record) != true) {
                if (entries[recordID] === entry) retireLocked(setOf(recordID))
                throw AuditEnrollmentUnavailable()
            }
            val owner = entry.owner.get()
            if (owner == null || entry.openingFailed.get() || entry.blocked) {
                retireLocked(setOf(recordID))
                throw AuditRegistryUnavailable()
            }
            owner
        }
    }

    private fun reserveLocked(record: StoredPhoneEnrollment, rows: List<StoredPhoneEnrollment>): Entry {
        val entry = Entry(record)
        val retained = rows.filter { it.phase != EnrollmentPhase.PREPARED && scope(it) == scope(record) }
            .map { AuditCacheBinding(it.enrollment.macID.copyBytes(), it.enrollment.accountID.copyBytes(),
                it.enrollment.authorityPublicKey.copyBytes()) }
        entry.opening = parent.async(dispatcher, start = CoroutineStart.LAZY) {
            try {
                val owner = create(record, retained) { action -> current(entry, action) }
                entry.owner.set(owner)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { entry.openingFailed.set(true) }
        }
        entry.opening.invokeOnCompletion { mutableChanges.update { it + 1u } }
        entries[record.enrollment.recordID] = entry
        return entry
    }

    /** The callback and its durable acceptance run under the same lock as pairing changes. Network work stays outside. */
    private suspend fun current(entry: Entry, action: (StoredPhoneEnrollment) -> Unit): Boolean = withContext(dispatcher) {
        enrollmentAccess.withLock {
            if (!parent.isActive || !entry.valid || entry.blocked || !entry.opening.isCompleted || entry.openingFailed.get() ||
                entry.owner.get() == null || entries[entry.record.enrollment.recordID] !== entry) return@withLock false
            val rows = try { readLocked() } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { return@withLock false }
            val active = rows.singleOrNull { it.enrollment.recordID == entry.record.enrollment.recordID && it.phase == EnrollmentPhase.ACTIVE }
            if (active?.sameConnectionAs(entry.record) != true) return@withLock false
            action(active)
            true
        }
    }

    /** Serialize an unowned file read with cache reservation, without holding enrollment access during disk work. */
    suspend fun readSnapshot(binding: AuditCacheBinding, fallback: () -> AuditRetainedSnapshot?): AuditRetainedSnapshot? = withContext(dispatcher) {
        val selected = Scope(CborValue.Bytes(binding.macID), CborValue.Bytes(binding.accountID))
        cacheAccess.computeIfAbsent(selected) { Mutex() }.withLock {
            val owned = enrollmentAccess.withLock {
                val sameScope = entries.values.filter { scope(it.record) == selected }
                // Opening may inspect the shared legacy path, including when its Root key differs.
                if (sameScope.any { !it.opening.isCompleted }) throw AuditRegistryUnavailable()
                val matching = sameScope.firstOrNull { it.record.enrollment.authorityPublicKey == CborValue.Bytes(binding.authorityPublicKey) }
                if (matching != null) {
                    if (matching.openingFailed.get()) throw AuditRegistryUnavailable()
                    val snapshot = matching.owner.get()?.state?.value ?: throw AuditRegistryUnavailable()
                    AuditRetainedSnapshot(snapshot.history, snapshot.localTimes)
                } else {
                    if (sameScope.any { it.blocked }) throw AuditRegistryUnavailable()
                    null
                }
            }
            // The synchronous fallback closes its file before another reservation in this Mac/account can start.
            owned ?: fallback()
        }
    }

    /** Immutable retained evidence only. This does not validate live trust, connectivity or presence. */
    suspend fun ownedSnapshot(binding: AuditCacheBinding): AuditEvidenceSnapshot? = withContext(dispatcher) {
        enrollmentAccess.withLock {
            entries.values.firstOrNull { entry ->
                val e = entry.record.enrollment
                entry.valid && !entry.blocked && entry.opening.isCompleted && !entry.openingFailed.get() &&
                    e.macID.copyBytes().contentEquals(binding.macID) && e.accountID.copyBytes().contentEquals(binding.accountID) &&
                    e.authorityPublicKey.copyBytes().contentEquals(binding.authorityPublicKey)
            }?.owner?.get()?.state?.value?.history
        }
    }

    private fun readLocked() = openEnrollments()?.use { it.snapshot().entries } ?: emptyList()
    private suspend fun readOrRetireLocked(): List<StoredPhoneEnrollment> = try { readLocked() }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { retireLocked(entries.keys.toSet()); throw AuditRegistryUnavailable() }

    private suspend fun retireStaleLocked(rows: List<StoredPhoneEnrollment>) {
        val active = rows.filter { it.phase == EnrollmentPhase.ACTIVE }.associateBy { it.enrollment.recordID }
        val stale = entries.filter { (id, entry) ->
            val state = entry.owner.get()?.state?.value
            !entry.valid || active[id]?.sameConnectionAs(entry.record) != true || state?.phase == AuditSyncPhase.CLOSED ||
                (state?.phase == AuditSyncPhase.FAILED && state.failure == AuditSyncFailure.STORAGE)
        }.keys.toSet()
        stale.forEach { id -> try { retireLocked(setOf(id)) } catch (_: AuditRegistryUnavailable) { } }
    }

    /** Caller holds the shared enrollment mutex. Complete this barrier before committing removal or replacement. */
    internal suspend fun invalidateRecordsLocked(recordIDs: Set<CborValue.Bytes>) = retireLocked(recordIDs)

    private suspend fun retireLocked(recordIDs: Set<CborValue.Bytes>) = withContext(NonCancellable) {
        val selected = recordIDs.mapNotNull { id -> entries[id]?.let { id to it } }
        selected.forEach { (_, entry) -> entry.valid = false; entry.opening.cancel() }
        var failed = false
        for ((id, entry) in selected) {
            entry.opening.join()
            try {
                entry.owner.get()?.let { closeConnection(it) }
                if (entries[id] === entry) entries.remove(id)
            } catch (_: Exception) { entry.blocked = true; failed = true }
        }
        if (selected.isNotEmpty()) mutableChanges.update { it + 1u }
        if (failed) throw AuditRegistryUnavailable()
    }

    suspend fun invalidate() = withContext(dispatcher) {
        enrollmentAccess.withLock { retireLocked(entries.keys.toSet()) }
    }
}
