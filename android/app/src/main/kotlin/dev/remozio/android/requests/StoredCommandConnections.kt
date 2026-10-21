package dev.remozio.android.requests

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import java.util.Collections
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** One active enrollment scope. A missing owner indicates a local failure, never a successful connection. */
internal class StoredCommandOwner(
    val recordID: CborValue.Bytes,
    val macID: CborValue.Bytes,
    val accountID: CborValue.Bytes,
    val label: String,
    val connection: CommandConnection?,
) {
    override fun toString() = "StoredCommandOwner(redacted)"
}

/** Application-owned connections survive screen recreation and ordinary network failures. */
internal class StoredCommandConnections(
    private val open: () -> EncryptedEnrollmentStore?,
    private val create: (StoredPhoneEnrollment) -> CommandConnection,
    private val enrollmentAccess: Mutex,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val closeConnection: (CommandConnection) -> Unit = { it.close() },
) {
    private data class FailedScope(val macID: CborValue.Bytes, val accountID: CborValue.Bytes)
    private fun scope(record: StoredPhoneEnrollment) = FailedScope(record.enrollment.macID, record.enrollment.accountID)
    private val failedClosures = mutableSetOf<CborValue.Bytes>()
    private val failedScopes = mutableSetOf<FailedScope>()
    private val owners = mutableMapOf<CborValue.Bytes, CommandConnection>()

    /** Takes one archive snapshot, retires changed incarnations, then acquires each independent active scope. */
    suspend fun acquireActive(): List<StoredCommandOwner> = withContext(dispatcher) {
        val context = currentCoroutineContext()
        enrollmentAccess.withLock {
            val rows = try {
                open()?.use { it.snapshot().entries } ?: emptyList()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                invalidateLocked()
                throw CommandRegistryUnavailable()
            }
            val active = rows.filter { it.phase == EnrollmentPhase.ACTIVE }.associateBy { it.enrollment.recordID }
            val stale = owners.filter { (id, owner) -> active[id]?.sameConnectionAs(owner.record) != true }
            // Finish retirement for every changed scope before constructing any replacement.
            stale.keys.forEach { id ->
                try { invalidateRecordsLocked(setOf(id)) }
                catch (_: CommandRegistryUnavailable) { /* This scope remains blocked by failedClosures. */ }
            }
            val acquired = active.values.map { record ->
                context.ensureActive()
                val e = record.enrollment
                val connection = if (e.recordID in failedClosures || scope(record) in failedScopes) null else owners[e.recordID] ?: try {
                    create(record).also { owners[e.recordID] = it }
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { null }
                StoredCommandOwner(e.recordID, e.macID, e.accountID, e.label, connection)
            }
            Collections.unmodifiableList(acquired)
        }
    }

    /** Revalidates the complete archive before returning an existing owner or opening its request index. */
    suspend fun acquire(recordID: CborValue.Bytes): CommandConnection = withContext(dispatcher) {
        enrollmentAccess.withLock {
            if (recordID in failedClosures) throw CommandRegistryUnavailable()
            val rows = try {
                open()?.use { it.snapshot().entries } ?: emptyList()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                invalidateLocked()
                throw CommandRegistryUnavailable()
            }
            val active = rows.filter { it.phase == EnrollmentPhase.ACTIVE }.associateBy { it.enrollment.recordID }
            val stale = owners.filter { (id, owner) -> active[id]?.sameConnectionAs(owner.record) != true }
            // Invalidate every changed incarnation before constructing any replacement.
            invalidateRecordsLocked(stale.keys)
            val record = active[recordID] ?: throw CommandEnrollmentUnavailable()
            if (scope(record) in failedScopes) throw CommandRegistryUnavailable()
            owners[recordID] ?: try {
                create(record).also { owners[recordID] = it }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { throw CommandRegistryUnavailable() }
        }
    }

    /** Setup must call this before committing enrollment changes, under the same enrollment mutex. */
    internal fun invalidateLocked() {
        invalidateRecordsLocked(owners.keys.toSet() + failedClosures)
    }

    /** The application enrollment host holds the shared mutex while retiring these records. */
    internal fun invalidateRecordsLocked(recordIDs: Set<CborValue.Bytes>) {
        recordIDs.forEach { id ->
            val owner = owners.remove(id)
            if (owner != null) {
                try { closeConnection(owner) } catch (_: Exception) {
                    failedClosures.add(id); failedScopes.add(scope(owner.record))
                }
            }
        }
        if (recordIDs.any { it in failedClosures }) throw CommandRegistryUnavailable()
    }

    suspend fun invalidate() = withContext(dispatcher) {
        enrollmentAccess.withLock { invalidateLocked() }
    }


}

internal class CommandEnrollmentUnavailable : IllegalStateException("Enrollment is not active")
internal class CommandRegistryUnavailable : IllegalStateException("Command storage unavailable")
