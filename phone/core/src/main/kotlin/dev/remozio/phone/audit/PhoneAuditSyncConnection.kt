package dev.remozio.phone.audit

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.PhoneAuditResult
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Captured once per explicit round. Saving settings cannot alter an active round's limits. */
data class AuditRoundLimits(val responseBudget: Int = 32, val timeoutMillis: Long = 30_000) {
    init { require(responseBudget in 1..4096 && timeoutMillis in 1..60_000) }
}

/** One enrolled audit exchange. The owner must join its stream before releasing the cache. */
interface AuditExchange : AutoCloseable {
    suspend fun exchange(query: AuditQuery): PhoneAuditResult
    suspend fun closeAndJoin()
}

/**
 * Owns one enrollment incarnation and cache. The application supplies a gate that runs under its enrollment mutex.
 * Only that gate may accept evidence. Network calls never hold it. No operation implies current Mac presence.
 */
class PhoneAuditSyncConnection(
    val record: StoredPhoneEnrollment,
    private val session: AuditSyncSession,
    private val open: suspend (CoroutineScope, StoredPhoneEnrollment, AuditRoundLimits) -> AuditExchange,
    private val withCurrent: suspend ((StoredPhoneEnrollment) -> Unit) -> Boolean,
    private val roundLimits: () -> AuditRoundLimits,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : AutoCloseable {
    init {
        val binding = session.binding
        val enrollment = record.enrollment
        require(record.phase == EnrollmentPhase.ACTIVE && binding.macID.contentEquals(enrollment.macID.copyBytes()) &&
            binding.accountID.contentEquals(enrollment.accountID.copyBytes()) &&
            binding.authorityPublicKey.contentEquals(enrollment.authorityPublicKey.copyBytes()))
        require(session.state.value.phase == AuditSyncPhase.IDLE)
    }
    private class OperationMarker(val owner: PhoneAuditSyncConnection) : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<OperationMarker>
    }
    private val operation = Mutex()
    private val retirement = Mutex()
    private val monitor = Any()
    private var closed = false
    private var cleanupFailed = false
    private var cacheCloseFailed = false
    private var job: Job? = null
    private var wire: AuditExchange? = null
    private var pending: AuditQuery? = null
    val state = session.state

    /** Busy calls do not queue or duplicate a round. A paused round requires explicit resume or cancellation. */
    suspend fun refresh(): Boolean = perform(resume = false)
    suspend fun resume(): Boolean = perform(resume = true)

    private suspend fun perform(resume: Boolean): Boolean = withContext(dispatcher + OperationMarker(this)) {
        currentCoroutineContext().ensureActive()
        if (!operation.tryLock()) return@withContext false
        try {
            coroutineScope {
                synchronized(monitor) { check(!closed && !cleanupFailed); job = coroutineContext.job }
                try {
                    val limits = roundLimits()
                    withTimeout(limits.timeoutMillis) {
                        current {
                            if (resume) session.resume(limits.responseBudget, limits.timeoutMillis.toULong())
                            else session.start(limits.responseBudget, limits.timeoutMillis.toULong())
                        }
                        drain(limits)
                    }
                    state.value.phase == AuditSyncPhase.COMPLETE || state.value.phase == AuditSyncPhase.PAUSED
                } catch (_: TimeoutCancellationException) {
                    failPending()
                    currentCoroutineContext().ensureActive()
                    false
                } catch (cancelled: CancellationException) {
                    synchronized(monitor) { if (!closed) session.cancel(); pending = null }
                    throw cancelled
                } catch (_: Exception) {
                    failPending()
                    false
                } finally { synchronized(monitor) { job = null } }
            }
        } finally { operation.unlock() }
    }

    private suspend fun CoroutineScope.drain(limits: AuditRoundLimits) {
        while (state.value.phase == AuditSyncPhase.SYNCING) {
            currentCoroutineContext().ensureActive()
            current { }
            val query = synchronized(monitor) { check(!closed); session.next()?.also { pending = it } } ?: return
            val candidate = open(this, record, limits)
            try {
                synchronized(monitor) { check(!closed); wire = candidate }
                current { }
                val result = candidate.exchange(query)
                currentCoroutineContext().ensureActive()
                current { active ->
                    when (result) {
                        is PhoneAuditResult.Unverified -> {
                            require(result.query === query)
                            result.acceptInto(session, active)
                        }
                        is PhoneAuditResult.Failure -> {
                            require(result.query === query)
                            session.transportFailed(query)
                        }
                    }
                    pending = null
                }
            } finally {
                try {
                    withContext(NonCancellable) { candidate.closeAndJoin() }
                    synchronized(monitor) { if (wire === candidate) wire = null }
                } catch (failure: Exception) {
                    synchronized(monitor) { wire = candidate; cleanupFailed = true }
                    throw failure
                }
            }
        }
    }

    private suspend fun current(action: (StoredPhoneEnrollment) -> Unit) {
        currentCoroutineContext().ensureActive()
        var ran = false
        val accepted = withCurrent { active ->
            check(!ran && active.phase == EnrollmentPhase.ACTIVE && active.sameConnectionAs(record))
            ran = true
            synchronized(monitor) { check(!closed && !cleanupFailed); action(active) }
        }
        check(accepted && ran) { "Audit enrollment is not current" }
        currentCoroutineContext().ensureActive()
    }

    private fun failPending() = synchronized(monitor) {
        if (!closed && state.value.phase == AuditSyncPhase.SYNCING) {
            pending?.let(session::transportFailed) ?: session.cancel()
        }
        pending = null
    }

    private fun retire(): Pair<Job?, AuditExchange?> = synchronized(monitor) {
        if (!closed) { closed = true; session.cancel(); pending = null }
        job to wire
    }

    /** Fences acceptance immediately. Call closeAndJoin to prove stream settlement and release cache ownership. */
    override fun close() {
        val owned = retire()
        owned.first?.cancel()
        owned.second?.close()
    }

    /** Safe under the enrollment mutex: cancellation releases any operation waiting to enter that mutex. */
    suspend fun closeAndJoin() {
        check(currentCoroutineContext()[OperationMarker]?.owner !== this) { "An audit operation cannot join itself" }
        withContext(NonCancellable) {
            retirement.withLock {
                // Fence admission and capture the job together; no newer operation can replace that job before the join.
                val owned = retire()
                owned.first?.cancel()
                try { owned.second?.close() } catch (_: Exception) { /* Joined closure below is the settlement authority. */ }
                owned.first?.join()
                val retained = synchronized(monitor) { wire }
                if (retained != null) {
                    retained.closeAndJoin()
                    synchronized(monitor) { if (wire === retained) wire = null }
                }
                synchronized(monitor) {
                    check(!cacheCloseFailed) { "Audit cache closure is uncertain" }
                    try { session.close() } catch (failure: Throwable) { cacheCloseFailed = true; throw failure }
                }
            }
        }
    }
    override fun toString() = "PhoneAuditSyncConnection(redacted)"
}
