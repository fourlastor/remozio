package dev.sebastiano.remozio.android.updates

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.PhoneUpdateProgressObservation
import dev.remozio.phone.transport.PhoneUpdateSchedulingStatus
import dev.remozio.protocol.UpdateSchedulingAction
import dev.remozio.protocol.UpdateSchedulingDesignation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.job
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

internal enum class MacUpdateProgressAvailability { UNKNOWN, ONLINE, OFFLINE, CLOSED }

internal class MacUpdateProgressState(
    val availability: MacUpdateProgressAvailability,
    val observation: PhoneUpdateProgressObservation? = null,
) {
    override fun toString() = "MacUpdateProgressState(redacted)"
}

internal interface MacUpdateProgressWire : AutoCloseable {
    suspend fun read(): PhoneUpdateProgressObservation
    suspend fun closeAndJoin()
}

/** Owns one enrollment incarnation. Each refresh reads one Root-signed observation. */
internal class MacUpdateProgressConnection(
    val record: StoredPhoneEnrollment,
    private val open: suspend (CoroutineScope, StoredPhoneEnrollment) -> MacUpdateProgressWire,
    private val currentEnrollment: suspend () -> StoredPhoneEnrollment,
    private val freshnessMillis: () -> Long,
    private val timeoutMillis: () -> Long,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : AutoCloseable {
    init { require(record.phase == EnrollmentPhase.ACTIVE) }

    private val operation = Mutex()
    private val monitor = Any()
    private var closed = false
    private var cleanupFailed = false
    private var wire: MacUpdateProgressWire? = null
    private var job: Job? = null
    private val mutableState = MutableStateFlow(MacUpdateProgressState(MacUpdateProgressAvailability.UNKNOWN))
    val state = mutableState.asStateFlow()

    fun snapshot(): MacUpdateProgressState = synchronized(monitor) {
        val value = mutableState.value
        if (value.availability != MacUpdateProgressAvailability.ONLINE) return@synchronized value
        val maximumAge = freshnessMillis()
        if (maximumAge <= 0 || value.observation?.isFresh(maximumAge) != true) {
            MacUpdateProgressState(MacUpdateProgressAvailability.OFFLINE, value.observation)
        } else value
    }

    /** Root supplies eligibility. The scheduling owner must still obtain and sign a fresh challenge. */
    fun canOffer(
        expected: PhoneUpdateProgressObservation,
        scheduling: PhoneUpdateSchedulingStatus,
        action: UpdateSchedulingAction,
    ): Boolean = synchronized(monitor) {
        if (closed || cleanupFailed || mutableState.value.observation !== expected) return@synchronized false
        val maximumAge = freshnessMillis()
        if (maximumAge <= 0 ||
            mutableState.value.availability != MacUpdateProgressAvailability.ONLINE || !expected.isFresh(maximumAge) ||
            !expected.matchesEnrollment(record) || !scheduling.matchesEnrollment(record) ||
            !scheduling.isFresh(maximumAge)) return@synchronized false
        val progress = expected.response
        val current = scheduling.response
        if (progress.status.scope != current.scope || progress.status.updateID != current.updateID ||
            progress.status.generation != current.generation || progress.status.revision != current.revision ||
            progress.status.requestedAction != current.requestedAction) {
            return@synchronized false
        }
        when (action) {
            UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES -> progress.canInstallWhenCurrentWorkFinishes
            UpdateSchedulingAction.DEFER_UPDATE ->
                progress.designation == UpdateSchedulingDesignation.THIS_ACCOUNT && progress.canDeferUpdate
            UpdateSchedulingAction.CANCEL_DRAIN -> progress.canCancelDrain
        }
    }

    suspend fun refresh(): Boolean = withContext(dispatcher) {
        currentCoroutineContext().ensureActive()
        if (!operation.tryLock()) return@withContext false
        try {
            coroutineScope {
                synchronized(monitor) { check(!closed && !cleanupFailed); job = coroutineContext.job }
                try {
                    val timeout = timeoutMillis()
                    require(timeout in 1..60_000)
                    withTimeout(timeout) {
                        checkCurrent()
                        exchange()
                    }
                    true
                } catch (_: TimeoutCancellationException) {
                    unavailable()
                    currentCoroutineContext().ensureActive()
                    false
                } catch (cancelled: CancellationException) {
                    unavailable()
                    throw cancelled
                } catch (_: Exception) {
                    unavailable()
                    false
                }
            }
        } finally { operation.unlock() }
    }

    private suspend fun CoroutineScope.exchange() {
        checkCurrent()
        val candidate = open(this, record)
        var produced: PhoneUpdateProgressObservation? = null
        var retained = false
        try {
            try {
                synchronized(monitor) { check(!closed && !cleanupFailed); wire = candidate }
                checkCurrent()
                produced = candidate.read()
                checkCurrent()
                require(checkNotNull(produced).matchesEnrollment(record))
            } finally {
                try {
                    withContext(NonCancellable) { candidate.closeAndJoin() }
                    synchronized(monitor) { if (wire === candidate) wire = null }
                } catch (failure: Exception) {
                    synchronized(monitor) { cleanupFailed = true }
                    throw failure
                }
            }
            checkCurrent()
            val value = checkNotNull(produced)
            val maximumAge = freshnessMillis()
            require(maximumAge > 0 && value.isFresh(maximumAge))
            synchronized(monitor) {
                check(!closed && !cleanupFailed)
                val old = mutableState.value.observation
                mutableState.value = MacUpdateProgressState(MacUpdateProgressAvailability.ONLINE, value)
                retained = true
                if (old !== value) old?.close()
            }
        } finally { if (!retained) produced?.close() }
    }

    private suspend fun checkCurrent(): StoredPhoneEnrollment {
        currentCoroutineContext().ensureActive()
        synchronized(monitor) { check(!closed && !cleanupFailed) }
        val current = currentEnrollment()
        currentCoroutineContext().ensureActive()
        require(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        synchronized(monitor) { check(!closed && !cleanupFailed) }
        return current
    }

    private fun unavailable() = synchronized(monitor) {
        if (!closed) mutableState.value = MacUpdateProgressState(
            MacUpdateProgressAvailability.OFFLINE, mutableState.value.observation)
    }

    override fun close() {
        val owned = synchronized(monitor) {
            if (closed) { check(!cleanupFailed); return }
            closed = true
            mutableState.value.observation?.close()
            mutableState.value = MacUpdateProgressState(MacUpdateProgressAvailability.CLOSED)
            job to wire
        }
        owned.first?.cancel()
        try { owned.second?.close() }
        catch (failure: Exception) {
            synchronized(monitor) { cleanupFailed = true }
            throw failure
        }
        check(!synchronized(monitor) { cleanupFailed })
    }

    internal fun retirementSettled(): Boolean = synchronized(monitor) {
        check(closed && !cleanupFailed)
        job?.isCompleted != false && wire == null
    }

    override fun toString() = "MacUpdateProgressConnection(redacted)"
}
