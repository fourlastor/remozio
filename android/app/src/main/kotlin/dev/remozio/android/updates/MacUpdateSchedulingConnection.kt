package dev.remozio.android.updates

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.PhoneUpdateSchedulingStatus
import dev.remozio.phone.transport.PhoneUpdateSchedulingChallengeResult
import dev.remozio.phone.transport.PhoneUpdateSchedulingApplyResult
import dev.remozio.phone.updates.PhoneUpdateSchedulingTooLateObservation
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.UpdateSchedulingAction
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex

internal enum class MacUpdateSchedulingAvailability { UNKNOWN, ONLINE, OFFLINE, CLOSED }
internal enum class MacUpdateSchedulingOutcome { SUBMITTING, ACKNOWLEDGED, FAILED, UNCERTAIN }

internal class MacUpdateSchedulingAttempt(
    val updateID: CborValue.Bytes,
    val generation: ULong,
    val revision: ULong,
    val action: UpdateSchedulingAction,
    val outcome: MacUpdateSchedulingOutcome,
) {
    fun ending(outcome: MacUpdateSchedulingOutcome) = MacUpdateSchedulingAttempt(updateID, generation, revision, action, outcome)
    override fun toString() = "MacUpdateSchedulingAttempt(redacted)"
}

internal class MacUpdateSchedulingState(
    val availability: MacUpdateSchedulingAvailability,
    val observation: PhoneUpdateSchedulingStatus? = null,
    val attempt: MacUpdateSchedulingAttempt? = null,
    val tooLate: PhoneUpdateSchedulingTooLateObservation? = null,
) {
    override fun toString() = "MacUpdateSchedulingState(redacted)"
}

internal interface UpdateSchedulingDecisionSigner : AutoCloseable {
    fun sign(challenge: PhoneUpdateSchedulingChallenge, current: StoredPhoneEnrollment): ByteArray
}

/** Owns one enrollment incarnation. Every explicit choice consumes its displayed observation once. */
internal class MacUpdateSchedulingConnection(
    val record: StoredPhoneEnrollment,
    private val open: suspend (CoroutineScope, StoredPhoneEnrollment) -> MacUpdateSchedulingWire,
    private val loadSigner: (StoredPhoneEnrollment) -> UpdateSchedulingDecisionSigner,
    private val currentEnrollment: suspend () -> StoredPhoneEnrollment,
    private val elapsedRealtimeNanos: () -> Long,
    private val freshnessMillis: () -> Long,
    private val timeoutMillis: () -> Long,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : AutoCloseable {
    init { require(record.phase == EnrollmentPhase.ACTIVE) }
    private val operation = Mutex()
    private val monitor = Any()
    private var closed = false
    private var cleanupFailed = false
    private var wire: MacUpdateSchedulingWire? = null
    private var signer: UpdateSchedulingDecisionSigner? = null
    private var job: Job? = null
    private var attemptedObservation: PhoneUpdateSchedulingStatus? = null
    private var startedAttempt = false
    private var submitted = false
    private var definitive = false
    private val mutableState = MutableStateFlow(MacUpdateSchedulingState(MacUpdateSchedulingAvailability.UNKNOWN))
    val state = mutableState.asStateFlow()

    fun snapshot(): MacUpdateSchedulingState = synchronized(monitor) {
        val value = mutableState.value
        val fresh = value.tooLate?.isFresh(freshnessMillis()) ?: value.observation?.isFresh(freshnessMillis())
        if (value.availability == MacUpdateSchedulingAvailability.ONLINE && fresh != true)
            MacUpdateSchedulingState(MacUpdateSchedulingAvailability.OFFLINE, value.observation, value.attempt, value.tooLate)
        else value
    }

    /** This checks freshness only. Root decides owner eligibility and whether activation is already irreversible. */
    fun canSchedule(expected: PhoneUpdateSchedulingStatus): Boolean = synchronized(monitor) {
        !closed && !cleanupFailed && mutableState.value.tooLate == null && mutableState.value.observation === expected && attemptedObservation !== expected &&
            mutableState.value.attempt?.outcome != MacUpdateSchedulingOutcome.SUBMITTING &&
            snapshot().availability == MacUpdateSchedulingAvailability.ONLINE && expected.matchesEnrollment(record)
    }

    suspend fun refresh(): Boolean = perform(scheduling = false) {
        exchange(accept = { publish(it) }) { it.status() }
        true
    }

    /** A new status read never retries an uncertain control. Another choice needs a fresh displayed observation. */
    suspend fun schedule(expected: PhoneUpdateSchedulingStatus, action: UpdateSchedulingAction): Boolean = perform(scheduling = true) {
        if (!canSchedule(expected)) return@perform false
        val selected = expected.response
        var acknowledged = false
        val query = PhoneUpdateSchedulingQuery.begin(record, selected.updateID.copyBytes(), selected.generation,
            selected.revision, action, elapsedRealtimeNanos, timeoutMillis())
        try {
            synchronized(monitor) {
                check(!closed)
                startedAttempt = true
                attemptedObservation = expected
                mutableState.value = MacUpdateSchedulingState(mutableState.value.availability, expected,
                    MacUpdateSchedulingAttempt(selected.updateID, selected.generation, selected.revision, action,
                        MacUpdateSchedulingOutcome.SUBMITTING))
            }
            val result = exchange { it.challengeResult(query) }
            val challenge = when (result) {
                is PhoneUpdateSchedulingChallengeResult.Ready -> result.challenge
                is PhoneUpdateSchedulingChallengeResult.TooLate -> {
                    try {
                        checkCurrent()
                        publishTooLate(result.observation, applied = false)
                        definitive = true
                    } catch (failure: Throwable) { result.close(); throw failure }
                    return@perform false
                }
            }
            try {
                checkCurrent()
                val candidate = loadSigner(record)
                try {
                    synchronized(monitor) { check(!closed); signer = candidate }
                    val signature = candidate.sign(challenge, checkCurrent())
                    checkCurrent()
                    exchange(accept = {
                        when (it) {
                            is PhoneUpdateSchedulingApplyResult.Applied -> {
                                publish(it.status, MacUpdateSchedulingOutcome.ACKNOWLEDGED)
                                acknowledged = true
                            }
                            is PhoneUpdateSchedulingApplyResult.TooLate -> publishTooLate(it.observation, applied = true)
                        }
                        definitive = true
                    }) { submitted = true; it.applyResult(challenge, signature) }
                } finally {
                    try {
                        candidate.close()
                        synchronized(monitor) { if (signer === candidate) signer = null }
                    } catch (failure: Exception) {
                        synchronized(monitor) { cleanupFailed = true }
                        throw failure
                    }
                }
            } finally { challenge.close() }
        } finally { query.close() }
        acknowledged
    }

    private suspend fun perform(scheduling: Boolean, body: suspend CoroutineScope.() -> Boolean): Boolean = withContext(dispatcher) {
        currentCoroutineContext().ensureActive()
        if (!operation.tryLock()) return@withContext false
        try {
            coroutineScope {
                synchronized(monitor) {
                    check(!closed && !cleanupFailed)
                    job = coroutineContext.job
                    startedAttempt = false
                    submitted = false
                    definitive = false
                }
                try {
                    val timeout = timeoutMillis()
                    require(timeout in 1..60_000)
                    withTimeout(timeout) { checkCurrent(); body() }
                } catch (_: TimeoutCancellationException) {
                    failure(scheduling)
                    currentCoroutineContext().ensureActive()
                    false
                } catch (cancelled: CancellationException) {
                    failure(scheduling)
                    throw cancelled
                } catch (_: Exception) {
                    failure(scheduling)
                    false
                }
            }
        } finally { operation.unlock() }
    }

    private suspend fun <T : AutoCloseable> CoroutineScope.exchange(
        accept: ((T) -> Unit)? = null,
        body: suspend (MacUpdateSchedulingWire) -> T,
    ): T {
        checkCurrent()
        val candidate = open(this, record)
        var produced: T? = null
        var retained = false
        try {
            try {
                synchronized(monitor) { check(!closed); wire = candidate }
                checkCurrent()
                val result = body(candidate)
                produced = result
                checkCurrent()
                when (result) {
                    is PhoneUpdateSchedulingStatus -> check(result.matchesEnrollment(record) && result.isFresh(freshnessMillis()))
                    is PhoneUpdateSchedulingChallengeResult.TooLate ->
                        check(result.observation.matchesEnrollment(record) && result.observation.isFresh(freshnessMillis()))
                    is PhoneUpdateSchedulingApplyResult.TooLate ->
                        check(result.observation.matchesEnrollment(record) && result.observation.isFresh(freshnessMillis()))
                    is PhoneUpdateSchedulingApplyResult.Applied ->
                        check(result.status.matchesEnrollment(record) && result.status.isFresh(freshnessMillis()))
                }
                if (accept != null) { accept(result); retained = true }
            } finally {
                try {
                    withContext(NonCancellable) { candidate.closeAndJoin() }
                    synchronized(monitor) { if (wire === candidate) wire = null }
                } catch (failure: Exception) {
                    synchronized(monitor) { cleanupFailed = true }
                    throw failure
                }
            }
            return checkNotNull(produced).also { retained = true }
        } finally { if (!retained) produced?.close() }
    }

    private suspend fun checkCurrent(): StoredPhoneEnrollment {
        currentCoroutineContext().ensureActive()
        synchronized(monitor) { check(!closed && !cleanupFailed) }
        val current = currentEnrollment()
        currentCoroutineContext().ensureActive()
        check(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        synchronized(monitor) { check(!closed && !cleanupFailed) }
        return current
    }

    private fun publish(value: PhoneUpdateSchedulingStatus, outcome: MacUpdateSchedulingOutcome? = null) = synchronized(monitor) {
        check(!closed)
        val old = mutableState.value
        val retainedTooLate = old.tooLate?.takeIf {
            it.response.progress.status.updateID == value.response.updateID &&
                it.response.progress.status.generation == value.response.generation
        }
        mutableState.value = MacUpdateSchedulingState(MacUpdateSchedulingAvailability.ONLINE, value,
            if (outcome != null) checkNotNull(old.attempt).ending(outcome) else old.attempt, retainedTooLate)
        if (old.observation !== value) old.observation?.close()
        if (old.tooLate !== retainedTooLate) old.tooLate?.close()
    }

    private fun publishTooLate(value: PhoneUpdateSchedulingTooLateObservation, applied: Boolean) = synchronized(monitor) {
        check(!closed)
        val old = mutableState.value
        val outcome = if (applied) MacUpdateSchedulingOutcome.UNCERTAIN else MacUpdateSchedulingOutcome.FAILED
        mutableState.value = MacUpdateSchedulingState(MacUpdateSchedulingAvailability.ONLINE,
            attempt = checkNotNull(old.attempt).ending(outcome), tooLate = value)
        old.observation?.close()
        if (old.tooLate !== value) old.tooLate?.close()
    }

    private fun failure(scheduling: Boolean) = synchronized(monitor) {
        if (!closed) {
            val old = mutableState.value
            val outcome = if (submitted) MacUpdateSchedulingOutcome.UNCERTAIN else MacUpdateSchedulingOutcome.FAILED
            mutableState.value = MacUpdateSchedulingState(MacUpdateSchedulingAvailability.OFFLINE, old.observation,
                if (!definitive && scheduling && startedAttempt) old.attempt?.ending(outcome) else old.attempt, old.tooLate)
        }
    }

    override fun close() {
        val owned = synchronized(monitor) {
            if (closed) return
            closed = true
            mutableState.value.observation?.close()
            mutableState.value.tooLate?.close()
            mutableState.value = MacUpdateSchedulingState(MacUpdateSchedulingAvailability.CLOSED)
            Triple(job, wire, signer)
        }
        owned.first?.cancel()
        try { owned.second?.close() } finally { owned.third?.close() }
        check(!synchronized(monitor) { cleanupFailed })
    }

    /** A replacement must wait for the entire operation job, including its non-cancellable transport cleanup. */
    internal fun retirementSettled(): Boolean = synchronized(monitor) {
        check(closed && !cleanupFailed)
        job?.isCompleted != false && wire == null && signer == null
    }

    override fun toString() = "MacUpdateSchedulingConnection(redacted)"
}

/** The application scope owns the operation. Cancelling a screen waiter cannot replay or cancel its control. */
internal fun applicationMacUpdateScheduling(scope: CoroutineScope, connection: MacUpdateSchedulingConnection,
    expected: PhoneUpdateSchedulingStatus, action: UpdateSchedulingAction): Deferred<Boolean> =
    scope.async { connection.schedule(expected, action) }
