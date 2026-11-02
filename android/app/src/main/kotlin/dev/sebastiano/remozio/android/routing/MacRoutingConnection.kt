package dev.sebastiano.remozio.android.routing

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.PhoneRoutingChallenge
import dev.remozio.phone.transport.PhoneRoutingResult
import dev.remozio.protocol.PhoneRoutingFailure
import dev.remozio.protocol.RoutingStatusMode
import dev.remozio.protocol.RoutingStatusOutcome
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex

internal enum class MacRoutingAvailability { UNKNOWN, ONLINE, OFFLINE, INCOMPATIBLE, CLOSED }
internal enum class MacRoutingAction { IDLE, SETTING_AWAY, ACKNOWLEDGED, CONFLICT, FAILED, UNCERTAIN }
internal class MacRoutingStatus(val availability: MacRoutingAvailability,
                                val observation: PhoneRoutingResult.Verified? = null,
                                val action: MacRoutingAction = MacRoutingAction.IDLE) {
    override fun toString() = "MacRoutingStatus(redacted)"
}
internal interface RoutingDecisionSigner : AutoCloseable { fun sign(challenge: PhoneRoutingChallenge): ByteArray }

/** One enrollment incarnation. The registry checks the archive; this owner fences retirement and all publication. */
internal class MacRoutingConnection(
    val record: StoredPhoneEnrollment,
    private val open: suspend (CoroutineScope, StoredPhoneEnrollment) -> RoutingWire,
    private val loadSigner: (StoredPhoneEnrollment) -> RoutingDecisionSigner,
    private val current: suspend () -> Boolean,
    private val freshnessMillis: () -> Long,
    private val timeoutMillis: () -> Long,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : AutoCloseable {
    init { require(record.phase == EnrollmentPhase.ACTIVE) }
    private val operation = Mutex()
    private val monitor = Any()
    private var closed = false
    private var cleanupFailed = false
    private class RoutingResourcesUnsettled : IllegalStateException("Routing resources unavailable")
    private var wire: RoutingWire? = null
    private var signer: RoutingDecisionSigner? = null
    private var job: Job? = null
    private val mutableState = MutableStateFlow(MacRoutingStatus(MacRoutingAvailability.UNKNOWN))
    val state = mutableState.asStateFlow()

    /** A recent signed sample can become last known without another packet. It cannot prove continuous connectivity. */
    fun snapshot(): MacRoutingStatus = synchronized(monitor) {
        val value = mutableState.value
        if (value.availability == MacRoutingAvailability.ONLINE && value.observation?.isFresh(freshnessMillis()) != true)
            MacRoutingStatus(MacRoutingAvailability.OFFLINE, value.observation, value.action)
        else value
    }
    fun canSetAway(): Boolean = snapshot().let {
        it.availability == MacRoutingAvailability.ONLINE && it.action != MacRoutingAction.SETTING_AWAY &&
            it.observation?.response?.state?.mode != RoutingStatusMode.AWAY
    }

    /** A busy operation stays owned by its caller. Periodic status checks never queue behind an Away operation. */
    suspend fun refresh(): Boolean = perform(away = false) {
        exchange(accept = { result ->
            publish(result, mutableState.value.action.takeUnless { it == MacRoutingAction.SETTING_AWAY } ?: MacRoutingAction.IDLE)
        }) { it.status() }
    }

    /** Call only for the user's explicit current choice. A conflict never retries with a newer revision. */
    suspend fun setAway(): Boolean = perform(away = true) {
        if (!canSetAway()) throw RoutingNotCurrent()
        val expected = checkNotNull(snapshot().observation).response.state.revision
        setAction(MacRoutingAction.SETTING_AWAY)
        val prepared = exchange { it.challenge(expected) }
        if (prepared !is PhoneRoutingResult.Verified || prepared.response.outcome == RoutingStatusOutcome.CONFLICT) {
            publish(prepared, if (prepared is PhoneRoutingResult.Verified) MacRoutingAction.CONFLICT else MacRoutingAction.FAILED)
            return@perform
        }
        val challenge = checkNotNull(prepared.challenge)
        checkCurrent()
        val candidate = loadSigner(record)
        try {
            synchronized(monitor) { check(!closed); signer = candidate }
            val signature = candidate.sign(challenge)
            checkCurrent()
            // Acknowledgment can be lost after Root commits. Never replay this application operation.
            exchange(accept = { result ->
                val action = when {
                    result !is PhoneRoutingResult.Verified -> MacRoutingAction.UNCERTAIN
                    result.response.outcome == RoutingStatusOutcome.APPLIED -> MacRoutingAction.ACKNOWLEDGED
                    else -> MacRoutingAction.CONFLICT
                }
                publish(result, action)
                definitive = result is PhoneRoutingResult.Verified
            }) { submitted = true; it.apply(challenge, signature) }
        } finally {
            try {
                candidate.close()
                synchronized(monitor) { if (signer === candidate) signer = null }
            } catch (failure: Exception) {
                synchronized(monitor) { cleanupFailed = true }
                throw failure
            }
        }
    }
    private var submitted = false // Access stays under operation; retirement never clears this evidence.
    private var definitive = false
    private class RoutingNotCurrent : IllegalStateException()
    private suspend fun perform(away: Boolean, body: suspend CoroutineScope.() -> Unit): Boolean = withContext(dispatcher) {
        currentCoroutineContext().ensureActive()
        if (!operation.tryLock()) return@withContext false
        try {
            coroutineScope {
                synchronized(monitor) { check(!closed && !cleanupFailed); job = coroutineContext.job; submitted = false; definitive = false }
                try {
                    val timeout = timeoutMillis(); require(timeout in 1..60_000)
                    withTimeout(timeout) { checkCurrent(); body() }
                    true
                } catch (_: RoutingNotCurrent) { false }
                catch (_: TimeoutCancellationException) {
                    failure(away)
                    currentCoroutineContext().ensureActive()
                    false
                }
                catch (cancelled: CancellationException) {
                    failure(away); throw cancelled
                } catch (_: Exception) { failure(away); false }
                finally { synchronized(monitor) { job = null } }
            }
        } finally { operation.unlock() }
    }
    private suspend fun CoroutineScope.exchange(accept: (PhoneRoutingResult) -> Unit = {},
                                                body: suspend (RoutingWire) -> PhoneRoutingResult): PhoneRoutingResult {
        checkCurrent()
        val candidate = open(this, record)
        try {
            synchronized(monitor) { check(!closed); wire = candidate }
            checkCurrent()
            val result = body(candidate)
            checkCurrent()
            if (result is PhoneRoutingResult.Verified) check(result.matchesEnrollment(record) && result.isFresh(freshnessMillis()))
            accept(result)
            return result
        } finally {
            try {
                withContext(NonCancellable) { candidate.closeAndJoin() }
                synchronized(monitor) { if (wire === candidate) wire = null }
            } catch (failure: Exception) {
                synchronized(monitor) { cleanupFailed = true }
                throw failure
            }
        }
    }
    private suspend fun checkCurrent() {
        currentCoroutineContext().ensureActive()
        synchronized(monitor) { check(!closed && !cleanupFailed) }
        check(current())
        currentCoroutineContext().ensureActive()
        synchronized(monitor) { check(!closed && !cleanupFailed) }
    }
    private fun setAction(action: MacRoutingAction) = synchronized(monitor) {
        check(!closed)
        val old = mutableState.value
        mutableState.value = MacRoutingStatus(old.availability, old.observation, action)
    }
    private fun publish(result: PhoneRoutingResult, action: MacRoutingAction) = synchronized(monitor) {
        check(!closed)
        mutableState.value = when (result) {
            is PhoneRoutingResult.Verified -> MacRoutingStatus(MacRoutingAvailability.ONLINE, result, action)
            is PhoneRoutingResult.Failure -> MacRoutingStatus(if (result.reason == PhoneRoutingFailure.INCOMPATIBLE)
                MacRoutingAvailability.INCOMPATIBLE else MacRoutingAvailability.OFFLINE, mutableState.value.observation, action)
        }
    }
    private fun failure(away: Boolean) = synchronized(monitor) {
        if (!closed) mutableState.value = MacRoutingStatus(MacRoutingAvailability.OFFLINE, mutableState.value.observation,
            if (definitive) mutableState.value.action else if (submitted) MacRoutingAction.UNCERTAIN
            else if (away) MacRoutingAction.FAILED else mutableState.value.action)
    }
    /** Foreground loss turns a retained sample into last known. It does not cancel an already explicit action. */
    fun backgrounded() = synchronized(monitor) {
        if (!closed) mutableState.value = MacRoutingStatus(MacRoutingAvailability.OFFLINE, mutableState.value.observation, mutableState.value.action)
    }
    override fun close() {
        val owned = synchronized(monitor) {
            if (closed) return
            closed = true
            mutableState.value = MacRoutingStatus(MacRoutingAvailability.CLOSED)
            Triple(job, wire, signer)
        }
        owned.first?.cancel()
        try { owned.second?.close() } finally { owned.third?.close() }
        if (synchronized(monitor) { cleanupFailed }) throw RoutingResourcesUnsettled()
    }
    override fun toString() = "MacRoutingConnection(redacted)"
}
