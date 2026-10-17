package dev.remozio.android.requests

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.requests.*
import dev.remozio.protocol.*
import java.io.IOException
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class CommandConnectionState { DISCONNECTED, CONNECTING, CONNECTED, CLOSED }

internal interface CommandConnectionWire : AutoCloseable {
    suspend fun receive()
    suspend fun send(bytes: ByteArray)
}

/** One trusted enrollment incarnation. The setup owner must close it before changing or removing trust. */
internal class CommandConnection(
    val record: StoredPhoneEnrollment,
    val limits: RequestLimits,
    private val open: suspend (CoroutineScope, CommandRequestEnrollment) -> CommandConnectionWire,
    private val clock: () -> ElapsedInstant,
    maximumRequests: Int = 128,
    retired: RetiredCommandRequests? = null,
    memoryBudget: CommandMemoryBudget? = null,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val openSnapshot: (suspend (CoroutineScope, CommandRequestEnrollment) -> CommandConnectionWire)? = null,
) : AutoCloseable {
    private val inbox = CommandRequestInbox(1, maximumRequests, memoryBudget)
    private val enrollment: CommandRequestEnrollment
    private val monitor = Any()
    private val running = Mutex()
    private val sending = Mutex()
    private var closed = false
    private class Attempt(val foreground: Boolean, val job: Job) { var wire: CommandConnectionWire? = null }
    private var attempt: Attempt? = null
    private var foregroundWaiters = 0
    private val state = MutableStateFlow(CommandConnectionState.DISCONNECTED)
    val connectionState = state.asStateFlow()
    val requests get() = enrollment.requestSessions
    val capacityLimited get() = enrollment.capacityLimited

    init {
        require(record.phase == EnrollmentPhase.ACTIVE)
        val e = record.enrollment
        enrollment = inbox.add(e.macID.copyBytes(), e.accountID.copyBytes(), e.authorityPublicKey.copyBytes(), limits, retired)
    }

    /** Foreground demand cancels an active snapshot before waiting for its transport cleanup. */
    suspend fun run() {
        val preempt = synchronized(monitor) {
            check(!closed)
            foregroundWaiters++
            attempt?.takeIf { !it.foreground }?.let { it.job to it.wire }
        }
        try {
            preempt?.first?.cancel()
            try { preempt?.second?.close() } catch (_: Exception) { }
            running.withLock { runAttempt(foreground = true, open) }
        } finally { synchronized(monitor) { foregroundWaiters-- } }
    }

    /** Returns false when foreground work owns or awaits the connection. No decision wire is published. */
    suspend fun fetchSnapshot(timeoutMillis: Long = 30_000): Boolean {
        require(timeoutMillis in 1..60_000)
        currentCoroutineContext().ensureActive()
        val opener = checkNotNull(openSnapshot) { "Snapshot transport unavailable" }
        val acquired = synchronized(monitor) {
            check(!closed)
            foregroundWaiters == 0 && running.tryLock()
        }
        if (!acquired) return false
        try {
            withTimeout(timeoutMillis) { runAttempt(foreground = false, opener) }
            currentCoroutineContext().ensureActive()
            synchronized(monitor) { check(!closed) }
            return true
        } finally { running.unlock() }
    }

    private suspend fun runAttempt(foreground: Boolean,
                                   opener: suspend (CoroutineScope, CommandRequestEnrollment) -> CommandConnectionWire) = withContext(dispatcher) {
        coroutineScope {
            val owner = Attempt(foreground, checkNotNull(coroutineContext[Job]))
            var candidate: CommandConnectionWire? = null
            try {
                synchronized(monitor) {
                    check(!closed && (foreground || foregroundWaiters == 0))
                    check(attempt == null)
                    attempt = owner
                    if (foreground) state.value = CommandConnectionState.CONNECTING
                }
                candidate = opener(this, enrollment)
                ensureActive()
                synchronized(monitor) {
                    check(!closed && attempt === owner)
                    owner.wire = checkNotNull(candidate)
                    if (foreground) state.value = CommandConnectionState.CONNECTED
                }
                checkNotNull(candidate).receive()
                ensureActive()
                synchronized(monitor) { check(!closed && attempt === owner) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { throw IOException("Command connection unavailable") }
            finally {
                try { candidate?.close() }
                finally {
                    synchronized(monitor) {
                        if (attempt === owner) {
                            attempt = null
                            if (!closed && foreground) state.value = CommandConnectionState.DISCONNECTED
                        }
                    }
                }
            }
        }
    }

    fun approval(session: CommandRequestSession) = CommandApprovalContext(record, limits) { send(session, it) }

    /** Rechecks the retained request and enrolled signing role before writing on this incarnation. */
    internal suspend fun send(session: CommandRequestSession, message: ApprovalMessage) = withContext(dispatcher) {
        sending.withLock {
            val owner = synchronized(monitor) { check(!closed); checkNotNull(attempt?.takeIf { it.foreground }) }
            val active = synchronized(monitor) { check(!closed && attempt === owner); checkNotNull(owner.wire) }
            check(enrollment.sessions().any { it === session })
            val e = record.enrollment
            check(message.wireVersion == 1uL && message.type == ApprovalMessageType.DECISION)
            val body = message.body.copyBytes()
            val claim = DecisionPayload.decode(body, limits.body)
            val key = when (claim.action.choice) {
                ActionChoice.EXECUTE -> e.biometricKey.also { check(message.purpose == SigningPurpose.BIOMETRIC_AUTHORIZATION) }
                ActionChoice.DECLINE -> e.decisionKey.also { check(message.purpose == SigningPurpose.CANCELLATION) }
                else -> throw IOException("Unsupported command decision")
            }
            session.withPendingDecision(clock(), e.phoneID.copyBytes(), key.keyID.copyBytes(), claim.action) {
                check(it.encode(limits.body).contentEquals(body))
                check(ApprovalSignature.verify(message.signature.copyBytes(), key.publicKey.copyBytes(), 1u,
                    message.type, message.purpose, body, limits.body, limits.signing))
            }
            ensureActive()
            synchronized(monitor) { check(!closed && attempt === owner && owner.wire === active) }
            active.send(message.encode(limits.body.maxBytes))
            ensureActive()
            synchronized(monitor) { check(!closed && attempt === owner && owner.wire === active) }
        }
    }

    override fun close() {
        val resources = synchronized(monitor) {
            if (closed) return
            closed = true
            state.value = CommandConnectionState.CLOSED
            attempt.also { attempt = null }
        }
        resources?.job?.cancel()
        try { resources?.wire?.close() } finally { inbox.close() }
    }
}
