package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PairingProofPurpose
import dev.remozio.protocol.PairingRecoveryFrame
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.job
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.TimeSource
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

internal interface RePairRecoveryWire {
    suspend fun lookup(): PairingRecoveryFrame.Reply
    suspend fun closeAndJoin()
}

internal interface PairingReceiptWire : AutoCloseable {
    suspend fun recover(): ByteArray?
    suspend fun closeAndJoin()
}

/** Owns a prepared-record lease until I/O has stopped. Recovery never submits another enrollment proof. */
internal class PairingReceiptRecovery(
    private val store: StoredPairingHost,
    private val open: suspend (CoroutineScope, StoredPhoneEnrollment) -> PairingReceiptWire,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val openRePair: (suspend (CoroutineScope, PreparedPairingAccess, Long) -> RePairRecoveryWire)? = null,
    private val clock: TimeSource = TimeSource.Monotonic,
    private val onSlowJoin: (Long) -> Unit = {},
) {
    suspend fun recover(recordID: CborValue.Bytes): PairingReceiptOutcome = withContext(dispatcher) {
        if (store.hasActivatedRePair(recordID)) return@withContext PairingReceiptOutcome.RESOLVED
        coroutineScope {
            val access = try {
                withContext(NonCancellable) { store.recoverable(recordID) }
            } catch (_: PairingRecoveryInProgress) {
                return@coroutineScope PairingReceiptOutcome.IN_PROGRESS
            }
            var wire: PairingReceiptWire? = null
            try {
                currentCoroutineContext().ensureActive()
                if (access.record.rePair != null) return@coroutineScope recoverRePair(this, access)
                val proof = withTimeout(30_000) {
                    check(access.lease.isCurrent())
                    wire = open(this@coroutineScope, access.record)
                    check(access.lease.isCurrent())
                    checkNotNull(wire).recover()
                }
                currentCoroutineContext().ensureActive()
                check(access.lease.isCurrent())
                if (proof == null) PairingReceiptOutcome.INCONCLUSIVE else withContext(NonCancellable) {
                    store.activate(recordID, CborValue.Bytes(proof), expected = access)
                    PairingReceiptOutcome.RESOLVED
                }
            } finally {
                withContext(NonCancellable) {
                    try { wire?.closeAndJoin() }
                    finally { store.release(recordID, access.lease) }
                }
            }
        }
    }

    private suspend fun recoverRePair(parent: CoroutineScope, access: PreparedPairingAccess): PairingReceiptOutcome {
        val open = openRePair ?: return PairingReceiptOutcome.INCONCLUSIVE
        val transcript = checkNotNull(access.record.pairing).transcript
        val started = clock.markNow()
        val caller = currentCoroutineContext().job
        for (attempt in 0 until 3) {
            if (attempt > 0) {
                val wait = attempt * 1_000L
                if (30_000L - started.elapsedNow().inWholeMilliseconds <= wait) return PairingReceiptOutcome.INCONCLUSIVE
                delay(wait)
            }
            caller.ensureActive()
            check(access.lease.isCurrent())
            val remaining = 30_000L - started.elapsedNow().inWholeMilliseconds
            if (remaining <= 0) return PairingReceiptOutcome.INCONCLUSIVE
            val budget = minOf(remaining, 8_000L)
            val attemptStarted = clock.markNow()
            var wire: RePairRecoveryWire? = null
            val reply = try {
                withTimeoutOrNull(budget) {
                    wire = open(parent, access, budget)
                    check(access.lease.isCurrent())
                    checkNotNull(wire).lookup()
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            } finally {
                val connected = wire
                if (connected != null) {
                    val joinStarted = clock.markNow()
                    try {
                        withContext(NonCancellable) { connected.closeAndJoin() }
                    } finally {
                        val joining = joinStarted.elapsedNow().inWholeMilliseconds
                        if (joining > 0 && attemptStarted.elapsedNow().inWholeMilliseconds > budget) onSlowJoin(joining)
                    }
                } else {
                    val overrun = attemptStarted.elapsedNow().inWholeMilliseconds - budget
                    if (overrun > 0) onSlowJoin(overrun)
                }
            }
            caller.ensureActive()
            check(access.lease.isCurrent())
            when (reply) {
                is PairingRecoveryFrame.Committed -> {
                    val signature = reply.signature.copyBytes()
                    if (transcript.verify(signature, transcript.macAuthorityKey.copyBytes(), PairingProofPurpose.MAC_COMMIT)) {
                        withContext(NonCancellable) { store.activate(access.record.enrollment.recordID, reply.signature, access) }
                        return PairingReceiptOutcome.RESOLVED
                    }
                }
                is PairingRecoveryFrame.Expired -> {
                    if (reply.receipt.verify(transcript)) {
                        withContext(NonCancellable) { store.retireExpiredRePair(access, reply.receipt) { caller.ensureActive() } }
                        return PairingReceiptOutcome.RESOLVED
                    }
                }
                null, PairingRecoveryFrame.Refused -> Unit
            }
        }
        return PairingReceiptOutcome.INCONCLUSIVE
    }
}

internal enum class PairingReceiptOutcome { RESOLVED, INCONCLUSIVE, IN_PROGRESS }

/** Re-read durable state even when cancellation or a failed result handoff hides a completed activation. */
internal suspend fun PairingReceiptRecovery.checkAndReconcile(
    recordID: CborValue.Bytes, refresh: () -> Unit,
): PairingReceiptOutcome =
    try { recover(recordID) } finally { refresh() }
