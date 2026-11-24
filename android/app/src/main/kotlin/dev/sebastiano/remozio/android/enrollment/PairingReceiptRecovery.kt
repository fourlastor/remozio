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
    private val openRePair: (suspend (CoroutineScope, PreparedPairingAccess) -> RePairRecoveryWire)? = null,
    private val clock: TimeSource = TimeSource.Monotonic,
) {
    suspend fun recover(recordID: CborValue.Bytes): Boolean = withContext(dispatcher) {
        if (store.hasActivatedRePair(recordID)) return@withContext true
        coroutineScope {
            val access = withContext(NonCancellable) { store.recoverable(recordID) }
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
                if (proof == null) false else withContext(NonCancellable) {
                    store.activate(recordID, CborValue.Bytes(proof), expected = access)
                    true
                }
            } finally {
                withContext(NonCancellable) {
                    try { wire?.closeAndJoin() }
                    finally { store.release(recordID, access.lease) }
                }
            }
        }
    }

    private suspend fun recoverRePair(parent: CoroutineScope, access: PreparedPairingAccess): Boolean {
        val open = openRePair ?: return false
        val transcript = checkNotNull(access.record.pairing).transcript
        val started = clock.markNow()
        val caller = currentCoroutineContext().job
        for (attempt in 0 until 3) {
            if (attempt > 0) {
                val wait = attempt * 1_000L
                if (30_000L - started.elapsedNow().inWholeMilliseconds <= wait) return false
                delay(wait)
            }
            caller.ensureActive()
            check(access.lease.isCurrent())
            val remaining = 30_000L - started.elapsedNow().inWholeMilliseconds
            if (remaining <= 0) return false
            var wire: RePairRecoveryWire? = null
            val reply = try {
                withTimeoutOrNull(minOf(remaining, 8_000L)) {
                    wire = open(parent, access)
                    check(access.lease.isCurrent())
                    checkNotNull(wire).lookup()
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            } finally {
                withContext(NonCancellable) { wire?.closeAndJoin() }
            }
            caller.ensureActive()
            check(access.lease.isCurrent())
            when (reply) {
                is PairingRecoveryFrame.Committed -> {
                    val signature = reply.signature.copyBytes()
                    if (transcript.verify(signature, transcript.macAuthorityKey.copyBytes(), PairingProofPurpose.MAC_COMMIT)) {
                        withContext(NonCancellable) { store.activate(access.record.enrollment.recordID, reply.signature, access) }
                        return true
                    }
                }
                is PairingRecoveryFrame.Expired -> {
                    if (reply.receipt.verify(transcript)) {
                        withContext(NonCancellable) { store.retireExpiredRePair(access, reply.receipt) { caller.ensureActive() } }
                        return true
                    }
                }
                null, PairingRecoveryFrame.Refused -> Unit
            }
        }
        return false
    }
}

/** Re-read durable state even when cancellation or a failed result handoff hides a completed activation. */
internal suspend fun PairingReceiptRecovery.checkAndReconcile(recordID: CborValue.Bytes, refresh: () -> Unit): Boolean =
    try { recover(recordID) } finally { refresh() }
