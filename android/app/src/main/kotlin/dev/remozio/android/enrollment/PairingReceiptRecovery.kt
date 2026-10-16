package dev.remozio.android.enrollment

import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

internal interface PairingReceiptWire : AutoCloseable {
    suspend fun recover(): ByteArray?
    suspend fun closeAndJoin()
}

/** Owns a prepared-record lease until I/O has stopped. Recovery never submits another enrollment proof. */
internal class PairingReceiptRecovery(
    private val store: StoredPairingHost,
    private val open: suspend (CoroutineScope, StoredPhoneEnrollment) -> PairingReceiptWire,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    suspend fun recover(recordID: CborValue.Bytes): Boolean = withContext(dispatcher) {
        coroutineScope {
            val access = withContext(NonCancellable) { store.recoverable(recordID) }
            var wire: PairingReceiptWire? = null
            try {
                currentCoroutineContext().ensureActive()
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
}

/** Re-read durable state even when cancellation or a failed result handoff hides a completed activation. */
internal suspend fun PairingReceiptRecovery.checkAndReconcile(recordID: CborValue.Bytes, refresh: () -> Unit): Boolean =
    try { recover(recordID) } finally { refresh() }
