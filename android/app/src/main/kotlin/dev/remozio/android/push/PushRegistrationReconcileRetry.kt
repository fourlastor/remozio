package dev.remozio.android.push

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

/** One coalesced signal retries retained challenges without adding work beyond the queue limit. */
internal class PushRegistrationReconcileRetry {
    private val signals = Channel<Unit>(Channel.CONFLATED)

    fun enqueue(admit: () -> Boolean): Boolean {
        var queued = false
        try { return admit().also { queued = it } }
        finally { if (!queued) signals.trySend(Unit) }
    }

    /** Every collector starts with reconciliation; the encrypted journal survives a lost process signal. */
    suspend fun run(reconcile: suspend () -> Boolean) {
        while (currentCoroutineContext().isActive) {
            val complete = try { reconcile() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { false }
            if (complete) signals.receive() else delay(10_000)
        }
    }
}
