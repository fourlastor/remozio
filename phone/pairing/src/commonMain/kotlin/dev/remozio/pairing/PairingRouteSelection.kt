@file:OptIn(ExperimentalAtomicApi::class)

package dev.remozio.pairing

import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.take
import kotlinx.io.IOException

/** Own every opened candidate until transfer or joined cleanup, including cancellation at the winning boundary.
 * [open] must release everything it created when it throws or is cancelled. [release] runs for every candidate
 * that does not win, and for the winner if the caller is cancelled before the transfer. The caller owns the winner afterwards. */
suspend fun <R, T : Any> firstAuthenticatedPairingRoute(routes: Flow<R>, timeoutMillis: Long,
    open: suspend (R) -> T, release: suspend (T) -> Unit,
): T = coroutineScope {
    require(timeoutMillis in 1..10_000)
    val held = AtomicReference<T?>(null)
    val ready = CompletableDeferred<Unit>()
    val cleanupFailure = AtomicReference<Throwable?>(null)
    var transferred = false
    val discovery = launch {
        try {
            coroutineScope {
                routes.take(8).collect { route ->
                    if (held.load() == null) launch {
                        var candidate: T? = null
                        var ownedBySelector = false
                        try {
                            candidate = open(route)
                            currentCoroutineContext().ensureActive()
                            ownedBySelector = held.compareAndSet(null, candidate)
                            if (ownedBySelector) ready.complete(Unit)
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { }
                        finally {
                            if (!ownedBySelector) candidate?.let {
                                withContext(NonCancellable) {
                                    try { release(it) }
                                    catch (failure: Throwable) { cleanupFailure.compareAndSet(null, failure) }
                                }
                            }
                        }
                    }
                }
            }
            if (held.load() == null) ready.completeExceptionally(IOException("No authenticated pairing route"))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { ready.completeExceptionally(IOException("Pairing discovery unavailable")) }
    }
    try {
        withTimeout(timeoutMillis) { ready.await() }
        withContext(NonCancellable) { discovery.cancelAndJoin() }
        currentCoroutineContext().ensureActive()
        if (cleanupFailure.load() != null) throw IOException("Pairing candidate cleanup failed")
        val winner = checkNotNull(held.load())
        transferred = true
        winner
    } finally {
        withContext(NonCancellable) {
            discovery.cancelAndJoin()
            if (!transferred) held.exchange(null)?.let { release(it) }
        }
    }
}
