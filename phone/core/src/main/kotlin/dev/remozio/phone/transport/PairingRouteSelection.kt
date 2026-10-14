package dev.remozio.phone.transport

import java.io.IOException
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.take

/** Race at most eight hints under one discovery/authentication budget. No proposal is sent before route selection. */
suspend fun authenticatePairingRoutes(parent: CoroutineScope, direct: Flow<ApprovalCarrierRoute>,
    localKeys: Array<javax.net.ssl.KeyManager>, invitation: dev.remozio.protocol.PairingInvitation,
    proposal: dev.remozio.protocol.PairingPhoneProposal, timeoutMillis: Long,
): PairingSetupChannel = firstAuthenticatedPairingRoute(direct, timeoutMillis, { route ->
    val carrier = route.open(parent)
    try {
        currentCoroutineContext().ensureActive()
        PairingSetupChannel.authenticate(parent, carrier, localKeys, invitation, proposal)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { carrier.close(); carrier.awaitClosed() }
        throw failure
    }
}, { it.closeAndJoin() })

/** Own every opened candidate until transfer or joined cleanup, including cancellation at the winning boundary. */
internal suspend fun <R, T : Any> firstAuthenticatedPairingRoute(routes: Flow<R>, timeoutMillis: Long,
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
                    if (held.get() == null) launch {
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
            if (held.get() == null) ready.completeExceptionally(IOException("No authenticated pairing route"))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { ready.completeExceptionally(IOException("Pairing discovery unavailable")) }
    }
    try {
        withTimeout(timeoutMillis) { ready.await() }
        withContext(NonCancellable) { discovery.cancelAndJoin() }
        currentCoroutineContext().ensureActive()
        if (cleanupFailure.get() != null) throw IOException("Pairing candidate cleanup failed")
        val winner = checkNotNull(held.get())
        transferred = true
        winner
    } finally {
        withContext(NonCancellable) {
            discovery.cancelAndJoin()
            if (!transferred) held.getAndSet(null)?.let { release(it) }
        }
    }
}
