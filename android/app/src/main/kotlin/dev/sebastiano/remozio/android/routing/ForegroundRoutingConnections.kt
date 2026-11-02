package dev.sebastiano.remozio.android.routing

import dev.remozio.protocol.CborValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal sealed interface ForegroundRoutingState {
    data object Stopped : ForegroundRoutingState
    data object Loading : ForegroundRoutingState
    data object Unavailable : ForegroundRoutingState
    class Ready(val owners: List<StoredRoutingOwner>) : ForegroundRoutingState
}

/** Navigation shares these jobs. A replacement foreground host waits for the previous host's cleanup. */
internal class ForegroundRoutingConnections(private val acquireActive: suspend () -> List<StoredRoutingOwner>,
                                            private val refreshMillis: () -> Long) {
    private class Running(val connection: MacRoutingConnection, val job: Job)
    private val running = Mutex()
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private val mutableState = MutableStateFlow<ForegroundRoutingState>(ForegroundRoutingState.Stopped)
    val state = mutableState.asStateFlow()

    /** Also retries completed connections. Healthy peers keep their current transport and requests. */
    fun refresh() { changes.trySend(Unit) }

    /** The root activity owns this call for its STARTED lifetime; individual screens must not run connections. */
    suspend fun runForeground() = running.withLock {
        supervisorScope {
            val peers = mutableMapOf<CborValue.Bytes, Running>()
            suspend fun retire(selected: Collection<Running>) {
                selected.forEach { it.job.cancel() }
                selected.map { it.job }.joinAll()
                selected.forEach { it.connection.backgrounded() }
            }
            mutableState.value = ForegroundRoutingState.Loading
            changes.trySend(Unit)
            try {
                for (signal in changes) {
                    val owners = try { acquireActive() }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) {
                        retire(peers.values.toList())
                        peers.clear()
                        mutableState.value = ForegroundRoutingState.Unavailable
                        continue
                    }
                    currentCoroutineContext().ensureActive()
                    val active = owners.associateBy { it.recordID }
                    val stale = peers.filter { (id, peer) -> active[id]?.connection !== peer.connection }
                    // Join old incarnations before any replacement can open a transport.
                    retire(stale.values)
                    stale.keys.forEach(peers::remove)
                    owners.forEach { owner ->
                        val connection = owner.connection ?: return@forEach
                        val retained = peers[owner.recordID]
                        if (retained?.job?.isCompleted == false) return@forEach
                        peers[owner.recordID] = Running(connection, launch {
                            try {
                                while (isActive) {
                                    connection.refresh()
                                    val interval = refreshMillis(); require(interval > 0)
                                    delay(interval)
                                }
                            } catch (cancelled: CancellationException) { throw cancelled }
                            catch (_: Exception) { connection.backgrounded() }
                        })
                    }
                    currentCoroutineContext().ensureActive()
                    mutableState.value = ForegroundRoutingState.Ready(owners)
                }
            } finally {
                withContext(NonCancellable) { retire(peers.values.toList()) }
                mutableState.value = ForegroundRoutingState.Stopped
            }
        }
    }
}
