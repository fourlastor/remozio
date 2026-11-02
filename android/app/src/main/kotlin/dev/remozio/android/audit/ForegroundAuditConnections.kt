package dev.remozio.android.audit

import dev.remozio.phone.audit.AuditSyncPhase
import dev.remozio.phone.audit.PhoneAuditSyncConnection
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import java.util.Collections
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal sealed interface ForegroundAuditPeerState {
    data object Loading : ForegroundAuditPeerState
    data object Unavailable : ForegroundAuditPeerState
    class Ready(val connection: PhoneAuditSyncConnection) : ForegroundAuditPeerState
}

/** Local loading and sync state only. Neither a cache nor a completed round proves current Mac presence. */
internal class ForegroundAuditPeer(val record: StoredPhoneEnrollment) {
    private val mutableState = MutableStateFlow<ForegroundAuditPeerState>(ForegroundAuditPeerState.Loading)
    val state = mutableState.asStateFlow()
    private val monitor = Any()
    private val requests = Channel<Boolean>(1)
    private var accepting = false
    private val mutableWorking = MutableStateFlow(true)
    val working = mutableWorking.asStateFlow()
    /** One explicit round at a time. Busy clicks never queue behind an active round. */
    fun request(resume: Boolean): Boolean = synchronized(monitor) {
        if (!accepting || mutableWorking.value) return@synchronized false
        if (!requests.trySend(resume).isSuccess) return@synchronized false
        mutableWorking.value = true
        true
    }
    internal fun enableRequests() = synchronized(monitor) { accepting = true; mutableWorking.value = false }
    internal fun roundFinished() = synchronized(monitor) { mutableWorking.value = false }
    internal suspend fun nextRequest(): Boolean? = requests.receiveCatching().getOrNull()
    internal fun retire() = synchronized(monitor) { accepting = false; requests.close() }
    internal fun publish(value: ForegroundAuditPeerState) { mutableState.value = value }
    override fun toString() = "ForegroundAuditPeer(redacted)"
}

internal sealed interface ForegroundAuditState {
    data object Stopped : ForegroundAuditState
    data object Loading : ForegroundAuditState
    data object Unavailable : ForegroundAuditState
    class Ready(peers: List<ForegroundAuditPeer>) : ForegroundAuditState {
        val peers: List<ForegroundAuditPeer> = Collections.unmodifiableList(peers.toList())
    }
}

/** One bounded round per active enrollment when history enters the foreground. No polling or automatic resume. */
internal class ForegroundAuditConnections(
    private val activeRecords: suspend () -> List<StoredPhoneEnrollment>,
    private val acquire: suspend (CborValue.Bytes) -> PhoneAuditSyncConnection,
) {
    private class Running(val peer: ForegroundAuditPeer, val job: Job)
    private val running = Mutex()
    private val changes = Channel<Unit>(Channel.CONFLATED)
    private val mutableState = MutableStateFlow<ForegroundAuditState>(ForegroundAuditState.Stopped)
    val state = mutableState.asStateFlow()

    /** Reconcile enrollment changes; retain healthy peers and their bounded round. */
    fun enrollmentsChanged() { changes.trySend(Unit) }

    /** The history host owns this call. A replacement waits for the previous host's joined stream cleanup. */
    suspend fun runForeground() = running.withLock {
        supervisorScope {
            val peers = mutableMapOf<CborValue.Bytes, Running>()
            suspend fun retire(selected: Collection<Running>) {
                selected.forEach { it.peer.retire(); it.job.cancel() }
                selected.map { it.job }.joinAll()
            }
            mutableState.value = ForegroundAuditState.Loading
            changes.trySend(Unit)
            try {
                for (signal in changes) {
                    val rows = try { activeRecords() }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) {
                        retire(peers.values.toList()); peers.clear()
                        mutableState.value = ForegroundAuditState.Unavailable
                        continue
                    }
                    currentCoroutineContext().ensureActive()
                    val active = rows.associateBy { it.enrollment.recordID }
                    check(active.size == rows.size)
                    val stale = peers.filter { (id, peer) -> active[id]?.sameConnectionAs(peer.peer.record) != true }
                    retire(stale.values)
                    stale.keys.forEach(peers::remove)
                    rows.forEach { record ->
                        val id = record.enrollment.recordID
                        if (peers[id]?.job?.isCompleted == false) return@forEach
                        val peer = ForegroundAuditPeer(record)
                        peers[id] = Running(peer, launch {
                            try {
                                val owner = acquire(id)
                                check(owner.record.sameConnectionAs(record))
                                currentCoroutineContext().ensureActive()
                                peer.publish(ForegroundAuditPeerState.Ready(owner))
                                // A response-budget pause requires an explicit user continuation.
                                if (owner.state.value.phase != AuditSyncPhase.PAUSED) owner.refresh()
                                check(owner.state.value.phase != AuditSyncPhase.CLOSED &&
                                    owner.state.value.failure != dev.remozio.phone.audit.AuditSyncFailure.STORAGE)
                                peer.enableRequests()
                                while (true) {
                                    val resume = peer.nextRequest() ?: break
                                    currentCoroutineContext().ensureActive()
                                    try { if (resume) owner.resume() else owner.refresh() }
                                    finally { peer.roundFinished() }
                                    check(owner.state.value.phase != AuditSyncPhase.CLOSED &&
                                        owner.state.value.failure != dev.remozio.phone.audit.AuditSyncFailure.STORAGE)
                                }
                            } catch (cancelled: CancellationException) { throw cancelled }
                            catch (_: Exception) { peer.publish(ForegroundAuditPeerState.Unavailable) }
                            finally { peer.retire(); peer.roundFinished() }
                        })
                    }
                    currentCoroutineContext().ensureActive()
                    mutableState.value = ForegroundAuditState.Ready(rows.map { peers.getValue(it.enrollment.recordID).peer })
                }
            } finally {
                withContext(NonCancellable) { retire(peers.values.toList()) }
                mutableState.value = ForegroundAuditState.Stopped
            }
        }
    }
}
