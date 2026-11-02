package dev.remozio.android.audit

import dev.remozio.phone.audit.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborValue
import java.util.Collections
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.*

internal data class AuditSyncScope(val macID: CborValue.Bytes, val accountID: CborValue.Bytes, val authority: CborValue.Bytes)
internal sealed interface AuditSyncProgress {
    data object Loading : AuditSyncProgress
    data object Unavailable : AuditSyncProgress
    class Observed(val phase: AuditSyncPhase, val failure: AuditSyncFailure?, val completedAt: ElapsedInstant?,
                   val responseAt: ElapsedInstant?, val history: AuditEvidenceSnapshot?,
                   val localTimes: AuditLocalSyncTimes? = null) : AuditSyncProgress
}
internal class AuditSyncDisplay(val scope: AuditSyncScope, val progress: AuditSyncProgress, val working: Boolean,
                               val request: (resume: Boolean) -> Boolean = { false }) {
    override fun toString() = "AuditSyncDisplay(redacted)"
}
internal sealed interface AuditSyncDisplays {
    data object Loading : AuditSyncDisplays
    data object Unavailable : AuditSyncDisplays
    class Ready(entries: List<AuditSyncDisplay>) : AuditSyncDisplays {
        val entries = Collections.unmodifiableList(entries.toList())
    }
}

/** Display projections cannot merge independent Root keys or establish Mac presence. */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun ForegroundAuditConnections.displays(): Flow<AuditSyncDisplays> = state.flatMapLatest { current ->
    when (current) {
        ForegroundAuditState.Stopped, ForegroundAuditState.Loading -> flowOf(AuditSyncDisplays.Loading)
        ForegroundAuditState.Unavailable -> flowOf(AuditSyncDisplays.Unavailable)
        is ForegroundAuditState.Ready -> {
            val peers = current.peers.map { peer ->
                val e = peer.record.enrollment
                val key = AuditSyncScope(e.macID, e.accountID, e.authorityPublicKey)
                peer.state.flatMapLatest { value ->
                    when (value) {
                        ForegroundAuditPeerState.Loading -> flowOf(AuditSyncDisplay(key, AuditSyncProgress.Loading, true))
                        ForegroundAuditPeerState.Unavailable -> flowOf(AuditSyncDisplay(key, AuditSyncProgress.Unavailable, false))
                        is ForegroundAuditPeerState.Ready -> combine(value.connection.state, peer.working) { snapshot, working ->
                            AuditSyncDisplay(key, AuditSyncProgress.Observed(snapshot.phase, snapshot.failure,
                                snapshot.lastCompletedAt, snapshot.lastResponseAt, snapshot.history, snapshot.localTimes), working, peer::request)
                        }
                    }
                }
            }
            if (peers.isEmpty()) flowOf(AuditSyncDisplays.Ready(emptyList()))
            else combine(peers) { AuditSyncDisplays.Ready(it.toList()) }
        }
    }
}

/** Elapsed timestamps belong to the current process clock epoch. Never format them as wall-clock dates. */
internal fun auditSyncAgeMillis(now: ElapsedInstant?, then: ElapsedInstant?): ULong? {
    if (now == null || then == null || now.epoch != then.epoch || now.milliseconds < then.milliseconds) return null
    return now.milliseconds - then.milliseconds
}

/** A saved wall-clock date never becomes a current-process elapsed age or live authority. */
internal sealed interface AuditSyncTimestamp {
    data object Unknown : AuditSyncTimestamp
    data class ElapsedAge(val milliseconds: ULong) : AuditSyncTimestamp
    data class PhoneTime(val value: AuditLocalSyncTime) : AuditSyncTimestamp
}
internal fun auditSyncTimestamp(now: ElapsedInstant?, then: ElapsedInstant?, saved: AuditLocalSyncTime?): AuditSyncTimestamp =
    auditSyncAgeMillis(now, then)?.let(AuditSyncTimestamp::ElapsedAge)
        ?: saved?.let(AuditSyncTimestamp::PhoneTime) ?: AuditSyncTimestamp.Unknown
