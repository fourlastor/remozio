package dev.remozio.android.requests

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.RequestPhase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal class PendingCommandOpen(val serial: Long, val target: CommandNotificationTarget)
internal data class CommandNavigationState(
    val selected: ScopedCommandRequest? = null,
    val pending: PendingCommandOpen? = null,
    val inboxRequested: Boolean = false,
    val unavailable: Boolean = false,
    val showAllScopes: Boolean = false,
)

/** Notification taps cannot replace an open review or its biometric operation. No method sends a decision. */
internal class CommandInboxNavigation(private val clock: () -> ElapsedInstant = RequestElapsedClock::now) {
    private val mutableState = MutableStateFlow(CommandNavigationState())
    val state = mutableState.asStateFlow()
    private var serial = 0L
    @Synchronized fun request(target: CommandNotificationTarget?) {
        serial++
        mutableState.value = mutableState.value.copy(pending = target?.let { PendingCommandOpen(serial, it) }, inboxRequested = true, unavailable = false, showAllScopes = target == null)
    }
    @Synchronized fun show(request: ScopedCommandRequest) {
        if (mutableState.value.selected == null) mutableState.value = mutableState.value.copy(selected = request, unavailable = false)
    }
    @Synchronized fun dismiss() { mutableState.value = mutableState.value.copy(selected = null) }
    @Synchronized fun inboxShown() { mutableState.value = mutableState.value.copy(inboxRequested = false) }
    @Synchronized fun allScopesShown() { mutableState.value = mutableState.value.copy(showAllScopes = false) }
    @Synchronized fun cancelPending() { mutableState.value = mutableState.value.copy(pending = null, unavailable = false) }
    @Synchronized fun expire(serial: Long) {
        val current = mutableState.value
        if (current.selected == null && current.pending?.serial == serial) mutableState.value = current.copy(pending = null, unavailable = true)
    }
    @Synchronized fun synchronize(owners: List<StoredCommandOwner>, requests: List<ScopedCommandRequest>, ready: Boolean, canOpen: Boolean = true) {
        var current = mutableState.value
        if (current.selected?.session?.closed?.value == true) {
            current = current.copy(selected = null)
            mutableState.value = current
        }
        if (!ready) return
        if (current.selected?.isCurrent(owners) == false) current = current.copy(selected = null)
        val pending = current.pending
        if (current.selected == null && pending != null && canOpen) {
            val owner = owners.singleOrNull { pending.target.matchesOwner(it) }
            current = if (owner == null) current.copy(pending = null, unavailable = true)
            else {
                val request = requests.singleOrNull { it.isCurrent(owners) && pending.target.matches(it) }
                if (request == null) current else {
                    val snapshot = request.session.snapshot(clock())
                    val status = snapshot.status
                    when {
                        snapshot.closed || status != null && (status.status.phase !in setOf(RequestPhase.QUEUED, RequestPhase.PRESENTED) ||
                            status.timing.authorizationRemainingUpperBoundMs == 0uL) -> current.copy(pending = null, unavailable = true)
                        status == null -> current
                        else -> current.copy(selected = request, pending = null, unavailable = false)
                    }
                }
            }
        }
        mutableState.value = current
    }
}
