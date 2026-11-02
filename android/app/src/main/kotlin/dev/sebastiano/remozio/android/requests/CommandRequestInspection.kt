package dev.sebastiano.remozio.android.requests

import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.CommandRequestSnapshot
import dev.remozio.phone.requests.ElapsedInstant

import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import dev.remozio.protocol.RequestPhase
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.produceState
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Sessions and this epoch live only in this process; elapsedRealtime includes deep sleep. */
internal object RequestElapsedClock {
    fun now() = ElapsedInstant(0, SystemClock.elapsedRealtime().toULong())
}

/** The caller owns the session and supplies trusted display names and optional enrollment-bound approval delivery. */
@Composable
internal fun CommandRequestInspection(
    session: CommandRequestSession,
    macName: String,
    accountName: String,
    onDismiss: () -> Unit,
    approval: CommandApprovalContext? = null,
) {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    key(session, lifecycle) {
        val snapshot by produceState<CommandRequestSnapshot?>(null, session, lifecycle) {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                try {
                    launch {
                        combine(session.revisions, session.closed) { _, _ -> session.snapshot(RequestElapsedClock.now()) }
                            .collect { value = it }
                    }
                    while (isActive) {
                        value = session.snapshot(RequestElapsedClock.now())
                        delay(1000)
                    }
                } finally {
                    // Stop retaining a UI capture while the host is not visible.
                    value = null
                }
            }
        }
        val approvalState = approval?.let { context ->
            remember(session, context.record, context.limits) { CommandApprovalViewState() }.also { owner ->
                DisposableEffect(owner) { onDispose { owner.clear() } }
                val phase = snapshot?.status?.status?.phase
                LaunchedEffect(owner, phase) {
                    if (phase != null && phase !in setOf(RequestPhase.QUEUED, RequestPhase.PRESENTED)) owner.clear()
                }
            }
        }
        snapshot?.let {
            if (it.closed) {
                LaunchedEffect(session) { onDismiss() }
                return@let
            }
            CommandInspection(it.capture, macName, accountName, onDismiss, status = it.status, requestKey = session,
                actions = approval?.let { context -> { CommandApprovalControls(session, context, it.status, checkNotNull(approvalState)) } })
        }
    }
}
