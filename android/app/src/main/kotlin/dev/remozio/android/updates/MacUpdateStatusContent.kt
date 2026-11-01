package dev.remozio.android.updates

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.UpdateSchedulingAction
import dev.remozio.protocol.UpdateSchedulingAdmissionState
import dev.remozio.protocol.UpdateSchedulingBlocker
import dev.remozio.protocol.UpdateSchedulingDesignation
import dev.remozio.protocol.UpdateSchedulingProgressPhase
import dev.remozio.protocol.UpdateSchedulingSecurityStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

private sealed interface MacUpdateOwners {
    data object Loading : MacUpdateOwners
    data object Unavailable : MacUpdateOwners
    class Ready(val progress: MacUpdateProgressConnection, val scheduling: MacUpdateSchedulingConnection) : MacUpdateOwners
}

/** The application owns both connections and every explicit scheduling operation. */
@Composable
internal fun MacUpdateStatusContent(recordID: CborValue.Bytes) {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var retry by remember(recordID) { mutableLongStateOf(0) }
    val owners by produceState<MacUpdateOwners>(MacUpdateOwners.Loading, app, recordID, lifecycle, retry) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            value = MacUpdateOwners.Loading
            try {
                val progress = app.macUpdateProgress.acquire(recordID)
                val scheduling = app.macUpdateScheduling.acquire(recordID)
                check(progress.record.sameConnectionAs(scheduling.record))
                value = MacUpdateOwners.Ready(progress, scheduling)
                awaitCancellation()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                value = MacUpdateOwners.Unavailable
                awaitCancellation()
            } finally {
                value = MacUpdateOwners.Loading
            }
        }
    }
    Text(stringResource(R.string.mac_update_heading), style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { heading() })
    val selected = owners as? MacUpdateOwners.Ready
    if (selected == null) {
        Text(stringResource(if (owners is MacUpdateOwners.Loading) R.string.mac_update_checking else R.string.mac_update_unavailable))
        TextButton(onClick = { retry++ }) { Text(stringResource(R.string.mac_update_refresh)) }
        return
    }
    key(selected.progress, selected.scheduling) {
        val progress = selected.progress
        val scheduling = selected.scheduling
        val publishedProgress by progress.state.collectAsStateWithLifecycle()
        val publishedScheduling by scheduling.state.collectAsStateWithLifecycle()
        val policy by app.routingWorkSettings.state.collectAsStateWithLifecycle()
        val scope = rememberCoroutineScope()
        var tick by remember { mutableLongStateOf(0) }
        var refreshing by remember { mutableStateOf(false) }
        var working by remember { mutableStateOf(false) }
        var incomplete by remember { mutableStateOf(false) }
        suspend fun refresh() {
            if (refreshing || working) return
            refreshing = true
            try {
                val progressRead = app.refreshMacUpdateProgress(progress)
                val schedulingRead = app.refreshMacUpdateScheduling(scheduling)
                progressRead.await()
                schedulingRead.await()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Each application owner retains its last verified observation.
            } finally {
                refreshing = false
            }
        }
        LaunchedEffect(progress, scheduling, lifecycle) {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                refresh()
                while (isActive) { tick++; delay(1000) }
            }
        }
        val progressSnapshot = remember(publishedProgress, tick) { safeProgressSnapshot(progress, publishedProgress) }
        val schedulingSnapshot = remember(publishedScheduling, tick) { safeSchedulingSnapshot(scheduling, publishedScheduling) }
        val displayedProgress = progressSnapshot.observation
        val displayedScheduling = schedulingSnapshot.observation
        val model = macUpdateDisplay(progress.record, progressSnapshot, schedulingSnapshot,
            policy.freshnessSeconds * 1000L,
            canSchedule = safeEligibility { displayedScheduling?.let(scheduling::canSchedule) == true },
            canOffer = { action -> safeEligibility { displayedProgress != null && displayedScheduling != null &&
                progress.canOffer(displayedProgress, displayedScheduling, action) } })
        MacUpdateStatusBody(model, refreshing, working, incomplete, onRefresh = {
            scope.launch { refresh() }
        }, onSchedule = { action ->
            if (!working && !refreshing && displayedProgress != null && displayedScheduling != null &&
                safeEligibility { scheduling.canSchedule(displayedScheduling) &&
                    progress.canOffer(displayedProgress, displayedScheduling, action) }) {
                working = true
                incomplete = false
                val operation = app.scheduleMacUpdate(scheduling, displayedScheduling, action)
                scope.launch {
                    try { incomplete = !operation.await() }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { incomplete = true }
                    finally { working = false }
                }
            } else incomplete = true
        })
    }
}

@Composable
internal fun MacUpdateStatusBody(model: MacUpdateDisplay, refreshing: Boolean, working: Boolean, incomplete: Boolean,
    onRefresh: () -> Unit, onSchedule: (UpdateSchedulingAction) -> Unit) {
    val frame = model.current ?: model.lastKnown
    if (frame == null) Text(stringResource(R.string.mac_update_no_current_status))
    else {
        Text(stringResource(if (model.current != null) R.string.mac_update_current_phase else R.string.mac_update_last_known_phase,
            stringResource(phaseLabel(frame.phase))), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        if (model.current == null) Text(stringResource(R.string.mac_update_no_current_status))
        if (model.current != null) {
            Text(stringResource(when (frame.security) {
                UpdateSchedulingSecurityStatus.UNKNOWN -> R.string.mac_update_security_unknown
                UpdateSchedulingSecurityStatus.NOT_SECURITY -> R.string.mac_update_not_security
                UpdateSchedulingSecurityStatus.SECURITY -> R.string.mac_update_security
            }))
            Text(stringResource(when (frame.admission) {
                UpdateSchedulingAdmissionState.UNKNOWN -> R.string.mac_update_admission_unknown
                UpdateSchedulingAdmissionState.OPEN -> R.string.mac_update_admission_open
                UpdateSchedulingAdmissionState.CLOSED -> R.string.mac_update_admission_closed
            }))
            Text(stringResource(when (frame.designation) {
                UpdateSchedulingDesignation.THIS_ACCOUNT -> R.string.mac_update_owner_this_account
                UpdateSchedulingDesignation.OTHER_ACCOUNT -> R.string.mac_update_owner_other_account
                UpdateSchedulingDesignation.UNASSIGNED -> R.string.mac_update_owner_unassigned
                UpdateSchedulingDesignation.UNKNOWN -> R.string.mac_update_owner_unknown
            }))
            Text(if (model.readyAgeMilliseconds == null) stringResource(R.string.mac_update_ready_age_unknown)
                else stringResource(R.string.mac_update_ready_age_seconds, ageSeconds(model.readyAgeMilliseconds)))
            model.blockers.forEach { blocker ->
                if (blocker.kind == UpdateSchedulingBlocker.Kind.OTHER_ACCOUNTS) {
                    Text(stringResource(R.string.mac_update_blocker_other_accounts))
                } else {
                    Text(stringResource(blockerLabel(blocker.kind), checkNotNull(blocker.count).toString()))
                    val age = blocker.oldestAgeMilliseconds
                    Text(if (age == null) stringResource(R.string.mac_update_blocker_age_unknown)
                        else stringResource(R.string.mac_update_blocker_age_seconds, ageSeconds(age)),
                        style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
    model.sampleAgeMilliseconds?.let { age ->
        Text(stringResource(R.string.mac_update_checked_age_seconds, ageSeconds(age.toULong())),
            style = MaterialTheme.typography.bodySmall)
    }
    if (model.tooLate) Text(stringResource(if (model.current != null) R.string.mac_update_too_late
        else R.string.mac_update_last_known_too_late),
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    val attempt = if (incomplete && !model.tooLate && model.attempt?.outcome != MacUpdateSchedulingOutcome.UNCERTAIN &&
        model.attempt?.outcome != MacUpdateSchedulingOutcome.SUBMITTING) R.string.mac_update_refresh_required
    else when (model.attempt?.outcome) {
        MacUpdateSchedulingOutcome.SUBMITTING -> R.string.mac_update_submitting
        MacUpdateSchedulingOutcome.ACKNOWLEDGED -> R.string.mac_update_acknowledged
        MacUpdateSchedulingOutcome.UNCERTAIN -> R.string.mac_update_uncertain
        MacUpdateSchedulingOutcome.FAILED -> R.string.mac_update_not_confirmed
        null -> null
    }
    attempt?.let { Text(stringResource(it), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
    if (model.canInstall) Text(stringResource(R.string.mac_update_drain_effect))
    else if (model.current?.phase == UpdateSchedulingProgressPhase.DRAINING &&
        model.current.admission == UpdateSchedulingAdmissionState.CLOSED) {
        Text(stringResource(R.string.mac_update_drain_active))
    }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (model.canInstall) TextButton(enabled = !working && !refreshing,
            onClick = { onSchedule(UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES) }) {
            Text(stringResource(R.string.mac_update_install_when_idle))
        }
        if (model.canDefer) TextButton(enabled = !working && !refreshing,
            onClick = { onSchedule(UpdateSchedulingAction.DEFER_UPDATE) }) { Text(stringResource(R.string.mac_update_defer)) }
        if (model.canCancelDrain) TextButton(enabled = !working && !refreshing,
            onClick = { onSchedule(UpdateSchedulingAction.CANCEL_DRAIN) }) { Text(stringResource(R.string.mac_update_cancel_drain)) }
        TextButton(enabled = !working && !refreshing, onClick = onRefresh) {
            Text(stringResource(if (refreshing) R.string.mac_update_checking else R.string.mac_update_refresh))
        }
    }
}

private fun phaseLabel(phase: UpdateSchedulingProgressPhase) = when (phase) {
    UpdateSchedulingProgressPhase.UNKNOWN -> R.string.mac_update_phase_unknown
    UpdateSchedulingProgressPhase.READY -> R.string.mac_update_phase_ready
    UpdateSchedulingProgressPhase.DRAINING -> R.string.mac_update_phase_draining
    UpdateSchedulingProgressPhase.ACTIVATING -> R.string.mac_update_phase_activating
    UpdateSchedulingProgressPhase.CHECKING_RESTART -> R.string.mac_update_phase_checking_restart
    UpdateSchedulingProgressPhase.FINISHING -> R.string.mac_update_phase_finishing
    UpdateSchedulingProgressPhase.COMPLETED -> R.string.mac_update_phase_completed
    UpdateSchedulingProgressPhase.CANCELLED -> R.string.mac_update_phase_cancelled
}

private fun blockerLabel(kind: UpdateSchedulingBlocker.Kind) = when (kind) {
    UpdateSchedulingBlocker.Kind.PENDING_REQUESTS -> R.string.mac_update_blocker_requests
    UpdateSchedulingBlocker.Kind.ACTIVE_COMMANDS -> R.string.mac_update_blocker_commands
    UpdateSchedulingBlocker.Kind.LIVE_GUI_PERMITS -> R.string.mac_update_blocker_permits
    UpdateSchedulingBlocker.Kind.OTHER_ACCOUNTS -> R.string.mac_update_blocker_other_accounts
}

private fun ageSeconds(milliseconds: ULong): String =
    (milliseconds / 1000uL + if (milliseconds % 1000uL == 0uL) 0uL else 1uL).toString()

private inline fun safeEligibility(read: () -> Boolean): Boolean = try { read() }
catch (cancelled: CancellationException) { throw cancelled }
catch (_: Exception) { false }

private fun safeProgressSnapshot(owner: MacUpdateProgressConnection, published: MacUpdateProgressState) = try { owner.snapshot() }
catch (cancelled: CancellationException) { throw cancelled }
catch (_: Exception) { MacUpdateProgressState(MacUpdateProgressAvailability.OFFLINE, published.observation) }

private fun safeSchedulingSnapshot(owner: MacUpdateSchedulingConnection, published: MacUpdateSchedulingState) = try { owner.snapshot() }
catch (cancelled: CancellationException) { throw cancelled }
catch (_: Exception) {
    MacUpdateSchedulingState(MacUpdateSchedulingAvailability.OFFLINE, published.observation, published.attempt, published.tooLate)
}
