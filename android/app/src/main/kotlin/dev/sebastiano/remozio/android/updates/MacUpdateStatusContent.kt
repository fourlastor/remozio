package dev.sebastiano.remozio.android.updates

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import dev.sebastiano.remozio.android.CoarseElapsedText
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioApplication
import dev.sebastiano.remozio.android.coarseElapsedText
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

/** A short first load shows nothing, so a fast read does not flash a loading line. */
private const val LOADING_DELAY_MILLIS = 400L

/** The application owns both connections and every explicit scheduling operation. */
@Composable
internal fun MacUpdateStatusContent(recordID: CborValue.Bytes) {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var retry by remember(recordID) { mutableLongStateOf(0) }
    val owners by produceState<MacUpdateOwners>(MacUpdateOwners.Loading, app, recordID, lifecycle, retry) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            // The application keeps both owners across stops, so the last content stays while they are reacquired.
            if (value !is MacUpdateOwners.Ready) value = MacUpdateOwners.Loading
            try {
                val progress = app.macUpdateProgress.acquire(recordID)
                val scheduling = app.macUpdateScheduling.acquire(recordID)
                check(progress.record.sameConnectionAs(scheduling.record))
                val shown = value as? MacUpdateOwners.Ready
                if (shown?.progress !== progress || shown.scheduling !== scheduling) value = MacUpdateOwners.Ready(progress, scheduling)
                awaitCancellation()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                value = MacUpdateOwners.Unavailable
                awaitCancellation()
            }
        }
    }
    val selected = (owners as? MacUpdateOwners.Ready)?.takeIf { it.progress.record.enrollment.recordID == recordID }
    if (selected == null) {
        if (owners is MacUpdateOwners.Unavailable) MacUpdateUnavailable(onRetry = { retry++ }) else MacUpdateLoading()
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
        // Any read in flight blocks a choice, because a newer observation would invalidate it.
        var checking by remember { mutableStateOf(false) }
        // Only a read the user asked for changes the Refresh control.
        var userRefreshing by remember { mutableStateOf(false) }
        var working by remember { mutableStateOf(false) }
        var incomplete by remember { mutableStateOf(false) }
        suspend fun refresh(requested: Boolean) {
            if (checking || working) return
            checking = true
            userRefreshing = requested
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
                checking = false
                userRefreshing = false
            }
        }
        LaunchedEffect(progress, scheduling, lifecycle) {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                refresh(requested = false)
                // Eligibility follows freshness every second. Displayed ages change at most once a minute.
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
        MacUpdateStatusBody(model, checking, userRefreshing, working, incomplete, onRefresh = {
            scope.launch { refresh(requested = true) }
        }, onSchedule = { action ->
            if (!working && !checking && displayedProgress != null && displayedScheduling != null &&
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
internal fun MacUpdateLoading() {
    MacUpdateHeading()
    DelayedChecking()
}

@Composable
internal fun MacUpdateUnavailable(onRetry: () -> Unit) {
    MacUpdateHeading()
    Text(stringResource(R.string.mac_update_unavailable), style = leadStyle(), color = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    TextButton(onClick = onRetry, modifier = Modifier.offset(x = (-12).dp)) { Text(stringResource(R.string.mac_update_try_again)) }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun MacUpdateStatusBody(model: MacUpdateDisplay, checking: Boolean, userRefreshing: Boolean, working: Boolean,
    incomplete: Boolean, onRefresh: () -> Unit, onSchedule: (UpdateSchedulingAction) -> Unit, initiallyShowDetails: Boolean = false) {
    val idle = !working && !checking
    MacUpdateHeading {
        Box(Modifier.size(48.dp), contentAlignment = Alignment.Center) {
            if (userRefreshing) {
                val label = stringResource(R.string.mac_update_checking)
                CircularProgressIndicator(Modifier.size(20.dp).semantics { contentDescription = label }, strokeWidth = 2.dp)
            } else IconButton(onClick = onRefresh, enabled = idle) {
                Icon(painterResource(R.drawable.ic_refresh), contentDescription = stringResource(R.string.mac_update_refresh))
            }
        }
    }
    val current = model.current
    val frame = current ?: model.lastKnown
    if (frame == null) {
        if (checking) DelayedChecking() else Supporting(stringResource(R.string.mac_update_no_status))
    } else Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        if (frame.security == UpdateSchedulingSecurityStatus.SECURITY) SecurityLabel()
        val phase = stringResource(phaseLabel(frame.phase))
        Text(if (current != null) phase else stringResource(R.string.mac_update_last_known_phase, phase),
            style = leadStyle(), color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        when {
            current == null -> {
                Supporting(stringResource(R.string.mac_update_last_known_hint))
                model.sampleAgeMilliseconds?.let { Supporting(checkedAge(it)) }
            }
            current.phase == UpdateSchedulingProgressPhase.DRAINING &&
                current.admission == UpdateSchedulingAdmissionState.CLOSED -> Supporting(stringResource(R.string.mac_update_drain_active))
            current.phase == UpdateSchedulingProgressPhase.CANCELLED -> Supporting(stringResource(R.string.mac_update_cancelled_hint))
        }
        if (current != null) model.blockers.forEach { Text(blockerLabel(it), style = MaterialTheme.typography.bodyMedium) }
    }
    if (model.canInstall) Supporting(stringResource(R.string.mac_update_drain_effect))
    else if (model.canCancelDrain) Supporting(stringResource(R.string.mac_update_cancel_effect))
    if (model.canInstall || model.canDefer || model.canCancelDrain) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (model.canInstall) FilledTonalButton(enabled = idle,
                onClick = { onSchedule(UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES) }) {
                Text(stringResource(R.string.mac_update_install_when_idle))
            }
            if (model.canDefer) OutlinedButton(enabled = idle, onClick = { onSchedule(UpdateSchedulingAction.DEFER_UPDATE) }) {
                Text(stringResource(R.string.mac_update_defer))
            }
            if (model.canCancelDrain) OutlinedButton(enabled = idle, onClick = { onSchedule(UpdateSchedulingAction.CANCEL_DRAIN) }) {
                Text(stringResource(R.string.mac_update_cancel_drain))
            }
        }
    }
    // Results sit below the actions, so a message never pushes a button away from the finger.
    if (model.tooLate) Text(stringResource(if (current != null) R.string.mac_update_too_late else R.string.mac_update_last_known_too_late),
        style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    val outcome = model.attempt?.outcome
    val result = if (incomplete && !model.tooLate && outcome != MacUpdateSchedulingOutcome.UNCERTAIN &&
        outcome != MacUpdateSchedulingOutcome.SUBMITTING) R.string.mac_update_not_confirmed
    else when (outcome) {
        MacUpdateSchedulingOutcome.SUBMITTING -> R.string.mac_update_submitting
        MacUpdateSchedulingOutcome.ACKNOWLEDGED -> R.string.mac_update_acknowledged
        MacUpdateSchedulingOutcome.UNCERTAIN -> R.string.mac_update_uncertain
        // Too late already says why the choice did not apply.
        MacUpdateSchedulingOutcome.FAILED -> R.string.mac_update_not_confirmed.takeUnless { model.tooLate }
        null -> null
    }
    result?.let {
        Text(stringResource(it), style = MaterialTheme.typography.bodyMedium, color = if (it == R.string.mac_update_not_confirmed) MaterialTheme.colorScheme.error else Color.Unspecified,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    }
    if (current != null) {
        val details = buildList {
            when (current.designation) {
                UpdateSchedulingDesignation.THIS_ACCOUNT -> add(stringResource(R.string.mac_update_owner_this_account))
                UpdateSchedulingDesignation.OTHER_ACCOUNT -> add(stringResource(R.string.mac_update_owner_other_account))
                UpdateSchedulingDesignation.UNASSIGNED -> add(stringResource(R.string.mac_update_owner_unassigned))
                UpdateSchedulingDesignation.UNKNOWN -> Unit
            }
            when (current.admission) {
                UpdateSchedulingAdmissionState.OPEN -> add(stringResource(R.string.mac_update_admission_open))
                UpdateSchedulingAdmissionState.CLOSED -> add(stringResource(R.string.mac_update_admission_closed))
                UpdateSchedulingAdmissionState.UNKNOWN -> Unit
            }
            model.readyAgeMilliseconds?.let { add(coarseElapsedText(it, READY_AGE)) }
            model.blockers.mapNotNull { it.oldestAgeMilliseconds }.maxOrNull()?.let { add(coarseElapsedText(it, OLDEST_WORK_AGE)) }
            model.sampleAgeMilliseconds?.let { add(checkedAge(it)) }
        }
        if (details.isNotEmpty()) {
            var shown by rememberSaveable { mutableStateOf(initiallyShowDetails) }
            TextButton(onClick = { shown = !shown }, modifier = Modifier.offset(x = (-12).dp)) {
                Text(stringResource(if (shown) R.string.mac_update_details_hide else R.string.mac_update_details_show))
            }
            val motion = MaterialTheme.motionScheme
            AnimatedVisibility(shown, enter = expandVertically(motion.defaultSpatialSpec()) + fadeIn(motion.defaultEffectsSpec()),
                exit = shrinkVertically(motion.defaultSpatialSpec()) + fadeOut(motion.defaultEffectsSpec())) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) { details.forEach { Supporting(it) } }
            }
        }
    }
}

@Composable
private fun leadStyle() = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium)

@Composable
private fun MacUpdateHeading(action: @Composable () -> Unit = {}) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(stringResource(R.string.mac_update_heading), style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f).semantics { heading() })
        action()
    }
}

@Composable
private fun DelayedChecking() {
    var shown by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { delay(LOADING_DELAY_MILLIS); shown = true }
    // The line keeps its space while hidden, so the card does not grow when it appears.
    Supporting(stringResource(R.string.mac_update_checking),
        if (shown) Modifier.semantics { liveRegion = LiveRegionMode.Polite } else Modifier.alpha(0f).clearAndSetSemantics {})
}

@Composable
private fun Supporting(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = modifier)
}

@Composable
private fun SecurityLabel() {
    Surface(color = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.small) {
        Text(stringResource(R.string.mac_update_security), style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
    }
}

private val READY_AGE = CoarseElapsedText(R.string.mac_update_ready_under_minute, R.plurals.mac_update_ready_minutes,
    R.plurals.mac_update_ready_hours, R.plurals.mac_update_ready_days)
private val OLDEST_WORK_AGE = CoarseElapsedText(R.string.mac_update_oldest_work_under_minute,
    R.plurals.mac_update_oldest_work_minutes, R.plurals.mac_update_oldest_work_hours, R.plurals.mac_update_oldest_work_days)
private val CHECKED_AGE = CoarseElapsedText(R.string.mac_update_checked_now, R.plurals.mac_update_checked_minutes,
    R.plurals.mac_update_checked_hours, R.plurals.mac_update_checked_days)

@Composable
private fun checkedAge(milliseconds: Long): String = coarseElapsedText(milliseconds.coerceAtLeast(0).toULong(), CHECKED_AGE)

@Composable
private fun blockerLabel(blocker: MacUpdateBlockerDisplay): String {
    val count = blocker.count?.coerceAtMost(Int.MAX_VALUE.toULong())?.toInt()
    val plural = when (blocker.kind) {
        UpdateSchedulingBlocker.Kind.OTHER_ACCOUNTS -> null
        UpdateSchedulingBlocker.Kind.PENDING_REQUESTS -> R.plurals.mac_update_blocker_requests
        UpdateSchedulingBlocker.Kind.ACTIVE_COMMANDS -> R.plurals.mac_update_blocker_commands
        UpdateSchedulingBlocker.Kind.LIVE_GUI_PERMITS -> R.plurals.mac_update_blocker_permits
    }
    return if (plural == null || count == null) stringResource(R.string.mac_update_blocker_other_accounts)
    else pluralStringResource(plural, count, count)
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
