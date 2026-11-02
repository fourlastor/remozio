package dev.sebastiano.remozio.android.routing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioApplication
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.RoutingStatusDestination
import dev.remozio.protocol.RoutingStatusMode
import dev.remozio.protocol.RoutingStatusReason
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Observes the application owner. Navigation never starts another routing connection. */
@Composable
internal fun MacRoutingStatusContent(recordID: CborValue.Bytes) {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val foreground by app.foregroundRouting.state.collectAsStateWithLifecycle()
    val owner = (foreground as? ForegroundRoutingState.Ready)?.owners?.singleOrNull { it.recordID == recordID }
    val connection = owner?.let { selected -> selected.connection?.takeIf {
        val e = it.record.enrollment
        e.recordID == recordID && e.macID == selected.macID && e.accountID == selected.accountID
    } }
    if (connection == null) {
        Text(stringResource(if (foreground is ForegroundRoutingState.Loading || foreground is ForegroundRoutingState.Stopped)
            R.string.routing_checking else R.string.routing_unavailable), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.routing_no_current_state))
        TextButton(onClick = app.foregroundRouting::refresh) { Text(stringResource(R.string.routing_refresh)) }
        return
    }
    key(connection) {
        val published by connection.state.collectAsStateWithLifecycle()
        val policy by app.routingWorkSettings.state.collectAsStateWithLifecycle()
        val lifecycle = LocalLifecycleOwner.current.lifecycle
        var tick by remember { mutableLongStateOf(0) }
        var working by remember { mutableStateOf(false) }
        var refreshing by remember { mutableStateOf(false) }
        var incomplete by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(connection, lifecycle) {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (isActive) { tick++; delay(1000) }
            }
        }
        val model = remember(published, policy, tick) {
            routingDisplay(connection.snapshot(), policy.freshnessSeconds * 1000L, connection.canSetAway())
        }
        RoutingStatusContent(model, working, refreshing, incomplete, onSetAway = {
            if (!working && !refreshing && connection.canSetAway()) {
                working = true; incomplete = false
                // Application ownership lets an explicit operation finish after this screen leaves composition.
                val operation = app.setRoutingAway(connection)
                scope.launch {
                    try { incomplete = !operation.await() }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { incomplete = true }
                    finally { working = false }
                }
            }
        }, onRefresh = {
            if (!working && !refreshing) {
                refreshing = true
                val operation = app.refreshRouting(connection)
                scope.launch {
                    try { operation.await() }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { /* The owner keeps the last-known observation. */ }
                    finally { refreshing = false }
                }
            }
        })
    }
}

@Composable
internal fun RoutingStatusContent(model: MacRoutingDisplay, working: Boolean, refreshing: Boolean, incomplete: Boolean,
                                  onSetAway: () -> Unit, onRefresh: () -> Unit) {
    Text(stringResource(when (model.availability) {
        MacRoutingAvailability.UNKNOWN -> R.string.routing_checking
        MacRoutingAvailability.ONLINE -> R.string.routing_recently_reachable
        MacRoutingAvailability.OFFLINE -> R.string.routing_offline
        MacRoutingAvailability.INCOMPATIBLE -> R.string.routing_incompatible
        MacRoutingAvailability.CLOSED -> R.string.routing_unavailable
    }), style = MaterialTheme.typography.titleMedium)
    model.currentMode?.let { Text(stringResource(R.string.routing_current_mode, stringResource(modeLabel(it))),
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
    model.lastKnownMode?.let { Text(stringResource(R.string.routing_last_known_mode, stringResource(modeLabel(it)))) }
    model.destination?.let { Text(stringResource(if (it == RoutingStatusDestination.PHONES) R.string.routing_to_phones else R.string.routing_to_mac)) }
    model.reason?.let { Text(stringResource(reasonLabel(it)), style = MaterialTheme.typography.bodyMedium) }
    if (model.detectionLimited) Text(stringResource(R.string.routing_detection_limited))
    model.sampleAgeMilliseconds?.let { age ->
        val seconds = age / 1000 + if (age % 1000 == 0L) 0 else 1
        Text(if (age < 1000) stringResource(R.string.routing_just_checked)
            else pluralStringResource(R.plurals.routing_verified_age, seconds.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), seconds),
            style = MaterialTheme.typography.bodySmall)
    }
    if (model.currentMode == null) Text(stringResource(R.string.routing_no_current_state))
    val action = when {
        working || model.action == MacRoutingAction.SETTING_AWAY -> R.string.routing_setting_away
        model.action == MacRoutingAction.UNCERTAIN -> R.string.routing_away_unknown
        model.action == MacRoutingAction.CONFLICT -> R.string.routing_away_conflict
        model.action == MacRoutingAction.FAILED -> R.string.routing_away_failed
        incomplete -> R.string.routing_away_incomplete
        model.action == MacRoutingAction.ACKNOWLEDGED -> R.string.routing_away_acknowledged
        else -> null
    }
    action?.let { Text(stringResource(it), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(enabled = model.canSetAway && !working && !refreshing, onClick = onSetAway) { Text(stringResource(R.string.routing_set_away)) }
        TextButton(enabled = !working && !refreshing, onClick = onRefresh) {
            Text(stringResource(if (refreshing) R.string.routing_checking else R.string.routing_refresh))
        }
    }
}

private fun modeLabel(mode: RoutingStatusMode) = when (mode) {
    RoutingStatusMode.AUTOMATIC -> R.string.routing_mode_automatic
    RoutingStatusMode.PRESENT -> R.string.routing_mode_present
    RoutingStatusMode.AWAY -> R.string.routing_mode_away
}
private fun reasonLabel(reason: RoutingStatusReason) = when (reason) {
    RoutingStatusReason.MANUAL_PRESENT -> R.string.routing_reason_present
    RoutingStatusReason.MANUAL_AWAY -> R.string.routing_reason_away
    RoutingStatusReason.REMOTE_DESKTOP -> R.string.routing_reason_remote
    RoutingStatusReason.LOCKED -> R.string.routing_reason_locked
    RoutingStatusReason.DISPLAYS_OFF -> R.string.routing_reason_displays_off
    RoutingStatusReason.DISPLAYS_DARK -> R.string.routing_reason_displays_dark
    RoutingStatusReason.IDLE -> R.string.routing_reason_idle
    RoutingStatusReason.ACTIVE -> R.string.routing_reason_active
    RoutingStatusReason.DETECTOR_UNAVAILABLE -> R.string.routing_reason_unavailable
}
