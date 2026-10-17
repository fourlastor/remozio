package dev.remozio.android.push

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.RemozioApplication
import dev.remozio.android.R
import dev.remozio.android.enrollment.MacInventoryState
import dev.remozio.protocol.PhonePushRecoveryPhase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun PushRegistrationStatusCard() {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val registrations = app.pushRegistrations
    val reports by registrations.status.collectAsStateWithLifecycle()
    val generation by app.pushClient.generationState.collectAsStateWithLifecycle()
    val revision by app.pushClient.tokenRevisionState.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var inventory by remember { mutableStateOf<MacInventoryState>(MacInventoryState.Loading) }
    var refresh by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(lifecycle, refresh) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) { inventory = app.macs.read() }
    }
    val observing = reports.values.any { it.result.root?.state?.phase == PhonePushRecoveryPhase.MAPPING_OBSERVED }
    val tick by produceState(0, observing, lifecycle) {
        if (observing) lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (isActive) { delay(250); value++ }
        }
    }
    val ready = inventory as? MacInventoryState.Ready
    val labels = remember(reports, generation, revision, ready, tick) {
        ready?.macs?.associate { mac -> mac.recordID to registrationStatusLabel(registrations.currentStatus(mac.recordID)) }.orEmpty()
    }
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.registration_status_title), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.registration_status_reason))
            when (val current = inventory) {
                MacInventoryState.Loading -> CircularProgressIndicator()
                MacInventoryState.Unavailable -> Text(stringResource(R.string.macs_unavailable))
                is MacInventoryState.Ready -> {
                    if (current.macs.isEmpty()) Text(stringResource(R.string.no_macs_paired))
                    current.macs.forEach { mac ->
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(mac.label, style = MaterialTheme.typography.titleMedium)
                            val label = when {
                                mac.setupIncomplete -> R.string.macs_setup_incomplete
                                generation == null || revision == null -> R.string.registration_provider_pending
                                else -> labels.getValue(mac.recordID)
                            }
                            Text(stringResource(label))
                        }
                    }
                }
            }
            OutlinedButton(enabled = !busy && generation != null && revision != null, onClick = {
                scope.launch {
                    busy = true
                    try {
                        val queued = withContext(Dispatchers.IO) { app.pushRegistrationWork.changed() }
                        message = if (queued) R.string.registration_retry_queued else R.string.fcm_action_failed
                    } finally { busy = false; refresh++ }
                }
            }) { Text(stringResource(R.string.registration_retry)) }
            TextButton(enabled = !busy, onClick = { refresh++ }) { Text(stringResource(R.string.notification_refresh)) }
            message?.let { Text(stringResource(it)) }
        }
    }
}
private fun registrationStatusLabel(result: PushRegistrationRun?): Int = when (result?.outcome) {
    null -> R.string.registration_pending
    PushRegistrationOutcome.ROOT_STATE -> when (result.root?.state?.phase) {
        PhonePushRecoveryPhase.MAPPING_OBSERVED -> R.string.registration_mapping_observed
        PhonePushRecoveryPhase.PROOF_COMMITTED -> R.string.registration_proof_committed
        else -> R.string.registration_waiting_challenge
    }
    PushRegistrationOutcome.WAITING_FOR_CHALLENGE -> R.string.registration_waiting_challenge
    PushRegistrationOutcome.RECOVERY_REQUIRED -> R.string.registration_recovery_required
    PushRegistrationOutcome.RETRY -> R.string.registration_retry_pending
    PushRegistrationOutcome.INCOMPATIBLE -> R.string.registration_incompatible
    PushRegistrationOutcome.OBSOLETE -> R.string.registration_pending
}
