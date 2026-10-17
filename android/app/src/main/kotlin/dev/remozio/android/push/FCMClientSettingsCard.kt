package dev.remozio.android.push

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.remozio.android.RemozioApplication
import dev.remozio.android.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun FCMClientSettingsCard() {
    val context = LocalContext.current
    val app = context.applicationContext as RemozioApplication
    val owner = app.pushClient
    val status by owner.status.collectAsStateWithLifecycle()
    val delivery by app.pushDelivery.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Int?>(null) }
    val notifications = remember(app) { AndroidWakeNotifications(app, 60_000) }
    val import = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            busy = true
            try {
                val imported = withContext(Dispatchers.IO) {
                    val bytes = context.contentResolver.openInputStream(uri)?.use { it.readNBytes(FCMClientConfiguration.MAXIMUM_BYTES + 1) }
                        ?: return@withContext PushConfigurationResult.FAILED
                    currentCoroutineContext().ensureActive()
                    owner.import(bytes)
                }
                result = when (imported) {
                    PushConfigurationResult.IMPORTED -> R.string.fcm_imported
                    PushConfigurationResult.UNCHANGED -> R.string.fcm_unchanged
                    PushConfigurationResult.RESTART_REQUIRED -> R.string.fcm_restart_required
                    PushConfigurationResult.INVALID -> R.string.fcm_invalid_configuration
                    PushConfigurationResult.FAILED -> R.string.fcm_action_failed
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
              catch (_: Exception) { result = R.string.fcm_action_failed }
            finally { busy = false }
        }
    }
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.fcm_settings_title), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.fcm_settings_reason))
            Text(stringResource(R.string.fcm_client_package, app.packageName), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(status.label()), style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (status == PushClientStatus.INITIALIZING) CircularProgressIndicator()
            Text(stringResource(R.string.registration_lifecycle_hint))
            Button(enabled = !busy, onClick = {
                try { import.launch(arrayOf("application/json", "text/plain", "application/octet-stream")) }
                catch (_: RuntimeException) { result = R.string.fcm_action_failed }
            }) {
                Text(stringResource(R.string.fcm_import_configuration))
            }
            if (owner.configured()) {
                val enableLabel = stringResource(R.string.fcm_enable_client)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(enableLabel, modifier = Modifier.weight(1f))
                    Switch(modifier = Modifier.semantics { contentDescription = enableLabel },
                        checked = owner.enabled(), enabled = !busy, onCheckedChange = { enabled ->
                        scope.launch {
                            busy = true; result = null
                            try {
                                val success = withContext(Dispatchers.IO) {
                                    owner.setEnabled(enabled) && (enabled || notifications.cancelAll())
                                }
                                if (!success) result = if (enabled) R.string.fcm_action_failed else R.string.fcm_disable_failed
                            } finally { busy = false }
                        }
                    })
                }
                if (owner.enabled() && status in setOf(PushClientStatus.REGISTRATION_FAILED, PushClientStatus.UNAVAILABLE)) {
                    OutlinedButton(enabled = !busy, onClick = {
                        scope.launch { busy = true; try { withContext(Dispatchers.IO) { owner.retry() } } finally { busy = false } }
                    }) { Text(stringResource(R.string.fcm_retry)) }
                }
                TextButton(enabled = !busy, onClick = {
                    scope.launch {
                        busy = true
                        try { result = if (withContext(Dispatchers.IO) { notifications.cancelAll() }) R.string.fcm_alerts_cleared else R.string.fcm_clear_failed }
                        finally { busy = false }
                    }
                }) { Text(stringResource(R.string.fcm_clear_alerts)) }
            }
            delivery?.takeIf { it.generation == owner.generation() }?.let {
                Text(stringResource(it.status.label()), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
            result?.let { Text(stringResource(it), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
        }
    }
}

private fun PushClientStatus.label(): Int = when (this) {
    PushClientStatus.UNCONFIGURED -> R.string.fcm_unconfigured
    PushClientStatus.DISABLED -> R.string.fcm_disabled
    PushClientStatus.INITIALIZING -> R.string.fcm_initializing
    PushClientStatus.CLIENT_READY -> R.string.fcm_client_ready
    PushClientStatus.REGISTRATION_FAILED -> R.string.fcm_registration_failed
    PushClientStatus.RESTART_REQUIRED -> R.string.fcm_restart_required
    PushClientStatus.UNAVAILABLE -> R.string.fcm_unavailable
}
private fun PushDeliveryStatus.label(): Int = when (this) {
    PushDeliveryStatus.QUEUED -> R.string.fcm_delivery_queued
    PushDeliveryStatus.ALERT_REQUESTED -> R.string.fcm_delivery_alert_requested
    PushDeliveryStatus.PERMISSION_BLOCKED -> R.string.fcm_delivery_permission_blocked
    PushDeliveryStatus.CHANNEL_BLOCKED -> R.string.fcm_delivery_channel_blocked
    PushDeliveryStatus.UNAVAILABLE -> R.string.fcm_delivery_unavailable
    PushDeliveryStatus.CAPACITY_LIMIT -> R.string.fcm_delivery_capacity
    PushDeliveryStatus.IGNORED -> R.string.fcm_delivery_ignored
}
