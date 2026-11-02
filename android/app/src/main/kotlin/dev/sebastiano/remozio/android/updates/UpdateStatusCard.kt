package dev.sebastiano.remozio.android.updates

import android.content.Intent
import android.provider.Settings
import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.input.KeyboardType
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun UpdateStatusCard() {
    val context = LocalContext.current
    val host = (context.applicationContext as RemozioApplication).updates
    val state by host.state.collectAsStateWithLifecycle()
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var resumed by remember { mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
    var openConfirmation by rememberSaveable { mutableStateOf(false) }
    var confirmationError by remember { mutableStateOf(false) }
    var showSettings by rememberSaveable { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        openConfirmation = true
        host.install()
    }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { resumed = true; host.onForeground() }
    LifecycleEventEffect(Lifecycle.Event.ON_PAUSE) { resumed = false; openConfirmation = false }
    LaunchedEffect(openConfirmation, state.confirmationAvailable, state.record?.nonce, resumed) {
        if (openConfirmation && state.confirmationAvailable && resumed) {
            val record = state.record ?: return@LaunchedEffect
            val binding = UpdateCallbackBinding(record.sessionId ?: return@LaunchedEffect, record.nonce)
            val action = withContext(Dispatchers.IO) {
                runCatching { UpdateConfirmationNotifications(context).existing(binding) }.getOrNull()
            }
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                openConfirmation = false
                confirmationError = runCatching { checkNotNull(action).send() }.isFailure
            }
        }
    }
    if (showSettings) UpdateSettingsDialog(state.preferences,
        onDismiss = { showSettings = false },
        onSave = { host.setPreferences(it); showSettings = false })
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.app_updates), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            state.installedVersion?.let { Text(stringResource(R.string.update_installed_version, it)) }
            Text(stringResource(when {
                state.busy -> R.string.update_working
                state.readyVersion != null && state.record?.phase?.terminal != false -> R.string.update_ready
                else -> when (state.record?.phase) {
                    UpdatePhase.RESERVED, UpdatePhase.BOUND -> R.string.update_recovering
                    UpdatePhase.INTENT, UpdatePhase.UNKNOWN -> R.string.update_outcome_unknown
                    UpdatePhase.SUBMITTED -> R.string.update_submitted
                    UpdatePhase.AWAITING_USER -> R.string.update_awaiting_confirmation
                    UpdatePhase.SUCCESS -> R.string.update_succeeded
                    UpdatePhase.FAILURE -> R.string.update_failed
                    UpdatePhase.ABANDONED -> R.string.update_abandoned
                    null -> R.string.update_none_staged
                }
            }), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            state.readyVersion?.let { Text(stringResource(R.string.update_ready_version, it)) }
            if (state.error != null) Text(stringResource(when (state.error) {
                UpdateHostError.RELEASE_CHECK -> R.string.update_check_error
                UpdateHostError.VERIFICATION -> R.string.update_download_error
                else -> R.string.update_operation_error
            }), color = MaterialTheme.colorScheme.error)
            val canDownload = !state.busy && state.readyVersion == null && !state.cleanupRequired && state.record?.phase?.terminal != false
            state.offered?.let { release ->
                Text(stringResource(R.string.update_release_available, release.versionName, Formatter.formatShortFileSize(context, release.size)))
                Button(onClick = { host.download() }, enabled = canDownload) { Text(stringResource(R.string.update_download)) }
            }
            if (state.checked && state.offered == null) Text(stringResource(R.string.update_no_newer_release))
            if (state.downloading) {
                Button(onClick = { host.cancelDownload() }) { Text(stringResource(R.string.update_cancel_download)) }
            }
            TextButton(onClick = { host.checkForUpdates() }, enabled = canDownload) { Text(stringResource(R.string.update_check_now)) }
            TextButton(onClick = { showSettings = true }, enabled = !state.busy) { Text(stringResource(R.string.update_settings)) }
            if (confirmationError || state.record?.phase == UpdatePhase.AWAITING_USER && !state.confirmationAvailable) {
                Text(stringResource(R.string.update_confirmation_unavailable))
            }
            if (state.cleanupRequired) {
                Text(stringResource(R.string.update_cleanup_needed))
                Button(onClick = { host.retryCleanup() }, enabled = !state.busy) { Text(stringResource(R.string.update_retry_cleanup)) }
            } else if (state.readyVersion != null && state.record?.phase?.terminal != false) {
                if (state.permissionRequired) {
                    Text(stringResource(R.string.update_permission_explanation))
                    Button(onClick = {
                        permission.launch(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, "package:${context.packageName}".toUri()))
                    }, enabled = !state.busy) { Text(stringResource(R.string.update_allow_installation)) }
                } else {
                    Button(onClick = { openConfirmation = true; host.install() }, enabled = !state.busy) {
                        Text(stringResource(R.string.update_install))
                    }
                }
                TextButton(onClick = { host.discard() }, enabled = !state.busy) { Text(stringResource(R.string.update_discard)) }
            }
            if (state.confirmationAvailable) {
                Button(onClick = { confirmationError = false; openConfirmation = true }, enabled = !state.busy) {
                    Text(stringResource(R.string.update_open_confirmation))
                }
            }
            if (state.record != null || state.error != null) {
                TextButton(onClick = { host.refresh() }, enabled = !state.busy) { Text(stringResource(R.string.update_refresh_status)) }
            }
        }
    }
}


@Composable
private fun UpdateSettingsDialog(current: UpdatePreferences, onDismiss: () -> Unit, onSave: (UpdatePreferences) -> Unit) {
    var automatic by remember { mutableStateOf(current.automatic) }
    var prereleases by remember { mutableStateOf(current.prereleases) }
    var hours by remember { mutableStateOf(current.intervalHours.toString()) }
    val parsedHours = hours.toIntOrNull()?.takeIf { it in 1..168 }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(stringResource(R.string.update_settings)) },
        text = {
            Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(stringResource(if (current.overridden) R.string.update_settings_phone else R.string.update_settings_default))
                Row(Modifier.fillMaxWidth().toggleable(automatic, role = Role.Switch, onValueChange = { automatic = it }), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.update_automatic), modifier = Modifier.weight(1f))
                    Switch(checked = automatic, onCheckedChange = null)
                }
                Text(stringResource(R.string.update_automatic_explanation))
                OutlinedTextField(value = hours, onValueChange = { if (it.length <= 3) hours = it },
                    label = { Text(stringResource(R.string.update_interval_hours)) },
                    supportingText = { Text(stringResource(R.string.update_interval_range)) },
                    isError = parsedHours == null, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                Row(Modifier.fillMaxWidth().toggleable(prereleases, role = Role.Switch, onValueChange = { prereleases = it }), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.update_prereleases), modifier = Modifier.weight(1f))
                    Switch(checked = prereleases, onCheckedChange = null)
                }
                TextButton(onClick = { onSave(UpdatePreferences()) }) { Text(stringResource(R.string.update_restore_defaults)) }
            }
        }, confirmButton = {
            Button(onClick = { onSave(UpdatePreferences(automatic, checkNotNull(parsedHours), prereleases, overridden = true)) },
                enabled = parsedHours != null) { Text(stringResource(R.string.update_save_settings)) }
        }, dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.update_cancel_settings)) } })
}
