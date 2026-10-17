package dev.remozio.android.push

import dev.remozio.android.transport.LocalNetworkSettingsCard
import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun NotificationSettingsScreen() {
    val context = LocalContext.current
    val backend = remember(context.applicationContext) { AndroidNotificationSetup(context) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    var refresh by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<LocalNotificationResult?>(null) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { refresh++ }
    val accessState = remember(backend, lifecycle, refresh) { mutableStateOf<NotificationAccess?>(null) }
    val access by accessState
    LaunchedEffect(accessState) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            accessState.value = null
            try { accessState.value = withContext(Dispatchers.IO) { backend.read() }; awaitCancellation() }
            finally { accessState.value = null }
        }
    }
    fun settings(channel: Boolean) {
        scope.launch {
            busy = true
            try {
                val prepared = !channel || withContext(Dispatchers.IO) { backend.prepare() }
                if (prepared) {
                    try { context.startActivity(backend.settingsIntent(channel)) }
                    catch (_: RuntimeException) { result = LocalNotificationResult.FAILED }
                } else result = LocalNotificationResult.FAILED
            } finally { busy = false; refresh++ }
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(stringResource(R.string.nav_settings), style = MaterialTheme.typography.headlineLarge,
            modifier = Modifier.semantics { heading() })
        Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.notification_settings_title), style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.semantics { heading() })
                Text(stringResource(R.string.notification_settings_reason))
                Text(stringResource(R.string.notification_remote_pending))
                val current = access
                if (current == null) {
                    CircularProgressIndicator()
                    Text(stringResource(R.string.notification_reading))
                } else {
                    Text(stringResource(notificationAccessLabel(current)), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(R.string.notification_visibility_limits))
                    if (current == NotificationAccess.PERMISSION_REQUIRED || current == NotificationAccess.CHANNEL_MISSING) {
                        Button(enabled = !busy, onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    if (withContext(Dispatchers.IO) { backend.prepare() }) {
                                        if (current == NotificationAccess.PERMISSION_REQUIRED) {
                                            try { permission.launch(Manifest.permission.POST_NOTIFICATIONS) }
                                            catch (_: RuntimeException) { result = LocalNotificationResult.FAILED }
                                        }
                                    } else result = LocalNotificationResult.FAILED
                                } finally { busy = false; refresh++ }
                            }
                        }) { Text(stringResource(R.string.notification_enable)) }
                    }
                    OutlinedButton(enabled = !busy, onClick = { settings(false) }) {
                        Text(stringResource(R.string.notification_app_settings))
                    }
                    OutlinedButton(enabled = !busy, onClick = { settings(true) }) {
                        Text(stringResource(R.string.notification_channel_settings))
                    }
                    Button(enabled = !busy && current.canTest, onClick = {
                        scope.launch {
                            busy = true
                            try { result = withContext(Dispatchers.IO) { backend.postLocalTest() } }
                            finally { busy = false; refresh++ }
                        }
                    }) { Text(stringResource(R.string.notification_local_test)) }
                    Text(stringResource(R.string.notification_local_test_explanation))
                    TextButton(enabled = !busy, onClick = {
                        scope.launch {
                            busy = true
                            try { result = withContext(Dispatchers.IO) { backend.clearLocalTest() } }
                            finally { busy = false }
                        }
                    }) { Text(stringResource(R.string.notification_clear_test)) }
                }
                if (busy) Text(stringResource(R.string.notification_working))
                result?.let {
                    Text(stringResource(notificationResultLabel(it)), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                }
                TextButton(enabled = !busy, onClick = { refresh++ }) { Text(stringResource(R.string.notification_refresh)) }
            }
        }
        FCMClientSettingsCard()
        PushRegistrationStatusCard()
        PushRegistrationWorkSettingsCard()
        WakeWorkSettingsCard()
        LocalNetworkSettingsCard()
    }
}

private fun notificationAccessLabel(access: NotificationAccess): Int = when (access) {
    NotificationAccess.PERMISSION_REQUIRED -> R.string.notification_permission_required
    NotificationAccess.APP_DISABLED -> R.string.notification_app_disabled
    NotificationAccess.CHANNEL_MISSING -> R.string.notification_channel_missing
    NotificationAccess.CHANNEL_DISABLED -> R.string.notification_channel_disabled
    NotificationAccess.ALLOWED -> R.string.notification_allowed
    NotificationAccess.QUIET -> R.string.notification_quiet
    NotificationAccess.UNAVAILABLE -> R.string.notification_unavailable
}

private fun notificationResultLabel(result: LocalNotificationResult): Int = when (result) {
    LocalNotificationResult.SUBMITTED -> R.string.notification_test_submitted
    LocalNotificationResult.BLOCKED -> R.string.notification_test_blocked
    LocalNotificationResult.FAILED -> R.string.notification_action_failed
    LocalNotificationResult.CLEARED -> R.string.notification_test_cleared
}
