package dev.sebastiano.remozio.android.transport

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.core.content.edit
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import dev.sebastiano.remozio.android.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

internal class LocalNetworkSettings(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("local-network", Context.MODE_PRIVATE)
    fun timeoutSeconds(): Int = try { preferences.getInt("direct-timeout-seconds", 3).coerceIn(1, 10) } catch (_: ClassCastException) { 3 }
    fun setTimeoutSeconds(value: Int) { require(value in 1..10); preferences.edit { putInt("direct-timeout-seconds", value) } }
}

@Composable
internal fun LocalNetworkSettingsCard() {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var refresh by remember { mutableIntStateOf(0) }
    var allowed by remember { mutableStateOf<Boolean?>(null) }
    val slider = rememberSliderState(value = 3f, steps = 8, trackRange = 1f..10f)
    val seconds = slider.value.roundToInt()
    var preferences by remember { mutableStateOf<LocalNetworkSettings?>(null) }
    var failed by remember { mutableStateOf(false) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { refresh++ }
    LaunchedEffect(lifecycle, refresh) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            allowed = null
            val loaded = withContext(Dispatchers.IO) { LocalNetworkSettings(context).let { it to it.timeoutSeconds() } }
            preferences = loaded.first
            slider.value = loaded.second.toFloat()
            allowed = context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED
            try { awaitCancellation() } finally { allowed = null }
        }
    }
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.lan_title), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.lan_explanation))
            allowed?.let { granted ->
                Text(stringResource(if (granted) R.string.lan_allowed else R.string.lan_not_allowed))
                if (!granted) Button(onClick = {
                    try { permission.launch(Manifest.permission.ACCESS_LOCAL_NETWORK) }
                    catch (_: RuntimeException) { failed = true }
                }) { Text(stringResource(R.string.lan_enable)) }
                OutlinedButton(onClick = {
                    try { context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))) }
                    catch (_: RuntimeException) { failed = true }
                }) { Text(stringResource(R.string.lan_system_settings)) }
            }
            Text(pluralStringResource(R.plurals.lan_timeout, seconds, seconds))
            val sliderLabel = stringResource(R.string.lan_timeout_label)
            val spokenValue = pluralStringResource(R.plurals.lan_timeout_seconds, seconds, seconds)
            Slider(modifier = Modifier.semantics { contentDescription = sliderLabel; stateDescription = spokenValue },
                state = slider, onValueChange = { slider.value = it },
                enabled = preferences != null && allowed != null, onValueChangeFinished = { preferences?.setTimeoutSeconds(seconds) })
            Text(stringResource(R.string.lan_timeout_next_connection))
            if (failed) Text(stringResource(R.string.lan_settings_failed))
        }
    }
}
