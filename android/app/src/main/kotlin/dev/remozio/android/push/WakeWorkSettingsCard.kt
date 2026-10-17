package dev.remozio.android.push

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.remozio.android.RemozioApplication
import dev.remozio.android.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun WakeWorkSettingsCard() {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val settings = app.wakeWorkSettings
    val scope = rememberCoroutineScope()
    var values by remember { mutableStateOf<List<String>?>(null) }
    var expanded by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(settings) {
        values = withContext(Dispatchers.IO) { settings.read().fields().map(Int::toString) }
    }
    val labels = listOf(R.string.wake_ingress_limit, R.string.wake_fetch_limit, R.string.wake_attempts,
        R.string.wake_backoff, R.string.wake_snapshot_timeout, R.string.wake_reconcile_interval)
    val ranges = listOf(1..4096, 1..4096, 1..20, 10..3600, 1..60, 15..1440)
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.wake_work_title), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.wake_work_reason))
            TextButton(onClick = { expanded = !expanded }, enabled = !busy) {
                Text(stringResource(if (expanded) R.string.wake_settings_hide else R.string.wake_settings_show))
            }
            if (expanded) {
            val fields = values
            if (fields == null) CircularProgressIndicator()
            else {
                fields.forEachIndexed { index, value ->
                    val range = ranges[index]
                    val valid = value.toIntOrNull()?.let { it in range } == true
                    OutlinedTextField(value, { changed ->
                        if (changed.length <= 5 && changed.all { it in '0'..'9' }) {
                            values = fields.toMutableList().also { it[index] = changed }; result = null
                        }
                    }, label = { Text(stringResource(labels[index])) },
                        supportingText = { Text(stringResource(R.string.wake_setting_range, range.first, range.last)) },
                        isError = !valid, enabled = !busy, singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                }
                Button(enabled = !busy && fields.indices.all { fields[it].toIntOrNull()?.let { n -> n in ranges[it] } == true },
                    onClick = {
                        scope.launch {
                            busy = true
                            try {
                                val n = fields.map(String::toInt)
                                val saved = withContext(Dispatchers.IO) { settings.save(WakeWorkPolicy(n[0], n[1], n[2], n[3], n[4], n[5])) }
                                result = if (saved) R.string.wake_settings_saved else R.string.wake_settings_failed
                            } finally { busy = false }
                        }
                    }) { Text(stringResource(R.string.wake_settings_save)) }
                TextButton(enabled = !busy, onClick = { values = WakeWorkPolicy().fields().map(Int::toString); result = null }) {
                    Text(stringResource(R.string.wake_settings_defaults))
                }
            }
            }
            result?.let { Text(stringResource(it), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
        }
    }
}
private fun WakeWorkPolicy.fields() = listOf(ingressLimit, fetchLimit, maximumAttempts, backoffSeconds, snapshotSeconds, reconcileMinutes)
