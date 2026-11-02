package dev.sebastiano.remozio.android.routing

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
import dev.sebastiano.remozio.android.RemozioApplication
import dev.sebastiano.remozio.android.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun RoutingWorkSettingsCard(initiallyExpanded: Boolean = false) {
    val settings = (LocalContext.current.applicationContext as RemozioApplication).routingWorkSettings
    val scope = rememberCoroutineScope()
    var fields by remember { mutableStateOf<List<String>?>(null) }
    var expanded by rememberSaveable { mutableStateOf(initiallyExpanded) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(settings) { fields = withContext(Dispatchers.IO) { settings.read().fields() } }
    val labels = listOf(R.string.routing_refresh_seconds, R.string.routing_freshness_seconds, R.string.routing_operation_seconds)
    val ranges = listOf(1..3600, 1..3600, 1..60)
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.routing_settings_title), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.routing_settings_reason))
            TextButton(enabled = !busy, onClick = { expanded = !expanded }) {
                Text(stringResource(if (expanded) R.string.routing_settings_hide else R.string.routing_settings_show))
            }
            if (expanded) {
                val values = fields
                if (values == null) Text(stringResource(R.string.routing_settings_reading))
                else {
                    values.forEachIndexed { index, value ->
                        val range = ranges[index]
                        val valid = value.toIntOrNull()?.let { it in range } == true
                        OutlinedTextField(value, { changed ->
                            if (changed.length <= 4 && changed.all { it in '0'..'9' }) {
                                fields = values.toMutableList().also { it[index] = changed }; result = null
                            }
                        }, label = { Text(stringResource(labels[index])) },
                            supportingText = { Text(stringResource(R.string.wake_setting_range, range.first, range.last)) },
                            isError = !valid, enabled = !busy, singleLine = true, modifier = Modifier.fillMaxWidth(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                    }
                    Button(enabled = !busy && values.indices.all { values[it].toIntOrNull()?.let { n -> n in ranges[it] } == true },
                        onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    val n = values.map(String::toInt)
                                    val saved = withContext(Dispatchers.IO) { settings.save(RoutingWorkPolicy(n[0], n[1], n[2])) }
                                    result = if (saved) R.string.routing_settings_saved else R.string.routing_settings_failed
                                } finally { busy = false }
                            }
                        }) { Text(stringResource(R.string.routing_settings_save)) }
                    TextButton(enabled = !busy, onClick = { fields = RoutingWorkPolicy().fields(); result = null }) {
                        Text(stringResource(R.string.wake_settings_defaults))
                    }
                }
            }
            result?.let { Text(stringResource(it), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
        }
    }
}
private fun RoutingWorkPolicy.fields() = listOf(refreshSeconds, freshnessSeconds, operationSeconds).map(Int::toString)
