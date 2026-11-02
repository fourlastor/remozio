package dev.sebastiano.remozio.android.audit

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun AuditWorkSettingsCard() {
    val settings = (LocalContext.current.applicationContext as RemozioApplication).auditWorkSettings
    val saved by settings.state.collectAsState()
    val scope = rememberCoroutineScope()
    var fields by rememberSaveable { mutableStateOf(saved.fields()) }
    var expanded by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<AuditSettingsResult?>(null) }
    AuditWorkSettingsContent(saved, fields, expanded, busy, result,
        onExpanded = { expanded = !expanded },
        onFields = { fields = it; result = null },
        onDefaults = { fields = AuditWorkPolicy().fields(); result = null },
        onSave = { policy ->
            if (!busy) {
                busy = true
                result = null
                scope.launch {
                    try {
                        result = if (withContext(Dispatchers.IO) { settings.save(policy) }) AuditSettingsResult.SAVED
                        else AuditSettingsResult.FAILED
                    } finally { busy = false }
                }
            }
        })
}

internal enum class AuditSettingsResult { SAVED, FAILED }

/** Display-only input boundary, also used by disposable native previews. */
@Composable
internal fun AuditWorkSettingsContent(
    saved: AuditWorkPolicy,
    fields: List<String>,
    expanded: Boolean,
    busy: Boolean,
    result: AuditSettingsResult?,
    onExpanded: () -> Unit,
    onFields: (List<String>) -> Unit,
    onSave: (AuditWorkPolicy) -> Unit,
    onDefaults: () -> Unit,
) {
    val labels = listOf(R.string.audit_settings_responses, R.string.audit_settings_seconds)
    val ranges = listOf(1..4096, 1..60)
    val numbers = fields.map(String::toIntOrNull)
    val valid = numbers.size == 2 && numbers.indices.all { numbers[it]?.let { n -> n in ranges[it] } == true }
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.audit_settings_title), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.audit_settings_reason))
            Text(stringResource(R.string.audit_settings_saved_values,
                pluralStringResource(R.plurals.audit_settings_saved_responses, saved.responseBudget, saved.responseBudget),
                pluralStringResource(R.plurals.audit_settings_saved_seconds, saved.operationSeconds, saved.operationSeconds)),
                style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.audit_settings_boundary))
            TextButton(enabled = !busy, onClick = onExpanded) {
                Text(stringResource(if (expanded) R.string.audit_settings_hide else R.string.audit_settings_show))
            }
            if (expanded) {
                fields.forEachIndexed { index, value ->
                    val range = ranges[index]
                    val fieldValid = numbers[index]?.let { it in range } == true
                    OutlinedTextField(value, { changed ->
                        if (changed.length <= 4 && changed.all { it in '0'..'9' }) {
                            onFields(fields.toMutableList().also { it[index] = changed })
                        }
                    }, label = { Text(stringResource(labels[index])) },
                        supportingText = { Text(stringResource(R.string.wake_setting_range, range.first, range.last)) },
                        isError = !fieldValid, enabled = !busy, singleLine = true, modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                }
                Button(enabled = !busy && valid, onClick = {
                    if (valid) onSave(AuditWorkPolicy(requireNotNull(numbers[0]), requireNotNull(numbers[1])))
                }) { Text(stringResource(if (busy) R.string.audit_settings_saving else R.string.audit_settings_save)) }
                TextButton(enabled = !busy, onClick = onDefaults) {
                    Text(stringResource(R.string.wake_settings_defaults))
                }
                Text(stringResource(R.string.audit_settings_defaults_hint), style = MaterialTheme.typography.bodySmall)
            }
            result?.let {
                Text(stringResource(if (it == AuditSettingsResult.SAVED) R.string.audit_settings_saved else R.string.audit_settings_failed),
                    color = if (it == AuditSettingsResult.FAILED) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
        }
    }
}

private fun AuditWorkPolicy.fields() = listOf(responseBudget, operationSeconds).map(Int::toString)
