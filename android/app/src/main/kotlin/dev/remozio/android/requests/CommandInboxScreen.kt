package dev.remozio.android.requests

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
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
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import dev.remozio.android.enrollment.StoredMac
import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.CommandRequestSnapshot
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

/** Screens observe application-owned connections without opening or stopping their transports. */
@Composable
internal fun CommandInboxScreen(mac: StoredMac, onBack: () -> Unit) {
    val runtime = (LocalContext.current.applicationContext as RemozioApplication).foregroundCommands
    val runtimeState by runtime.state.collectAsState()
    val selectedOwner = (runtimeState as? ForegroundCommandState.Ready)?.owners?.singleOrNull { it.recordID == mac.recordID }
    val owner = selectedOwner?.connection
    val failure = when (runtimeState) {
        ForegroundCommandState.Unavailable -> R.string.commands_storage_unavailable
        is ForegroundCommandState.Ready -> when {
            selectedOwner == null -> R.string.commands_enrollment_unavailable
            owner == null -> R.string.commands_storage_unavailable
            else -> null
        }
        else -> null
    }
    var selected by remember(mac.recordID) { mutableStateOf<CommandRequestSession?>(null) }
    LaunchedEffect(owner) { selected = null }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TextButton(onClick = onBack) { Text(stringResource(R.string.commands_back)) }
        Text(mac.label, style = MaterialTheme.typography.headlineLarge, modifier = Modifier.semantics { heading() })
        Text(stringResource(R.string.commands_presence_unknown))
        owner?.let { connection ->
            val state by connection.connectionState.collectAsState()
            val limited by connection.capacityLimited.collectAsState()
            if (limited) Text(stringResource(R.string.commands_capacity))
            Text(stringResource(when (state) {
                CommandConnectionState.CONNECTING -> R.string.commands_connecting
                CommandConnectionState.CONNECTED -> R.string.commands_connected
                CommandConnectionState.DISCONNECTED -> R.string.commands_disconnected
                CommandConnectionState.CLOSED -> R.string.commands_enrollment_unavailable
            }))
            if (limited || state == CommandConnectionState.DISCONNECTED || state == CommandConnectionState.CLOSED) {
                TextButton(onClick = runtime::refresh) { Text(stringResource(R.string.commands_reconnect)) }
            }
        } ?: run { if (failure == null) CircularProgressIndicator() }
        failure?.let {
            Text(stringResource(it))
            if (owner == null) TextButton(onClick = runtime::refresh) { Text(stringResource(R.string.macs_retry)) }
        }
        owner?.let { connection ->
            val requests by connection.requests.collectAsState()
            if (requests.isEmpty()) Text(stringResource(R.string.commands_empty))
            LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                itemsIndexed(requests, key = { _, session -> session.identity.requestID.copyBytes().joinToString("") { "%02x".format(it) } }) { index, session ->
                    CommandRequestRow(session, index + 1, onOpen = { selected = session })
                }
            }
            selected?.let { session ->
                val approval = remember(connection, session) { connection.approval(session) }
                CommandRequestInspection(session, commandMacLabel(checkNotNull(selectedOwner), (runtimeState as ForegroundCommandState.Ready).owners),
                    stringResource(R.string.commands_account_suffix, commandAccountSuffix(selectedOwner, (runtimeState as ForegroundCommandState.Ready).owners)),
                    onDismiss = { selected = null }, approval = approval)
            }
        }
    }
}

@Composable
internal fun CommandRequestRow(session: CommandRequestSession, number: Int, onOpen: () -> Unit, macName: String? = null, accountName: String? = null) {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var snapshot by remember(session) { mutableStateOf<CommandRequestSnapshot?>(null) }
    LaunchedEffect(session, lifecycle) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            try {
                while (isActive) { snapshot = session.snapshot(RequestElapsedClock.now()); delay(1000) }
            } finally { snapshot = null }
        }
    }
    snapshot?.takeUnless { it.closed }?.let { current ->
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(macName ?: stringResource(R.string.commands_request_number, number), style = MaterialTheme.typography.titleMedium)
                        accountName?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    }
                    TextButton(onClick = onOpen) { Text(stringResource(R.string.commands_review)) }
                }
                current.status?.let { RequestStatusSummary(it) } ?: Text(stringResource(R.string.commands_waiting_status))
            }
        }
    }
}
