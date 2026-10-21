package dev.remozio.android.requests

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication

@Composable
internal fun CombinedCommandInboxScreen(onPair: () -> Unit) {
    val runtime = (LocalContext.current.applicationContext as RemozioApplication).foregroundCommands
    val state by runtime.state.collectAsStateWithLifecycle()
    CombinedCommandInboxSurface(state, onPair, runtime::refresh)
}

/** Filters and selection belong to the display. All foreground connection jobs remain app-owned. */
@Composable
internal fun CombinedCommandInboxSurface(state: ForegroundCommandState, onPair: () -> Unit, onRetry: () -> Unit) {
    val owners = (state as? ForegroundCommandState.Ready)?.owners.orEmpty()
    var filter by rememberSaveable { mutableStateOf<String?>(null) }
    var selected by remember { mutableStateOf<ScopedCommandRequest?>(null) }
    val requestFlow = remember(owners) { observeCommandInbox(owners) }
    val received by requestFlow.collectAsStateWithLifecycle(initialValue = emptyList())
    val requests = received.filter { it.isCurrent(owners) && (filter == null || commandIdentityText(it.owner.recordID) == filter) }
    val visibleOwners = owners.filter { filter == null || commandIdentityText(it.recordID) == filter }
    LaunchedEffect(owners, state) {
        if (selected?.isCurrent(owners) == false) selected = null
        if (state is ForegroundCommandState.Ready && owners.none { commandIdentityText(it.recordID) == filter }) filter = null
    }
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 840.dp).fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(stringResource(R.string.nav_requests), style = MaterialTheme.typography.headlineLarge,
                modifier = Modifier.semantics { heading() })
            if (owners.size > 1) LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item { FilterChip(selected = filter == null, onClick = { filter = null },
                    label = { Text(stringResource(R.string.commands_all_hosts)) }) }
                items(owners, key = { commandIdentityText(it.recordID) }) { owner ->
                    val id = commandIdentityText(owner.recordID)
                    FilterChip(selected = filter == id, onClick = { filter = id }, label = {
                        Column {
                            Text(commandMacLabel(owner, owners))
                            Text(stringResource(R.string.commands_account_suffix, commandAccountSuffix(owner, owners)),
                                style = MaterialTheme.typography.labelSmall)
                        }
                    })
                }
            }
            when (state) {
                ForegroundCommandState.Loading, ForegroundCommandState.Stopped -> {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(stringResource(R.string.macs_loading))
                }
                ForegroundCommandState.Unavailable -> {
                    Text(stringResource(R.string.commands_storage_unavailable))
                    OutlinedButton(onClick = onRetry) { Text(stringResource(R.string.macs_retry)) }
                }
                is ForegroundCommandState.Ready -> LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (owners.isEmpty()) item {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(stringResource(R.string.no_macs_paired), style = MaterialTheme.typography.titleLarge)
                            Text(stringResource(R.string.pairing_empty_description))
                            Button(onClick = onPair) { Text(stringResource(R.string.pairing_setup_title)) }
                        }
                    } else {
                        if (requests.isEmpty()) item { Text(stringResource(R.string.commands_empty)) }
                        itemsIndexed(requests, key = { _, request -> request.key }) { index, request ->
                            CommandRequestRow(request.session, index + 1, onOpen = { selected = request },
                                macName = commandMacLabel(request.owner, owners),
                                accountName = stringResource(R.string.commands_account_suffix, commandAccountSuffix(request.owner, owners)))
                        }
                        item { Text(stringResource(R.string.commands_connections), style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.padding(top = 12.dp).semantics { heading() }) }
                        items(visibleOwners, key = { "connection:${commandIdentityText(it.recordID)}" }) { owner ->
                            CommandPeerStatus(owner, owners, onRetry)
                        }
                    }
                }
            }
        }
    }
    selected?.takeIf { it.isCurrent(owners) }?.let { request ->
        val approval = remember(request.connection, request.session) { request.connection.approval(request.session) }
        CommandRequestInspection(request.session, commandMacLabel(request.owner, owners),
            stringResource(R.string.commands_account_suffix, commandAccountSuffix(request.owner, owners)),
            onDismiss = { selected = null }, approval = approval)
    }
}

@Composable
private fun CommandPeerStatus(owner: StoredCommandOwner, owners: List<StoredCommandOwner>, onRetry: () -> Unit) {
    val connection = owner.connection
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(commandMacLabel(owner, owners), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.commands_account_suffix, commandAccountSuffix(owner, owners)), style = MaterialTheme.typography.bodySmall)
        if (connection == null) {
            Text(stringResource(R.string.commands_storage_unavailable))
            TextButton(onClick = onRetry) { Text(stringResource(R.string.macs_retry)) }
        } else {
            val state by connection.connectionState.collectAsStateWithLifecycle()
            val limited by connection.capacityLimited.collectAsStateWithLifecycle()
            Text(stringResource(when (state) {
                CommandConnectionState.CONNECTING -> R.string.commands_connecting
                CommandConnectionState.CONNECTED -> R.string.commands_connected
                CommandConnectionState.DISCONNECTED -> R.string.commands_disconnected
                CommandConnectionState.CLOSED -> R.string.commands_enrollment_unavailable
            }))
            if (limited) Text(stringResource(R.string.commands_capacity))
            if (state == CommandConnectionState.DISCONNECTED || state == CommandConnectionState.CLOSED || limited) {
                TextButton(onClick = onRetry) { Text(stringResource(R.string.commands_reconnect)) }
            }
        }
        Text(stringResource(R.string.commands_presence_unknown), style = MaterialTheme.typography.bodySmall)
    }
}
