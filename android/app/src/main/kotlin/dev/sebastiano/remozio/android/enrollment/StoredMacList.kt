package dev.sebastiano.remozio.android.enrollment

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
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
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.RemozioApplication
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import dev.remozio.protocol.CborValue

@Composable
internal fun StoredMacList(onOpen: (StoredMac) -> Unit) {
    val app = LocalContext.current.applicationContext as RemozioApplication
    val reader = app.macs
    val scope = rememberCoroutineScope()
    var removal by remember { mutableStateOf<StoredMac?>(null) }
    var removing by remember { mutableStateOf(false) }
    var removalError by remember { mutableStateOf<Int?>(null) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var retry by remember { mutableIntStateOf(0) }
    val receiptStates = remember { mutableMapOf<CborValue.Bytes, MutableState<ReceiptCheckState>>() }
    val state by produceState<MacInventoryState>(MacInventoryState.Loading, reader, lifecycle, retry) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            value = MacInventoryState.Loading
            try {
                value = reader.read()
                awaitCancellation()
            } finally {
                value = MacInventoryState.Loading
            }
        }
    }
    removal?.let { mac ->
        val abandonRePair = mac.setupIncomplete && mac.canAbandonRePair
        val title = if (abandonRePair) R.string.macs_abandon_repair else R.string.macs_remove_local
        val description = if (abandonRePair) R.string.macs_abandon_repair_description else R.string.macs_remove_local_description
        AlertDialog(
            onDismissRequest = { if (!removing) removal = null },
            title = { Text(stringResource(title)) },
            text = { Text(stringResource(description, mac.label)) },
            confirmButton = {
                TextButton(enabled = !removing, onClick = {
                    removing = true
                    removalError = null
                    scope.launch {
                        try {
                            if (abandonRePair) app.pairing.abandonAmbiguousRePair(mac.recordID, mac.revision)
                            else app.pairing.remove(mac.recordID, mac.revision)
                        } catch (_: OrdinaryPairingReplacementPending) {
                            removalError = R.string.macs_remove_local_pairing_pending
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (_: Exception) {
                            removalError = if (abandonRePair) R.string.macs_abandon_repair_failed else R.string.macs_remove_local_failed
                        } finally {
                            removal = null
                            removing = false
                            retry++
                        }
                    }
                }) { Text(stringResource(title)) }
            },
            dismissButton = {
                TextButton(enabled = !removing, onClick = { removal = null }) { Text(stringResource(android.R.string.cancel)) }
            },
        )
    }
    removalError?.let { Text(stringResource(it), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
    when (val current = state) {
        MacInventoryState.Loading -> InventoryCard {
            CircularProgressIndicator()
            Text(stringResource(R.string.macs_loading))
        }
        MacInventoryState.Unavailable -> InventoryCard {
            Text(stringResource(R.string.macs_unavailable), style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            Text(stringResource(R.string.macs_unavailable_description))
            TextButton(onClick = { retry++ }) { Text(stringResource(R.string.macs_retry)) }
        }
        is MacInventoryState.Ready -> {
            SideEffect { receiptStates.keys.retainAll(current.macs.filter { it.setupIncomplete }.map { it.recordID }.toSet()) }
            if (current.macs.isEmpty()) InventoryCard {
                Text(stringResource(R.string.no_macs_paired), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(R.string.pairing_empty_description), style = MaterialTheme.typography.bodyLarge)
            }
            current.macs.forEach { mac ->
                key(mac.recordID) {
                    InventoryCard {
                        Text(mac.label, style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.semantics { heading() })
                        if (mac.setupIncomplete) {
                            Text(stringResource(R.string.macs_setup_incomplete), style = MaterialTheme.typography.titleMedium)
                            Text(stringResource(if (mac.rePair) R.string.pairing_repair_pending
                                else R.string.macs_setup_incomplete_description))
                        } else {
                            dev.sebastiano.remozio.android.routing.MacRoutingStatusContent(mac.recordID)
                            HorizontalDivider(Modifier.padding(vertical = 8.dp))
                            dev.sebastiano.remozio.android.updates.MacUpdateStatusContent(mac.recordID)
                        }
                        if (mac.setupIncomplete) {
                            PairingReceiptControl(mac,
                                status = remember(receiptStates, mac.recordID) {
                                    receiptStates.getOrPut(mac.recordID) { mutableStateOf(ReceiptCheckState.IDLE) }
                                },
                                onChecked = { retry++ })
                            if (mac.canAbandonRePair) {
                                TextButton(onClick = { removal = mac }) { Text(stringResource(R.string.macs_abandon_repair)) }
                            }
                        } else {
                            TextButton(onClick = { onOpen(mac) }) { Text(stringResource(R.string.commands_open)) }
                            TextButton(onClick = { removal = mac }) { Text(stringResource(R.string.macs_remove_local)) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun InventoryCard(content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { content() }
    }
}
