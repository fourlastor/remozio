package dev.remozio.android.enrollment

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import kotlinx.coroutines.awaitCancellation
import dev.remozio.protocol.CborValue

@Composable
internal fun StoredMacList(onOpen: (StoredMac) -> Unit) {
    val reader = (LocalContext.current.applicationContext as RemozioApplication).macs
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
                        Text(stringResource(if (mac.setupIncomplete) R.string.macs_setup_incomplete else R.string.macs_not_connected),
                            style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(if (mac.setupIncomplete) R.string.macs_setup_incomplete_description else R.string.macs_unknown_status))
                        if (mac.setupIncomplete) PairingReceiptControl(mac,
                            status = remember(receiptStates, mac.recordID) {
                                receiptStates.getOrPut(mac.recordID) { mutableStateOf(ReceiptCheckState.IDLE) }
                            },
                            onChecked = { retry++ })
                        else TextButton(onClick = { onOpen(mac) }) {
                            Text(stringResource(R.string.commands_open))
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
