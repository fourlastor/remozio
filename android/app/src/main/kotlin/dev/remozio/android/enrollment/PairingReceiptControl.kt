package dev.remozio.android.enrollment

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch

internal enum class ReceiptCheckState { IDLE, CHECKING, UNAVAILABLE }

@Composable
internal fun PairingReceiptControl(mac: StoredMac, status: MutableState<ReceiptCheckState>, onChecked: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as RemozioApplication
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    var state by status
    var operation by remember(mac.recordID) { mutableStateOf<Job?>(null) }
    fun checkPairing() {
        if (operation?.isActive == true || !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        state = ReceiptCheckState.CHECKING
        operation = scope.launch {
            try {
                if (app.pairingReceipts.checkAndReconcile(mac.recordID, onChecked)) {
                    state = ReceiptCheckState.IDLE
                } else state = ReceiptCheckState.UNAVAILABLE
            } catch (cancelled: CancellationException) {
                state = ReceiptCheckState.IDLE
                throw cancelled
            } catch (_: Exception) { state = ReceiptCheckState.UNAVAILABLE }
        }
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { _ ->
        checkPairing()
    }
    LaunchedEffect(lifecycle, mac.recordID) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            try { awaitCancellation() } finally { operation?.cancel() }
        }
    }
    if (state == ReceiptCheckState.CHECKING) {
        CircularProgressIndicator()
        Text(stringResource(R.string.pairing_receipt_checking), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    } else {
        if (state != ReceiptCheckState.IDLE) {
            Text(stringResource(R.string.pairing_receipt_unavailable),
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        }
        TextButton(onClick = {
            if (context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) checkPairing()
            else permission.launch(Manifest.permission.ACCESS_LOCAL_NETWORK)
        }) { Text(stringResource(R.string.pairing_receipt_check)) }
    }
}
