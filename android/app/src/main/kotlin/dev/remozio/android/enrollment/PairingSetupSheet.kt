package dev.remozio.android.enrollment

import android.Manifest
import android.os.SystemClock
import android.content.pm.PackageManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.util.concurrent.atomic.AtomicBoolean
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import dev.remozio.protocol.PairingInvitation
import dev.remozio.android.R
import dev.remozio.android.biometrics.PairingBiometricPrompt
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PairingSetupSheet(model: PairingViewModel, activity: ComponentActivity) {
    val state by model.state.collectAsState()
    if (state.phase == PairingPhase.CLOSED) return
    val lifecycle = activity.lifecycle
    DisposableEffect(lifecycle, model) {
        val observer = object : DefaultLifecycleObserver {
            override fun onResume(owner: LifecycleOwner) = model.foreground(true)
            override fun onPause(owner: LifecycleOwner) = model.foreground(false)
        }
        lifecycle.addObserver(observer)
        model.foreground(lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED))
        onDispose { lifecycle.removeObserver(observer); model.foreground(false) }
    }
    state.signer?.let { signer ->
        DisposableEffect(signer, activity) {
            val prompt = PairingBiometricPrompt(activity, signer)
            prompt.authenticate { model.biometricResult(signer, it) }
            onDispose { prompt.close() }
        }
    }
    PairingSetupSurface(state, model::connect, model::confirmComparison, model::expire, model::close)
}

/** Display-only surface. Callback ownership remains with the retained setup host. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PairingSetupSurface(state: PairingScreenState, onConnect: (String) -> Unit, onCompare: () -> Unit,
    onExpire: () -> Unit, onClose: () -> Unit, preview: Boolean = false) {
    BoxWithConstraints {
        if (maxWidth >= 600.dp) {
            Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Surface(Modifier.widthIn(max = 560.dp).fillMaxWidth().padding(24.dp), shape = MaterialTheme.shapes.extraLarge) {
                    PairingSetupContent(state, onConnect, onCompare, onExpire, onClose, preview, Modifier.padding(24.dp))
                }
            }
        } else {
            ModalBottomSheet(onDismissRequest = onClose,
                sheetState = rememberBottomSheetState(initialValue = SheetValue.Hidden, enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded))) {
                PairingSetupContent(state, onConnect, onCompare, onExpire, onClose, preview, Modifier.padding(horizontal = 24.dp).padding(bottom = 24.dp))
            }
        }
    }
}

@Composable
private fun PairingSetupContent(state: PairingScreenState, onConnect: (String) -> Unit, onCompare: () -> Unit,
    onExpire: () -> Unit, onClose: () -> Unit, preview: Boolean, modifier: Modifier) {
    val context = LocalContext.current
    var invitation by rememberSaveable { mutableStateOf("") }
    var denied by remember { mutableStateOf(false) }
    var scannerBusy by remember { mutableStateOf(false) }
    var scannerFailed by remember { mutableStateOf(false) }
    val scannerLive = remember { AtomicBoolean(true) }
    DisposableEffect(Unit) { onDispose { scannerLive.set(false) } }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        denied = !granted
        if (granted) onConnect(invitation)
    }
    var seconds by remember(state.transcript) { mutableLongStateOf(0) }
    LaunchedEffect(state.expiresElapsedMillis, state.phase) {
        val deadline = state.expiresElapsedMillis ?: return@LaunchedEffect
        while (true) {
            val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0)
            seconds = (remaining + 999) / 1000
            if (seconds == 0L) { onExpire(); break }
            delay(1000)
        }
    }
    Column(modifier.fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        if (preview) Text(stringResource(R.string.pairing_setup_preview), color = MaterialTheme.colorScheme.error)
        Text(stringResource(R.string.pairing_setup_title), style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() })
        if (state.phase == PairingPhase.INPUT) {
            Text(stringResource(R.string.pairing_setup_intro))
            OutlinedButton(onClick = {
                scannerBusy = true; scannerFailed = false
                try {
                    val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).enableAutoZoom().build()
                    GmsBarcodeScanning.getClient(context, options).startScan()
                        .addOnSuccessListener { barcode ->
                            if (scannerLive.get()) {
                                val text = barcode.rawValue
                                if (text != null && runCatching { PairingInvitation.importText(text) }.isSuccess) invitation = text
                                else scannerFailed = true
                            }
                        }
                        .addOnFailureListener { if (scannerLive.get()) scannerFailed = true }
                        .addOnCompleteListener { if (scannerLive.get()) scannerBusy = false }
                } catch (_: RuntimeException) { scannerBusy = false; scannerFailed = true }
            }, enabled = !preview && !scannerBusy, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_scan)) }
            if (scannerBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (scannerFailed) Text(stringResource(R.string.pairing_setup_scan_failed), color = MaterialTheme.colorScheme.error)
            OutlinedTextField(value = invitation, onValueChange = { if (it.length <= 16_384) invitation = it },
                label = { Text(stringResource(R.string.pairing_setup_invitation)) }, modifier = Modifier.fillMaxWidth(), maxLines = 5)
            if (denied) Text(stringResource(R.string.pairing_setup_lan_denied), color = MaterialTheme.colorScheme.error)
            Button(onClick = {
                if (context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) onConnect(invitation)
                else permission.launch(Manifest.permission.ACCESS_LOCAL_NETWORK)
            }, enabled = !preview && invitation.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_connect)) }
        } else {
            val status = when (state.phase) {
                PairingPhase.CONNECTING -> R.string.pairing_setup_waiting
                PairingPhase.COMPARING -> R.string.pairing_setup_compare
                PairingPhase.PREPARING, PairingPhase.BIOMETRIC -> R.string.pairing_setup_preparing
                PairingPhase.SUBMITTING -> R.string.pairing_setup_submitting
                PairingPhase.COMPLETE -> R.string.pairing_setup_complete
                PairingPhase.EXPIRED -> R.string.pairing_setup_expired
                PairingPhase.CLOSING -> R.string.pairing_setup_closing
                else -> if (state.mayHaveSavedSetup) R.string.pairing_setup_incomplete else R.string.pairing_setup_failed
            }
            Text(stringResource(status), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (state.phase in setOf(PairingPhase.CONNECTING, PairingPhase.PREPARING, PairingPhase.BIOMETRIC, PairingPhase.SUBMITTING, PairingPhase.CLOSING)) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            if (state.phase == PairingPhase.CONNECTING) {
                SelectionContainer { Text(stringResource(R.string.pairing_setup_phone, state.phoneSuffix), style = MaterialTheme.typography.titleMedium) }
            }
            state.comparisonCode?.let { code ->
                if (state.phase in setOf(PairingPhase.COMPARING, PairingPhase.PREPARING, PairingPhase.BIOMETRIC)) {
                    SelectionContainer {
                        Text(code.replace(" ", "\n"),
                            style = MaterialTheme.typography.headlineLarge, fontFamily = FontFamily.Monospace)
                    }
                    Text(pluralStringResource(R.plurals.pairing_setup_remaining, seconds.toInt(), seconds))
                }
            }
            if (state.phase == PairingPhase.COMPARING) {
                Button(onClick = onCompare, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_match)) }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_mismatch)) }
            }
        }
        if (state.phase != PairingPhase.COMPARING) TextButton(onClick = onClose,
            enabled = state.phase != PairingPhase.CLOSING) {
            Text(stringResource(if (state.phase == PairingPhase.COMPLETE) R.string.pairing_setup_done else R.string.pairing_biometric_cancel))
        }
    }
}
