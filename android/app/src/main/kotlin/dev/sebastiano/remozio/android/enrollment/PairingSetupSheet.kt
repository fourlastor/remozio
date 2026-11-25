package dev.sebastiano.remozio.android.enrollment

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
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.util.concurrent.atomic.AtomicBoolean
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import dev.remozio.protocol.PairingInvitation
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.RePairInvitation
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.biometrics.PairingBiometricPrompt
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PairingSetupSheet(model: PairingViewModel, activity: ComponentActivity, testV2: Boolean = false) {
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
    PairingSetupSurface(state, model::connect, model::confirmComparison, model::expire, model::close,
        inspectRePair = model::inspectRePair, onConnectV2 = if (testV2) model::connectV2 else null,
        inspectRePairV2 = if (testV2) model::inspectRePairV2 else null)
}

/** Display-only surface. Callback ownership remains with the retained setup host. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PairingSetupSurface(state: PairingScreenState, onConnect: (String) -> Boolean, onCompare: () -> Unit,
    onExpire: () -> Unit, onClose: () -> Unit, preview: Boolean = false,
    inspectRePair: (suspend (String) -> RePairAvailability)? = null,
    onConnectV2: ((PairingInvitationV2) -> Boolean)? = null,
    inspectRePairV2: (suspend (PairingInvitationV2) -> RePairAvailability)? = null,
) {
    BoxWithConstraints {
        if (maxWidth >= 600.dp) {
            Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Surface(Modifier.widthIn(max = 560.dp).fillMaxWidth().padding(24.dp), shape = MaterialTheme.shapes.extraLarge) {
                    PairingSetupContent(state, onConnect, onCompare, onExpire, onClose, preview, Modifier.padding(24.dp), inspectRePair, onConnectV2, inspectRePairV2)
                }
            }
        } else {
            ModalBottomSheet(onDismissRequest = onClose,
                sheetState = rememberBottomSheetState(initialValue = SheetValue.Hidden, enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded))) {
                PairingSetupContent(state, onConnect, onCompare, onExpire, onClose, preview, Modifier.padding(horizontal = 24.dp).padding(bottom = 24.dp), inspectRePair, onConnectV2, inspectRePairV2)
            }
        }
    }
}

@Composable
private fun PairingSetupContent(state: PairingScreenState, onConnect: (String) -> Boolean, onCompare: () -> Unit,
    onExpire: () -> Unit, onClose: () -> Unit, preview: Boolean, modifier: Modifier,
    inspectRePair: (suspend (String) -> RePairAvailability)?,
    onConnectV2: ((PairingInvitationV2) -> Boolean)?,
    inspectRePairV2: (suspend (PairingInvitationV2) -> RePairAvailability)?,
) {
    val context = LocalContext.current
    var invitation by remember { mutableStateOf("") }
    var invitationV2 by remember { mutableStateOf<PairingInvitationV2?>(null) }
    LaunchedEffect(invitationV2) {
        val parsed = invitationV2 ?: return@LaunchedEffect
        delay(parsed.lifetimeMilliseconds.toLong())
        if (invitationV2 === parsed) invitationV2 = null
    }
    val input = invitation.trim()
    val isV1RePair = input.startsWith("remozio-repair:")
    val isV2RePair = invitationV2?.replacement != null
    val rePairInput = isV1RePair || isV2RePair
    var v1Availability by remember(input) { mutableStateOf<RePairAvailability?>(null) }
    var v2Availability by remember(invitationV2) { mutableStateOf<RePairAvailability?>(null) }
    val availability = if (isV2RePair) v2Availability else v1Availability
    val hasInvitation = if (onConnectV2 != null) invitationV2 != null else input.isNotBlank()
    val canConnect = hasInvitation && (!rePairInput || availability == RePairAvailability.ELIGIBLE)

    fun connect() {
        if (!canConnect) return
        if (onConnectV2 != null) {
            val parsed = invitationV2 ?: return
            if (onConnectV2(parsed)) invitationV2 = null
        } else if (onConnect(invitation)) {
            invitation = ""
        }
    }
    LaunchedEffect(input, state.phase, preview, inspectRePair) {
        if (isV1RePair && state.phase == PairingPhase.INPUT && !preview && inspectRePair != null) {
            delay(250)
            v1Availability = inspectRePair(input)
        }
    }
    LaunchedEffect(invitationV2, state.phase, preview, inspectRePairV2) {
        val parsed = invitationV2 ?: return@LaunchedEffect
        if (parsed.replacement != null && state.phase == PairingPhase.INPUT && !preview && inspectRePairV2 != null) {
            v2Availability = inspectRePairV2(parsed)
        }
    }
    var denied by remember { mutableStateOf(false) }
    var scannerBusy by remember { mutableStateOf(false) }
    var scannerFailed by remember { mutableStateOf(false) }
    var wrongInvitationVersion by remember { mutableStateOf(false) }
    val scannerLive = remember { AtomicBoolean(true) }
    DisposableEffect(Unit) { onDispose { scannerLive.set(false) } }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        denied = !granted
        if (granted && canConnect) connect()
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
                scannerBusy = true; scannerFailed = false; wrongInvitationVersion = false
                try {
                    val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).enableAutoZoom().build()
                    GmsBarcodeScanning.getClient(context, options).startScan()
                        .addOnSuccessListener { barcode ->
                            if (scannerLive.get()) {
                                val text = barcode.rawValue
                                if (onConnectV2 != null) {
                                    invitationV2 = text?.let { runCatching { PairingInvitationV2.importText(it) }.getOrNull() }
                                    scannerFailed = invitationV2 == null
                                } else if (text?.trimStart()?.startsWith("remozio-pairing:v2:") == true) {
                                    invitation = ""
                                    wrongInvitationVersion = true
                                } else if (text != null && runCatching {
                                    if (text.startsWith("remozio-repair:")) RePairInvitation.importText(text)
                                    else PairingInvitation.importText(text)
                                }.isSuccess) invitation = text
                                else scannerFailed = true
                            }
                        }
                        .addOnFailureListener { if (scannerLive.get()) scannerFailed = true }
                        .addOnCompleteListener { if (scannerLive.get()) scannerBusy = false }
                } catch (_: RuntimeException) { scannerBusy = false; scannerFailed = true }
            }, enabled = !preview && !scannerBusy, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_scan)) }
            if (scannerBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (scannerFailed) Text(stringResource(R.string.pairing_setup_scan_failed), color = MaterialTheme.colorScheme.error)
            if (wrongInvitationVersion) {
                Text(stringResource(R.string.pairing_setup_v2_wrong_field), color = MaterialTheme.colorScheme.error)
            }
            if (onConnectV2 != null) {
                AndroidView(factory = { viewContext -> PairingInvitationV2Editor(viewContext) { invitationV2 = it } },
                    modifier = Modifier.fillMaxWidth())
                if (invitationV2 != null) Text(stringResource(R.string.pairing_setup_invitation_ready))
            } else {
                OutlinedTextField(value = invitation, onValueChange = { text ->
                    val v2 = text.trimStart().startsWith("remozio-pairing:v2:")
                    wrongInvitationVersion = v2
                    scannerFailed = false
                    if (v2) invitation = ""
                    else if (text.length <= 16_384) invitation = text
                }, label = { Text(stringResource(R.string.pairing_setup_invitation)) },
                    modifier = Modifier.fillMaxWidth(), maxLines = 5)
            }
            if (denied) Text(stringResource(R.string.pairing_setup_lan_denied), color = MaterialTheme.colorScheme.error)
            when (availability) {
                RePairAvailability.PENDING -> Text(stringResource(R.string.pairing_repair_pending))
                RePairAvailability.UNAVAILABLE -> Text(stringResource(R.string.pairing_repair_unavailable))
                else -> Unit
            }
            if (!rePairInput || availability == RePairAvailability.ELIGIBLE) Button(onClick = {
                if (context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) connect()
                else permission.launch(Manifest.permission.ACCESS_LOCAL_NETWORK)
            }, enabled = !preview && canConnect, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(if (rePairInput) R.string.pairing_repair_connect else R.string.pairing_setup_connect))
            }
        } else {
            val status = when (state.phase) {
                PairingPhase.CONNECTING -> R.string.pairing_setup_waiting
                PairingPhase.COMPARING -> R.string.pairing_setup_compare
                PairingPhase.PREPARING, PairingPhase.BIOMETRIC -> R.string.pairing_setup_preparing
                PairingPhase.SUBMITTING -> R.string.pairing_setup_submitting
                PairingPhase.COMPLETE -> R.string.pairing_setup_complete
                PairingPhase.RECOVERY_PENDING -> R.string.pairing_repair_pending
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
                    if (state.clockSkewAdvisory) Text(stringResource(R.string.pairing_setup_clock_advisory))
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
