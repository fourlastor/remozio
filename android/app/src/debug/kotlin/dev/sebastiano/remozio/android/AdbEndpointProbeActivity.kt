package dev.sebastiano.remozio.android

import android.net.nsd.DiscoveryRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import java.net.InetAddress
import java.net.NetworkInterface
import kotlinx.coroutines.*
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Debug-only feasibility probe. It cannot enable debugging, pair a host, or send an ADB command. */
class AdbEndpointProbeActivity : ComponentActivity() {
    private enum class Work { IDLE, PICKING, CONNECTING }
    private val operation = ProbeOperation()
    private var work by mutableStateOf(Work.IDLE)
    private var port by mutableStateOf("")
    private var result by mutableStateOf("")
    private var job: Job? = null
    private var socketProbe: AdbLoopbackProbe? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        result = getString(R.string.adb_probe_initial)
        setContent {
            RemozioTheme {
                Scaffold { insets ->
                    Column(Modifier.fillMaxSize().padding(insets).imePadding().verticalScroll(rememberScrollState())
                        .padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Column(Modifier.widthIn(max = 640.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text(stringResource(R.string.adb_probe_title), style = MaterialTheme.typography.headlineLarge)
                            Text(stringResource(R.string.adb_probe_description))
                            Card(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text(stringResource(R.string.adb_probe_discovery_title), style = MaterialTheme.typography.titleMedium)
                                    Text(stringResource(R.string.adb_probe_discovery_help))
                                    Button(enabled = work == Work.IDLE, onClick = ::pick) {
                                        Text(stringResource(R.string.adb_probe_pick))
                                    }
                                }
                            }
                            Text(stringResource(R.string.adb_probe_manual_title), style = MaterialTheme.typography.titleMedium)
                            OutlinedTextField(port, onValueChange = { if (it.length <= 5 && it != port) {
                                port = it
                                result = getString(R.string.adb_probe_initial)
                            } },
                                modifier = Modifier.fillMaxWidth(), enabled = work == Work.IDLE, singleLine = true,
                                label = { Text(stringResource(R.string.adb_probe_port)) },
                                supportingText = { Text(stringResource(R.string.adb_probe_manual_help)) },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                isError = port.isNotEmpty() && probePort(port) == null)
                            FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                ProbeAddressFamily.entries.forEach { family ->
                                    OutlinedButton(enabled = work == Work.IDLE && probePort(port) != null, onClick = { connect(family) }) {
                                        Text(stringResource(if (family == ProbeAddressFamily.IPV4) R.string.adb_probe_ipv4 else R.string.adb_probe_ipv6))
                                    }
                                }
                            }
                            Text(result, Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                            if (work != Work.IDLE) OutlinedButton(onClick = ::stop) { Text(stringResource(R.string.adb_probe_stop)) }
                            TextButton(onClick = { finish() }) { Text(stringResource(R.string.probe_close)) }
                        }
                    }
                }
            }
        }
    }

    override fun onStop() {
        // The system picker can cover this activity. It never starts a socket test automatically.
        if (work == Work.CONNECTING) stop()
        super.onStop()
    }

    override fun onDestroy() { stop(); super.onDestroy() }

    private fun stop() {
        operation.invalidate()
        socketProbe?.close()
        socketProbe = null
        job?.cancel()
        job = null
        work = Work.IDLE
        result = getString(R.string.adb_probe_stopped)
    }

    private fun complete(token: Any, message: String, selectedPort: Int? = null) {
        if (!operation.complete(token)) return
        if (selectedPort != null) port = selectedPort.toString()
        work = Work.IDLE
        job = null
        result = message
    }

    private fun pick() {
        if (work != Work.IDLE) return
        val token = operation.begin()
        work = Work.PICKING
        result = getString(R.string.adb_probe_picking)
        job = lifecycleScope.launch {
            try {
                val service = withTimeout(90_000) { selectService() }
                if (service == null) complete(token, getString(R.string.adb_probe_picker_cancelled))
                else {
                    val match = withContext(Dispatchers.IO) {
                        val own = NetworkInterface.getNetworkInterfaces()?.toList()?.flatMap { it.inetAddresses.toList() }.orEmpty()
                        probeLocalMatch(service.type, service.port, service.addresses, own)
                    }
                    val message = when (match) {
                        ProbeLocalMatch.MATCH -> getString(R.string.adb_probe_local_candidate, service.port)
                        ProbeLocalMatch.DIFFERENT_DEVICE -> getString(R.string.adb_probe_other_device)
                        ProbeLocalMatch.UNKNOWN -> getString(R.string.adb_probe_unverified)
                    }
                    complete(token, message, service.port.takeIf { match == ProbeLocalMatch.MATCH })
                }
            } catch (_: TimeoutCancellationException) { complete(token, getString(R.string.adb_probe_picker_timeout)) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (error: DiscoveryFailure) { complete(token, getString(R.string.adb_probe_discovery_failed, error.code)) }
            catch (_: Exception) { complete(token, getString(R.string.adb_probe_unverified)) }
        }
    }

    private class Service(val type: String, val port: Int, val addresses: List<InetAddress>)
    private class DiscoveryFailure(val code: Int) : Exception()

    private suspend fun selectService(): Service? = suspendCancellableCoroutine { continuation ->
        val nsd = getSystemService(NsdManager::class.java)
        val listener = object : NsdManager.ServiceInfoCallback {
            override fun onServiceUpdated(info: NsdServiceInfo) {
                if (!continuation.isActive) return
                val addresses = info.hostAddresses
                if (addresses.size !in 1..16) continuation.resume(Service("", 0, emptyList()))
                else continuation.resume(Service(info.serviceType, info.port, addresses.toList()))
            }
            override fun onServiceInfoCallbackRegistrationFailed(code: Int) {
                if (continuation.isActive) continuation.resumeWithException(DiscoveryFailure(code))
            }
            override fun onServiceInfoCallbackUnregistered() { if (continuation.isActive) continuation.resume(null) }
            override fun onServiceLost() { }
        }
        try {
            nsd.registerServiceInfoCallback(DiscoveryRequest.Builder(ADB_CONNECT_SERVICE)
                .setFlags(DiscoveryRequest.FLAG_SHOW_PICKER).build(), mainExecutor, listener)
            // API 37 picker registrations end after selection. Explicit cancellation also releases them.
            continuation.invokeOnCancellation { runCatching { nsd.unregisterServiceInfoCallback(listener) } }
        } catch (error: Exception) { if (continuation.isActive) continuation.resumeWithException(error) }
    }

    private fun connect(family: ProbeAddressFamily) {
        if (work != Work.IDLE) return
        val selectedPort = probePort(port) ?: return
        val token = operation.begin()
        val probe = AdbLoopbackProbe().also { socketProbe = it }
        work = Work.CONNECTING
        result = getString(R.string.adb_probe_connecting)
        job = lifecycleScope.launch {
            try {
                val response = withContext(Dispatchers.IO) { probe.connect(selectedPort, family) }
                val label = when (response) {
                    ProbeConnectResult.CONNECTED -> R.string.adb_probe_connected
                    ProbeConnectResult.REFUSED -> R.string.adb_probe_refused
                    ProbeConnectResult.TIMED_OUT -> R.string.adb_probe_timeout
                    ProbeConnectResult.DENIED -> R.string.adb_probe_denied
                    ProbeConnectResult.UNAVAILABLE -> R.string.adb_probe_unavailable
                    ProbeConnectResult.STOPPED -> R.string.adb_probe_stopped
                }
                complete(token, getString(R.string.adb_probe_result_scope,
                    if (family == ProbeAddressFamily.IPV4) "127.0.0.1" else "::1", selectedPort, getString(label)))
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { complete(token, getString(R.string.adb_probe_unavailable)) }
            finally { probe.close(); if (socketProbe === probe) socketProbe = null }
        }
    }
}
