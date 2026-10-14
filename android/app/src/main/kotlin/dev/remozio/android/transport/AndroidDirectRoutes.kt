package dev.remozio.android.transport

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.nsd.DiscoveryRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.PatternMatcher
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.DirectTCPConnector
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow

/** Names and addresses are untrusted hints. The channel connector verifies the enrolled keys on every attempt. */
internal fun androidDirectRoutes(context: Context, macID: ByteArray): Flow<ApprovalCarrierRoute> {
    require(macID.size == 16)
    val name = "Remozio-" + macID.joinToString("") { "%02x".format(it.toInt() and 255) }
    return androidNamedRoutes(context, "_remozio._tcp.", name)
}

/** Pairing hints use their separate service type and scope. Only pinned setup TLS authenticates the endpoint. */
internal fun androidPairingRoutes(context: Context, macID: ByteArray, accountID: ByteArray): Flow<ApprovalCarrierRoute> {
    require(macID.size == 16 && accountID.size == 16)
    fun id(bytes: ByteArray) = android.util.Base64.encodeToString(bytes,
        android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
    return androidNamedRoutes(context, "_remozio-pairing._tcp.", "R-${id(macID)}-${id(accountID)}")
}

private fun androidNamedRoutes(context: Context, type: String, name: String): Flow<ApprovalCarrierRoute> {
    val app = context.applicationContext
    return callbackFlow {
        if (app.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) {
            close(); return@callbackFlow
        }
        val manager = app.getSystemService(NsdManager::class.java)
        if (manager == null) { close(); return@callbackFlow }
        val executor = app.mainExecutor
        val stopped = AtomicBoolean(false)
        val callbacks = mutableListOf<NsdManager.ServiceInfoCallback>()
        val registrations = mutableSetOf<Pair<String, android.net.Network?>>()
        val emitted = mutableSetOf<Pair<android.net.Network, InetSocketAddress>>()
        var started = false
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) { }
            override fun onDiscoveryStopped(serviceType: String) { close() }
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) { close() }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) { close() }
            override fun onServiceLost(serviceInfo: NsdServiceInfo) { }
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                if (app.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) { close(); return }
                if (stopped.get() || serviceInfo.serviceName != name || registrations.size >= 8) return
                if (!registrations.add(serviceInfo.serviceName to serviceInfo.network)) return
                val callback = object : NsdManager.ServiceInfoCallback {
                    override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) { }
                    override fun onServiceInfoCallbackUnregistered() { }
                    override fun onServiceLost() { }
                    override fun onServiceUpdated(info: NsdServiceInfo) {
                        if (stopped.get() || info.serviceName != name || info.port !in 1..65_535) return
                        val network = info.network ?: return
                        for (address in info.hostAddresses.take(4)) {
                            if (emitted.size >= 32 || address.isAnyLocalAddress || address.isMulticastAddress) continue
                            val endpoint = InetSocketAddress(address, info.port)
                            if (!emitted.add(network to endpoint)) continue
                            trySend(ApprovalCarrierRoute { parent ->
                                DirectTCPConnector { network.socketFactory.createSocket() }.connect(parent, endpoint)
                            })
                        }
                    }
                }
                try {
                    manager.registerServiceInfoCallback(serviceInfo, executor, callback)
                    callbacks += callback
                } catch (_: RuntimeException) { }
            }
        }
        executor.execute {
            if (app.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) {
                close(); return@execute
            }
            if (!stopped.get()) try {
                val request = DiscoveryRequest.Builder(type)
                    .setFlags(DiscoveryRequest.FLAG_NO_PICKER)
                    .setServiceNameFilter(PatternMatcher(name, PatternMatcher.PATTERN_LITERAL)).build()
                manager.discoverServices(request, executor, listener)
                started = true
            } catch (_: RuntimeException) { close() }
        }
        awaitClose {
            stopped.set(true)
            executor.execute {
                callbacks.forEach { runCatching { manager.unregisterServiceInfoCallback(it) } }
                if (started) runCatching { manager.stopServiceDiscovery(listener) }
            }
        }
    }.buffer(8)
}
