package dev.sebastiano.remozio.android

import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

internal const val ADB_CONNECT_SERVICE = "_adb-tls-connect._tcp"
internal enum class ProbeAddressFamily { IPV4, IPV6 }
internal enum class ProbeConnectResult { CONNECTED, REFUSED, TIMED_OUT, DENIED, UNAVAILABLE, STOPPED }
internal enum class ProbeLocalMatch { MATCH, DIFFERENT_DEVICE, UNKNOWN }

internal fun probePort(text: String): Int? = text.takeIf { it.length in 1..5 && it.all { c -> c in '0'..'9' } }
    ?.toIntOrNull()?.takeIf { it in 1..65535 }

/** Address matching is diagnostic evidence only. A service advertisement never proves adbd identity. */
internal fun probeLocalMatch(serviceType: String, port: Int, advertised: List<InetAddress>, own: List<InetAddress>): ProbeLocalMatch {
    if (serviceType.removeSuffix(".") != ADB_CONNECT_SERVICE || port !in 1..65535 || advertised.size !in 1..16 || own.isEmpty()) {
        return ProbeLocalMatch.UNKNOWN
    }
    val usable = advertised.filter { !it.isAnyLocalAddress && !it.isLoopbackAddress && !it.isMulticastAddress }
    if (usable.isEmpty()) return ProbeLocalMatch.UNKNOWN
    return if (usable.any { candidate -> own.any { it.address.contentEquals(candidate.address) } }) ProbeLocalMatch.MATCH
        else ProbeLocalMatch.DIFFERENT_DEVICE
}

/** One explicit TCP attempt. No DNS, payload read/write, ADB authentication, or retry. */
internal class AdbLoopbackProbe(private val socketFactory: () -> Socket = { Socket() }) : AutoCloseable {
    private var closed = false
    private var started = false
    private var socket: Socket? = null

    fun connect(port: Int, family: ProbeAddressFamily): ProbeConnectResult {
        require(port in 1..65535)
        val active = synchronized(this) {
            if (closed) return ProbeConnectResult.STOPPED
            check(!started)
            started = true
            socketFactory().also { socket = it }
        }
        val address = when (family) {
            ProbeAddressFamily.IPV4 -> byteArrayOf(127, 0, 0, 1)
            ProbeAddressFamily.IPV6 -> ByteArray(16).apply { this[15] = 1 }
        }
        try {
            active.connect(InetSocketAddress(InetAddress.getByAddress(address), port), 3000)
            return synchronized(this) { if (closed) ProbeConnectResult.STOPPED else ProbeConnectResult.CONNECTED }
        } catch (_: ConnectException) { return failure(ProbeConnectResult.REFUSED) }
        catch (_: SocketTimeoutException) { return failure(ProbeConnectResult.TIMED_OUT) }
        catch (_: SecurityException) { return failure(ProbeConnectResult.DENIED) }
        catch (_: java.io.IOException) { return failure(ProbeConnectResult.UNAVAILABLE) }
        finally { close() }
    }

    private fun failure(result: ProbeConnectResult) = synchronized(this) { if (closed) ProbeConnectResult.STOPPED else result }

    override fun close() {
        val previous = synchronized(this) {
            closed = true
            socket.also { socket = null }
        }
        runCatching { previous?.close() }
    }
}
