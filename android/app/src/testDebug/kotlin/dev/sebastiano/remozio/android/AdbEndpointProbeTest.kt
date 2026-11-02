package dev.sebastiano.remozio.android

import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Test
import kotlin.test.*

class AdbEndpointProbeTest {
    private fun address(vararg bytes: Int) = InetAddress.getByAddress(bytes.map(Int::toByte).toByteArray())

    @Test fun portInputCannotIntroduceAnAddressOrScanRange() {
        assertEquals(1, probePort("1"))
        assertEquals(5555, probePort("05555"))
        assertEquals(65535, probePort("65535"))
        listOf("", "0", "65536", "-1", "+1", " 5555", "5555 ", "1-99", "127.0.0.1:5555", "５５５５", "100000").forEach {
            assertNull(probePort(it), it)
        }
    }

    @Test fun advertisedAddressesAreEvidenceOnlyAndCannotSelectAnotherDevice() {
        val own = address(192, 168, 1, 20)
        val other = address(192, 168, 1, 21)
        assertEquals(ProbeLocalMatch.MATCH, probeLocalMatch("$ADB_CONNECT_SERVICE.", 32000, listOf(own), listOf(own)))
        assertEquals(ProbeLocalMatch.DIFFERENT_DEVICE, probeLocalMatch(ADB_CONNECT_SERVICE, 32000, listOf(other), listOf(own)))
        for (addresses in listOf(emptyList(), listOf(address(127, 0, 0, 1)), listOf(address(0, 0, 0, 0)),
            listOf(address(224, 0, 0, 1)), List(17) { own })) {
            assertEquals(ProbeLocalMatch.UNKNOWN, probeLocalMatch(ADB_CONNECT_SERVICE, 32000, addresses, listOf(own)))
        }
        assertEquals(ProbeLocalMatch.UNKNOWN, probeLocalMatch("_http._tcp", 32000, listOf(own), listOf(own)))
        assertEquals(ProbeLocalMatch.UNKNOWN, probeLocalMatch(ADB_CONNECT_SERVICE, 0, listOf(own), listOf(own)))
        assertEquals(ProbeLocalMatch.UNKNOWN, probeLocalMatch(ADB_CONNECT_SERVICE, 32000, listOf(own), emptyList()))
    }

    private open class FakeSocket : Socket() {
        var target: InetSocketAddress? = null
        var timeout = 0
        var closes = 0
        override fun connect(endpoint: SocketAddress, timeout: Int) { target = endpoint as InetSocketAddress; this.timeout = timeout }
        override fun close() { closes++ }
        override fun getInputStream(): java.io.InputStream = error("No reads permitted")
        override fun getOutputStream(): java.io.OutputStream = error("No writes permitted")
    }

    @Test fun onlyLiteralLoopbackAddressesReachTheSocketAndEveryAttemptCloses() {
        for (family in ProbeAddressFamily.entries) {
            val socket = FakeSocket()
            val probe = AdbLoopbackProbe { socket }
            assertEquals(ProbeConnectResult.CONNECTED, probe.connect(43210, family))
            val target = checkNotNull(socket.target)
            assertTrue(target.address.isLoopbackAddress)
            assertEquals(if (family == ProbeAddressFamily.IPV4) 4 else 16, target.address.address.size)
            assertEquals(43210, target.port)
            assertEquals(3000, socket.timeout)
            assertEquals(1, socket.closes)
            probe.close()
            assertEquals(1, socket.closes)
            assertEquals(ProbeConnectResult.STOPPED, probe.connect(43210, family))
        }
    }

    @Test fun failuresAreTypedWithoutExposingProviderMessagesOrRetrying() {
        val cases = listOf(ConnectException("private detail") to ProbeConnectResult.REFUSED,
            SocketTimeoutException("private detail") to ProbeConnectResult.TIMED_OUT,
            SecurityException("private detail") to ProbeConnectResult.DENIED,
            SocketException("private detail") to ProbeConnectResult.UNAVAILABLE)
        for ((error, result) in cases) {
            var attempts = 0
            val socket = object : FakeSocket() {
                override fun connect(endpoint: SocketAddress, timeout: Int) { attempts++; throw error }
            }
            assertEquals(result, AdbLoopbackProbe { socket }.connect(5555, ProbeAddressFamily.IPV4))
            assertEquals(1, attempts)
            assertEquals(1, socket.closes)
        }
    }

    @Test fun stopClosesABlockedAttemptAndPreventsLateSuccess() {
        val entered = CountDownLatch(1)
        val released = CountDownLatch(1)
        val socket = object : FakeSocket() {
            override fun connect(endpoint: SocketAddress, timeout: Int) { entered.countDown(); check(released.await(3, TimeUnit.SECONDS)) }
            override fun close() { super.close(); released.countDown() }
        }
        val probe = AdbLoopbackProbe { socket }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future = executor.submit<ProbeConnectResult> { probe.connect(5555, ProbeAddressFamily.IPV4) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            probe.close()
            assertEquals(ProbeConnectResult.STOPPED, future.get(3, TimeUnit.SECONDS))
            assertEquals(1, socket.closes)
        } finally { probe.close(); executor.shutdownNow() }
        val neverOpened = AdbLoopbackProbe { error("Must not create a socket") }
        neverOpened.close()
        assertEquals(ProbeConnectResult.STOPPED, neverOpened.connect(5555, ProbeAddressFamily.IPV4))
    }

    @Test fun syntheticListenerReceivesEofWithoutAnyAdbOrApplicationBytes() {
        val executor = Executors.newSingleThreadExecutor()
        ServerSocket(0, 1, address(127, 0, 0, 1)).use { listener ->
            listener.soTimeout = 3000
            try {
                val peer = executor.submit<Int> { listener.accept().use { socket -> socket.soTimeout = 3000; socket.getInputStream().read() } }
                assertEquals(ProbeConnectResult.CONNECTED, AdbLoopbackProbe().connect(listener.localPort, ProbeAddressFamily.IPV4))
                assertEquals(-1, peer.get(3, TimeUnit.SECONDS))
            } finally { executor.shutdownNow() }
        }
    }
}
