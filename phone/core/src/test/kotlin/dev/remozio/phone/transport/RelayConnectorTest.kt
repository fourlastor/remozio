package dev.remozio.phone.transport

import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.junit.Test
import kotlin.test.*

class RelayConnectorTest {
    private class Fixture(hostname: String = "localhost") : AutoCloseable {
        val certificate = HeldCertificate.Builder().commonName("synthetic-relay")
            .addSubjectAlternativeName(hostname).build()
        val server = MockWebServer().apply {
            useHttps(HandshakeCertificates.Builder().heldCertificate(certificate).build().sslSocketFactory())
            start(InetAddress.getByName("127.0.0.1"), 0)
        }
        val connector = RelayConnector(HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build().sslSocketFactory())
        val endpoint = RelayEndpoint("localhost", server.port)
        val credential = RelayAccessCredential(endpoint, "synthetic-id", "synthetic-secret")
        fun upgrade(listener: WebSocketListener) = server.enqueue(MockResponse.Builder()
            .webSocketUpgrade(listener).addHeader("Sec-WebSocket-Protocol", WebSocketUpgrade.PROTOCOL).build())
        override fun close() = server.close()
    }

    @Test fun authenticatesThenSendsScopedCredentialsAndBinaryRecords() = runBlocking {
        Fixture().use { fixture ->
            fixture.upgrade(object : WebSocketListener() {
                override fun onMessage(webSocket: WebSocket, bytes: ByteString) { webSocket.send(bytes) }
            })
            val owner = SupervisorJob()
            val carrier = fixture.connector.connect(CoroutineScope(owner), fixture.endpoint, fixture.credential)
            try {
                val payload = ByteArray(32_768) { it.toByte() }
                carrier.send(payload)
                assertContentEquals(payload, withTimeout(5_000) { carrier.receive() })
                val request = assertNotNull(fixture.server.takeRequest(5, TimeUnit.SECONDS))
                assertEquals("/remozio/approval", request.url.encodedPath)
                assertEquals("synthetic-id", request.headers["CF-Access-Client-Id"])
                assertEquals("synthetic-secret", request.headers["CF-Access-Client-Secret"])
                assertEquals(WebSocketUpgrade.PROTOCOL, request.headers["Sec-WebSocket-Protocol"])
            } finally { carrier.close(); withTimeout(5_000) { carrier.awaitClosed() }; owner.cancel() }
        }
    }

    @Test fun drainsRecordsBeforeNormalPeerClose() = runBlocking {
        Fixture().use { fixture ->
            fixture.upgrade(object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.send(byteArrayOf(1, 2, 3).toByteString())
                    webSocket.send(byteArrayOf(4, 5).toByteString())
                    webSocket.close(1000, "done")
                }
            })
            val owner = SupervisorJob()
            val carrier = fixture.connector.connect(CoroutineScope(owner), fixture.endpoint, fixture.credential)
            try {
                withTimeout(5_000) {
                    assertContentEquals(byteArrayOf(1, 2, 3), carrier.receive())
                    assertContentEquals(byteArrayOf(4, 5), carrier.receive())
                    assertNull(carrier.receive())
                }
            } finally { carrier.close(); withTimeout(5_000) { carrier.awaitClosed() }; owner.cancel() }
        }
    }

    @Test fun rejectsAnUntrustedCertificateAndWrongHostnameBeforeHttp() = runBlocking {
        for (wrongHostname in listOf(false, true)) Fixture(if (wrongHostname) "other.example" else "localhost").use { fixture ->
            val connector = if (wrongHostname) fixture.connector else RelayConnector(
                HandshakeCertificates.Builder().addTrustedCertificate(HeldCertificate.Builder().build().certificate).build().sslSocketFactory())
            val owner = SupervisorJob()
            try {
                assertFailsWith<IOException> { connector.connect(CoroutineScope(owner), fixture.endpoint, fixture.credential) }
                assertEquals(0, fixture.server.requestCount)
            } finally { owner.cancel(); withTimeout(5_000) { owner.join() } }
        }
    }

    @Test fun rejectsRedirectWithoutSendingCredentialsToAnotherEndpoint() = runBlocking {
        Fixture().use { target -> Fixture().use { fixture ->
            fixture.server.enqueue(MockResponse.Builder().code(302).addHeader("Location", target.server.url("/stolen")).build())
            val owner = SupervisorJob()
            try {
                assertFailsWith<IOException> { fixture.connector.connect(CoroutineScope(owner), fixture.endpoint, fixture.credential) }
                assertEquals(1, fixture.server.requestCount)
                assertEquals(0, target.server.requestCount)
            } finally { owner.cancel(); withTimeout(5_000) { owner.join() } }
        } }
    }

    @Test fun parentCancellationReleasesAnIdleConnection(): Unit = runBlocking {
        Fixture().use { fixture ->
            fixture.upgrade(object : WebSocketListener() {})
            val owner = SupervisorJob()
            val carrier = fixture.connector.connect(CoroutineScope(owner), fixture.endpoint, fixture.credential)
            owner.cancel()
            withTimeout(5_000) { carrier.awaitClosed(); owner.join() }
            assertFailsWith<IOException> { carrier.receive() }
        }
    }
    @Test fun oversizedFirstFrameIsRejectedBeforeItsBodyArrives(): Unit = runBlocking {
        RawPeer { socket, request ->
            val key = request.lineSequence().first { it.startsWith("Sec-WebSocket-Key:") }.substringAfter(':').trim()
            val accept = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-1")
                .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray()))
            socket.outputStream.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                "Sec-WebSocket-Accept: $accept\r\nSec-WebSocket-Protocol: ${WebSocketUpgrade.PROTOCOL}\r\n\r\n").toByteArray())
            // Declare 32769 bytes and never send the body.
            socket.outputStream.write(byteArrayOf(0x82.toByte(), 126, 0x80.toByte(), 1))
            socket.outputStream.flush()
            while (socket.inputStream.read() >= 0) { }
        }.use { peer ->
            val owner = SupervisorJob()
            val carrier = peer.connector.connect(CoroutineScope(owner), peer.endpoint, peer.credential)
            try { withTimeout(5_000) { assertFailsWith<IOException> { carrier.receive() } } }
            finally { carrier.close(); withTimeout(5_000) { carrier.awaitClosed() }; owner.cancel() }
        }
    }

    @Test fun upgradeDeadlineAndCallerCancellationCloseTheNativeSocket(): Unit = runBlocking {
        for (cancelCaller in listOf(false, true)) RawPeer { socket, _ ->
            // The HTTPS request arrives, but the relay never sends a response. The connector closes TCP before TLS, so the
            // peer sees either end of stream or a reset, depending on timing. A read timeout still fails: the socket stayed open.
            val closed = runCatching { socket.inputStream.read() }
            assertTrue(closed.getOrNull() == -1 || closed.exceptionOrNull() is java.net.SocketException, "Socket not closed: $closed")
        }.use { peer ->
            val owner = SupervisorJob()
            try {
                if (cancelCaller) {
                    val attempt = launch(Dispatchers.IO) {
                        peer.connector.connect(CoroutineScope(owner), peer.endpoint, peer.credential)
                    }
                    withTimeout(5_000) { peer.requestArrived.await() }
                    attempt.cancel()
                    withTimeout(5_000) { attempt.join() }
                } else {
                    assertFailsWith<IOException> {
                        peer.connector.connect(CoroutineScope(owner), peer.endpoint, peer.credential, timeoutMillis = 1_000)
                    }
                }
                withTimeout(5_000) { peer.finished.await() }
            } finally { owner.cancel(); withTimeout(5_000) { owner.join() } }
        }
    }

    private class RawPeer(action: (javax.net.ssl.SSLSocket, String) -> Unit) : AutoCloseable {
        private val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        private val keys = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        private val listener = keys.sslContext().serverSocketFactory.createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val endpoint = RelayEndpoint("localhost", listener.localPort)
        val credential = RelayAccessCredential(endpoint, "synthetic-id", "synthetic-secret")
        val connector = RelayConnector(HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build().sslSocketFactory())
        val requestArrived = CompletableDeferred<Unit>()
        val finished = CompletableDeferred<Unit>()
        @Volatile private var accepted: java.net.Socket? = null
        private val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        init {
            executor.submit {
                try {
                    (listener.accept() as javax.net.ssl.SSLSocket).use { socket ->
                        accepted = socket; socket.soTimeout = 6_000
                        val request = StringBuilder()
                        while (!request.endsWith("\r\n\r\n")) {
                            val byte = socket.inputStream.read()
                            check(byte >= 0 && request.length < 16_384)
                            request.append(byte.toChar())
                        }
                        requestArrived.complete(Unit)
                        action(socket, request.toString())
                    }
                    finished.complete(Unit)
                } catch (failure: Throwable) { requestArrived.completeExceptionally(failure); finished.completeExceptionally(failure) }
            }
        }
        override fun close() {
            listener.close(); accepted?.close(); executor.shutdownNow()
            check(executor.awaitTermination(7, TimeUnit.SECONDS))
        }
    }

}
