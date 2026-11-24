package dev.sebastiano.remozio.android.transport

import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.PinnedTLSClient
import dev.remozio.phone.transport.TLSRecordSession
import java.net.InetAddress
import java.net.InetSocketAddress
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidPinnedTLSClientTest {
    @Test fun platformTlsHandshakesAndExchangesBytesThroughThePinnedClient(): Unit = runBlocking {
        AndroidTlsTestFixture.create().use { fixture ->
            exchangeWithSoftwareServer(fixture)
        }
    }

    private suspend fun exchangeWithSoftwareServer(fixture: AndroidTlsTestFixture) = coroutineScope {
        val loopback = InetAddress.getByName("127.0.0.1")
        val protocol = "remozio-test/1"
        fixture.listen(loopback).use { listener ->
            val serverExchange = async(Dispatchers.IO) {
                (listener.accept() as SSLSocket).use { socket ->
                    fixture.handshake(socket, protocol)
                    assertEquals(42, socket.inputStream.read())
                    socket.outputStream.write(43)
                    socket.outputStream.flush()
                }
            }
            val carrier = DirectTCPConnector().connect(this, InetSocketAddress(loopback, listener.localPort))
            val engine = PinnedTLSClient(arrayOf(fixture.clientKeys), fixture.serverCertificate.publicKey.encoded, protocol, 65_536)
            val session = TLSRecordSession(this, engine, carrier)
            try {
                withTimeout(10_000) {
                    session.awaitOpen()
                    session.send(byteArrayOf(42))
                    assertArrayEquals(byteArrayOf(43), session.receive())
                    serverExchange.await()
                }
            } finally {
                session.closeAndJoin()
            }
        }
    }
}
