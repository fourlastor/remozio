package dev.remozio.phone.transport

import dev.remozio.protocol.ChannelOffer
import dev.remozio.protocol.ChannelRole
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingKey
import dev.remozio.protocol.PairingRecoveryFrame
import dev.remozio.protocol.PairingReplacement
import dev.remozio.protocol.PairingTranscript
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

/** The JVM fixture uses real TLS with software keys and injects exporter bytes. */
class PairingRecoveryConnectorTest {
    private class BrokenRoute : EncryptedRecordTransport {
        var closed = false
        var joined = false
        override val maximumMessageBytes = 32_768
        override suspend fun send(ciphertext: ByteArray) { throw IOException("Fixture route failed") }
        override suspend fun receive(): ByteArray? = null
        override fun close() { closed = true }
        override suspend fun awaitClosed() { check(closed); joined = true }
    }

    private class Provider(private val available: Boolean = true, private val exports: Boolean = true) : PairingRecoveryTLSProvider {
        val engines = CopyOnWriteArrayList<SSLEngine>()
        var exportCalls = 0
        override fun configure(engine: SSLEngine) {
            engines.add(engine)
            if (!available) throw IOException("Fixture provider unsupported")
        }
        override fun export(engine: SSLEngine): ByteArray? {
            exportCalls++
            return if (exports) ByteArray(32) { 7 } else null
        }
    }

    private class Fixture(alpn: String = PairingRecoveryFrame.APPLICATION_PROTOCOL) : AutoCloseable {
        private val serverKey = HeldCertificate.Builder().ecdsa256().commonName("recovery-fixture").build()
        private val candidateKey = HeldCertificate.Builder().ecdsa256().commonName("candidate-fixture").build()
        val keys = ClientTLSKeyManager(candidateKey.keyPair.private, arrayOf(candidateKey.certificate))
        val pin = serverKey.keyPair.public.encoded
        val transcript = transcript(serverKey, candidateKey)
        private val server = HandshakeCertificates.Builder().heldCertificate(serverKey)
            .addTrustedCertificate(candidateKey.certificate).build().sslContext().serverSocketFactory
            .createServerSocket(0, 4, InetAddress.getLoopbackAddress()) as SSLServerSocket
        init {
            server.soTimeout = 5_000
            server.enabledProtocols = arrayOf("TLSv1.3")
            server.needClientAuth = true
            server.sslParameters = server.sslParameters.apply { applicationProtocols = arrayOf(alpn) }
        }
        val route = ApprovalCarrierRoute { owner ->
            DirectTCPConnector().connect(owner, InetSocketAddress(server.inetAddress, server.localPort))
        }

        fun accept(exchange: Boolean) {
            (server.accept() as SSLSocket).use { socket ->
                socket.soTimeout = 5_000
                socket.startHandshake()
                if (!exchange) {
                    val received = runCatching { socket.inputStream.read() }.getOrNull()
                    check(received == null || received == -1)
                    return
                }
                val input = java.io.DataInputStream(socket.inputStream)
                val output = java.io.DataOutputStream(socket.outputStream)
                fun read(): PairingRecoveryFrame {
                    val length = input.readInt()
                    check(length in 1..PairingRecoveryFrame.MAXIMUM_BYTES)
                    return PairingRecoveryFrame.decode(ByteArray(length).also(input::readFully))
                }
                fun send(frame: PairingRecoveryFrame) {
                    val bytes = frame.encode()
                    output.writeInt(bytes.size)
                    output.write(bytes)
                    output.flush()
                }
                check(read() is PairingRecoveryFrame.Lookup)
                send(PairingRecoveryFrame.Challenge(ByteArray(32) { 8 }))
                check(read() is PairingRecoveryFrame.Proof)
                send(PairingRecoveryFrame.Refused)
                // Let the client dispose of this session before opening the next one.
                runCatching { input.read() }
            }
        }

        override fun close() { server.close(); keys.close() }

        companion object {
            private fun transcript(server: HeldCertificate, candidate: HeldCertificate): PairingTranscript {
                fun id(byte: Byte) = ByteArray(16) { byte }
                fun point(key: HeldCertificate) = key.keyPair.public.encoded.takeLast(65).toByteArray()
                fun distinct() = HeldCertificate.Builder().ecdsa256().build()
                val scope = ChannelScope(id(1), id(2), id(3), id(4))
                fun offer(role: ChannelRole, byte: Byte) = ChannelOffer(role, scope, ByteArray(32) { byte },
                    setOf(1uL), emptyList(), emptySet())
                return PairingTranscript(id(6), ByteArray(32) { 7 }, offer(ChannelRole.PHONE, 8), offer(ChannelRole.MAC, 9),
                    1u, 1u, point(distinct()), point(server), PairingKey(id(10), point(candidate)),
                    PairingKey(id(11), point(distinct())), PairingKey(id(12), point(distinct())), ByteArray(32) { 13 },
                    PairingReplacement(id(3), id(5)), id(14), 1_000u, 2_000u)
            }
        }
    }

    @Test fun failedDirectCarrierJoinsBeforeRelayAndEachAttemptGetsFreshTls() = runBlocking<Unit> {
        Fixture().use { fixture ->
            val server = launch(Dispatchers.IO) { repeat(2) { fixture.accept(exchange = true) } }
            val provider = Provider()
            val broken = BrokenRoute()
            var relayOpens = 0
            val relay = ApprovalCarrierRoute { owner ->
                assertTrue(broken.joined)
                relayOpens++
                fixture.route.open(owner)
            }
            val direct = PairingRecoveryChannel.connect(this, flowOf(ApprovalCarrierRoute { broken }), relay, 2_000,
                fixture.keys, fixture.pin, fixture.transcript, provider, {}, {})
            try { assertEquals(PairingRecoveryFrame.Refused, withTimeout(3_000) { direct.lookup() }) }
            finally { direct.closeAndJoin() }
            val withoutLan = PairingRecoveryChannel.connect(this, emptyFlow(), relay, 2_000,
                fixture.keys, fixture.pin, fixture.transcript, provider, {}, {})
            try { assertEquals(PairingRecoveryFrame.Refused, withTimeout(3_000) { withoutLan.lookup() }) }
            finally { withoutLan.closeAndJoin() }
            withTimeout(5_000) { server.join() }
            assertEquals(2, relayOpens)
            assertEquals(3, provider.engines.size)
            assertNotSame(provider.engines[1], provider.engines[2])
        }
    }

    @Test fun unsupportedAndFailingExportersCloseTheirCarrierBeforeReturning() = runBlocking<Unit> {
        Fixture().use { fixture ->
            val unsupported = Provider(available = false)
            val broken = BrokenRoute()
            assertFails {
                PairingRecoveryChannel.connect(this, emptyFlow(), ApprovalCarrierRoute { broken }, 1_000,
                    fixture.keys, fixture.pin, fixture.transcript, unsupported, {}, {})
            }
            assertTrue(broken.joined)
            val server = launch(Dispatchers.IO) { fixture.accept(exchange = false) }
            val failing = Provider(exports = false)
            var joined = false
            val route = ApprovalCarrierRoute { owner ->
                val carrier = fixture.route.open(owner)
                object : EncryptedRecordTransport by carrier {
                    override suspend fun awaitClosed() { carrier.awaitClosed(); joined = true }
                }
            }
            assertFails {
                PairingRecoveryChannel.connect(this, emptyFlow(), route, 1_000, fixture.keys, fixture.pin,
                    fixture.transcript, failing, {}, {})
            }
            withTimeout(5_000) { server.join() }
            assertTrue(joined)
            assertEquals(1, failing.exportCalls)
        }
    }

    @Test fun aCompanionWithoutRecoveryAlpnCannotStartALookup() = runBlocking<Unit> {
        Fixture("remozio-receipt/1").use { fixture ->
            val server = launch(Dispatchers.IO) { runCatching { fixture.accept(exchange = false) } }
            val provider = Provider()
            assertFails {
                PairingRecoveryChannel.connect(this, flowOf(fixture.route), null, 2_000, fixture.keys, fixture.pin,
                    fixture.transcript, provider, {}, {})
            }
            withTimeout(5_000) { server.join() }
            assertFalse(provider.engines.isEmpty())
        }
    }
}
