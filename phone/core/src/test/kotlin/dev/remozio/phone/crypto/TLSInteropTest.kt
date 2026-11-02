package dev.remozio.phone.crypto

import dev.remozio.protocol.*
import dev.remozio.phone.audit.*
import dev.remozio.phone.transport.PhoneAuditChannel
import dev.remozio.phone.transport.PhoneAuditResult
import javax.crypto.KeyGenerator
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PhoneRoutingChannel
import dev.remozio.phone.transport.PhoneRoutingChallenge
import dev.remozio.phone.transport.PhoneRoutingResult
import kotlinx.serialization.json.JsonObject
import dev.remozio.phone.requests.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.flow.first
import dev.remozio.phone.transport.ApprovalChannelConnector
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.DirectTCPConnector
import dev.remozio.phone.transport.EnrolledChannelPurpose
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flowOf
import java.net.InetSocketAddress
import dev.remozio.phone.transport.NegotiatedTLSChannel
import dev.remozio.phone.transport.RelayAccessCredential
import dev.remozio.phone.transport.EncryptedRecordTransport
import dev.remozio.phone.transport.TLSRecordSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import dev.remozio.phone.transport.ClientTLSKeyManager
import dev.remozio.phone.transport.PinnedTLSClient
import dev.remozio.phone.transport.TLSClientProgress
import dev.remozio.phone.transport.TLSClientState
import java.nio.ByteBuffer
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.int
import org.junit.Assert.*
import org.junit.Test

/** Disposable keys and loopback sockets only. This is not an Android Keystore or production relay test. */
class TLSInteropTest {
    @Test fun mutualTLS13PreservesPayloadThroughFragmentingOpaqueRelay(): Unit = Fixture().use { f ->
        for (payload in listOf(ByteArray(0), "synthetic-remozio-private-request-contents".repeat(1_500).toByteArray())) {
            Relay(f.port).use { relay ->
                f.connect(relay.port).use { socket ->
                    socket.startHandshake()
                    assertEquals("TLSv1.3", socket.session.protocol)
                    assertEquals("remozio-experiment/1", socket.applicationProtocol)
                    assertArrayEquals(payload, exchange(socket, payload))
                }
                if (payload.isNotEmpty()) {
                    val captured = relay.capture()
                    assertTrue(captured.size > payload.size)
                    assertFalse(String(captured, Charsets.ISO_8859_1).contains("synthetic-remozio-private-request-contents"))
                }
            }
        }
    }

    @Test fun wrongServerPinFailsBeforeApplicationData(): Unit = Fixture().use { f ->
        f.connect(f.port, serverPin = f.phone.certificate).use { socket ->
            assertThrows(IOException::class.java) { socket.startHandshake() }
        }
    }

    @Test fun wrongOrMissingClientIdentityCannotReceiveAnEcho(): Unit = Fixture().use { f ->
        for (identity in listOf(f.mac, null)) {
            f.connect(f.port, identity = identity).use { socket ->
                assertThrows(IOException::class.java) { socket.startHandshake(); exchange(socket, byteArrayOf(1, 2, 3)) }
            }
        }
    }

    @Test fun expiredAndFutureClientCertificatesCannotReceiveAnEcho() {
        for (startDate in listOf("-2d", "+2d")) Fixture(phoneStartDate = startDate).use { f ->
            f.connect(f.port).use { socket ->
                assertThrows(IOException::class.java) { socket.startHandshake(); exchange(socket, byteArrayOf(1)) }
            }
        }
    }

    @Test fun downgradeAndWrongApplicationProtocolFail(): Unit = Fixture().use { f ->
        f.connect(f.port).use { socket ->
            socket.enabledProtocols = arrayOf("TLSv1.2")
            assertThrows(IOException::class.java) { socket.startHandshake() }
        }
        f.connect(f.port).use { socket ->
            socket.sslParameters = socket.sslParameters.apply { applicationProtocols = arrayOf("unrelated/1") }
            assertThrows(IOException::class.java) { socket.startHandshake(); exchange(socket, byteArrayOf(1)) }
        }
    }

    @Test fun relayTamperingCannotProduceApplicationReply(): Unit = Fixture().use { f ->
        Relay(f.port).use { relay ->
            f.connect(relay.port).use { socket ->
                socket.startHandshake()
                relay.tamper.set(true)
                assertThrows(IOException::class.java) { exchange(socket, "synthetic-tamper-target".toByteArray()) }
                assertTrue(relay.changed.get())
            }
        }
    }

    @Test fun oversizedFrameIsRejectedWithoutAnEcho(): Unit = Fixture().use { f ->
        f.connect(f.port).use { socket ->
            socket.startHandshake()
            DataOutputStream(socket.outputStream).apply { writeInt(65_537); flush() }
            assertThrows(IOException::class.java) { DataInputStream(socket.inputStream).readInt() }
        }
    }

    @Test fun controllerPipeClosureStopsTheNativeListener(): Unit = Fixture().use { f ->
        f.closeControllerPipe()
        assertTrue(f.waitForPeerExit())
    }

    @Test fun innerTLSCrossesAnIndependentlyAuthenticatedWebSocketCarrier(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port).use { relay ->
            val payload = "synthetic-inner-private-request".repeat(2_000).toByteArray()
            f.connect(relay.port).use { socket ->
                socket.startHandshake()
                assertTrue(relay.outerAuthenticated.get())
                assertEquals("TLSv1.3", socket.session.protocol)
                assertArrayEquals(payload, exchange(socket, payload))
            }
            val visible = relay.capture()
            assertTrue(visible.size > payload.size)
            assertFalse(String(visible, Charsets.ISO_8859_1).contains("synthetic-inner-private-request"))
        }
    }

    @Test fun validOuterTLSDoesNotOverrideTheInnerMacPin(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port).use { relay ->
            f.connect(relay.port, serverPin = f.phone.certificate).use { socket ->
                assertThrows(IOException::class.java) { socket.startHandshake() }
                assertTrue(relay.outerAuthenticated.get())
            }
        }
    }

    @Test fun outerCarrierTrustFailureDoesNotReachTheInnerPeer(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port, trustOuter = false).use { relay ->
            f.connect(relay.port).use { socket ->
                assertThrows(IOException::class.java) { socket.startHandshake() }
                assertFalse(relay.outerAuthenticated.get())
                assertEquals(0, relay.capture().size)
            }
        }
    }

    @Test fun authenticatedWebSocketRelayCannotAlterInnerTraffic(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port).use { relay ->
            f.connect(relay.port).use { socket ->
                socket.startHandshake(); relay.tamper.set(true)
                assertThrows(IOException::class.java) { exchange(socket, "synthetic-inner-tamper".toByteArray()) }
                assertTrue(relay.outerAuthenticated.get()); assertTrue(relay.changed.get())
            }
        }
    }

    @Test fun engineExchangesFragmentedRecordsWithTheNativePeer(): Unit = Fixture().use { f ->
        for (receiveChunkSize in listOf(1, 32_768)) engineExchange(f, receiveChunkSize)
    }

    private fun engineExchange(f: Fixture, receiveChunkSize: Int) {
        Relay(f.port).use { relay ->
            f.engine().use { engine ->
                Socket("127.0.0.1", relay.port).use { socket ->
                    socket.soTimeout = 4_000
                    val plaintext = ByteArrayOutputStream()
                    fun deliver(batch: TLSClientProgress) {
                        batch.encrypted.forEach { socket.outputStream.write(it.copyBytes()) }
                        socket.outputStream.flush()
                        batch.plaintext.forEach { plaintext.write(it.copyBytes()) }
                    }
                    fun receive() {
                        val buffer = ByteArray(receiveChunkSize)
                        val count = socket.inputStream.read(buffer)
                        if (count < 0) { engine.endOfInput(); error("Unexpected EOF") }
                        deliver(engine.receive(buffer.copyOf(count)))
                    }
                    deliver(engine.start())
                    while (engine.state() == TLSClientState.HANDSHAKING) {
                        assertEquals(0, plaintext.size())
                        receive()
                    }
                    assertEquals(TLSClientState.OPEN, engine.state())
                    val payload = "synthetic-engine-private-data".repeat(2_000).toByteArray()
                    val frame = ByteBuffer.allocate(payload.size + 4).putInt(payload.size).put(payload).array()
                    var sent = 0
                    while (sent < frame.size) {
                        val batch = engine.send(frame.copyOfRange(sent, minOf(sent + 32_768, frame.size)))
                        sent += batch.consumedPlaintextBytes
                        deliver(batch)
                        if (batch.consumedPlaintextBytes == 0) receive()
                    }
                    while (plaintext.size() < frame.size) receive()
                    assertArrayEquals(frame, plaintext.toByteArray())
                    assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("synthetic-engine-private-data"))
                }
            }
        }
    }

    @Test fun engineRejectsWrongPinClientIdentityAndApplicationProtocol(): Unit = Fixture().use { f ->
        for (engine in listOf(f.engine(pin = f.phone.certificate), f.engine(protocol = "unrelated/1"), f.engine(identity = f.mac))) {
            engine.use {
                Socket("127.0.0.1", f.port).use { socket ->
                    socket.soTimeout = 4_000
                    assertThrows(IOException::class.java) {
                        var batch = engine.start()
                        while (true) {
                            assertTrue(batch.plaintext.isEmpty())
                            batch.encrypted.forEach { socket.outputStream.write(it.copyBytes()) }
                            socket.outputStream.flush()
                            val buffer = ByteArray(4_096)
                            val count = socket.inputStream.read(buffer)
                            batch = if (count < 0) engine.endOfInput() else engine.receive(buffer.copyOf(count))
                        }
                    }
                    assertEquals(TLSClientState.FAILED, engine.state())
                }
            }
        }
    }

    @Test fun engineLimitsAndAbortReleaseTheChannel(): Unit = Fixture().use { f ->
        f.engine(budget = 1).use { engine ->
            assertThrows(IOException::class.java) { engine.start() }
            assertEquals(TLSClientState.FAILED, engine.state())
        }
        f.engine().use { engine ->
            assertThrows(IllegalStateException::class.java) { engine.send(byteArrayOf(1)) }
            val start = engine.start()
            assertEquals(0, start.consumedPlaintextBytes)
            assertTrue(start.plaintext.isEmpty())
            assertThrows(IOException::class.java) { engine.receive(ByteArray(32_769)) }
            assertEquals(TLSClientState.FAILED, engine.state())
        }
        f.engine().use { engine ->
            engine.start()
            assertThrows(IOException::class.java) { engine.endOfInput() }
            assertEquals(TLSClientState.FAILED, engine.state())
            engine.close()
            assertEquals(TLSClientState.CLOSED, engine.state())
            assertThrows(IllegalStateException::class.java) { engine.receive(byteArrayOf()) }
        }
    }

    @Test fun sessionOwnsAFragmentedNativeTlsExchange(): Unit = Fixture().use { f ->
        runBlocking {
            withTimeout(8_000) {
                val socket = Socket("127.0.0.1", f.port).apply { soTimeout = 4_000 }
                val carrier = SocketRecords(socket)
                val engine = f.engine()
                val session = TLSRecordSession(this, engine, carrier, handshakeTimeoutMillis = 4_000)
                try {
                    session.awaitOpen()
                    val payload = "synthetic-owned-session".repeat(2_500).toByteArray()
                    val frame = ByteBuffer.allocate(payload.size + 4).putInt(payload.size).put(payload).array()
                    val reply = async {
                        val collected = ByteArrayOutputStream()
                        while (collected.size() < frame.size) {
                            val chunk = requireNotNull(session.receive())
                            check(collected.size() + chunk.size <= frame.size)
                            collected.write(chunk)
                        }
                        collected.toByteArray()
                    }
                    var offset = 0
                    while (offset < frame.size) {
                        val end = minOf(offset + 16_384, frame.size)
                        session.send(frame.copyOfRange(offset, end))
                        offset = end
                    }
                    assertArrayEquals(frame, reply.await())
                } finally { session.closeAndJoin() }
                assertTrue(socket.isClosed)
                assertEquals(TLSClientState.CLOSED, engine.state())
            }
        }
    }

    @Test fun sessionRejectsWrongPinAndReleasesTheNativeConnection(): Unit = Fixture().use { f ->
        runBlocking {
            withTimeout(8_000) {
                val socket = Socket("127.0.0.1", f.port).apply { soTimeout = 4_000 }
                val engine = f.engine(pin = f.phone.certificate)
                val session = TLSRecordSession(this, engine, SocketRecords(socket), handshakeTimeoutMillis = 4_000)
                try {
                    var rejected = false
                    try { session.awaitOpen() } catch (_: IOException) { rejected = true }
                    assertTrue(rejected)
                } finally { session.closeAndJoin() }
                assertTrue(socket.isClosed)
                assertEquals(TLSClientState.CLOSED, engine.state())
            }
        }
    }

    @Test fun ownedSessionCrossesThePlatformHttpsRelayConnector(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
            runBlocking {
                withTimeout(10_000) {
                    val carrier = relay.connector.connect(this, relay.endpoint,
                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                    val engine = f.engine()
                    val session = TLSRecordSession(this, engine, carrier, handshakeTimeoutMillis = 4_000)
                    try {
                        session.awaitOpen()
                        val payload = "synthetic-connector-private".repeat(2_000).toByteArray()
                        val frame = ByteBuffer.allocate(payload.size + 4).putInt(payload.size).put(payload).array()
                        val reply = async {
                            val collected = ByteArrayOutputStream()
                            while (collected.size() < frame.size) collected.write(requireNotNull(session.receive()))
                            collected.toByteArray()
                        }
                        var offset = 0
                        while (offset < frame.size) {
                            val end = minOf(offset + 16_384, frame.size)
                            session.send(frame.copyOfRange(offset, end)); offset = end
                        }
                        assertArrayEquals(frame, reply.await())
                        assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("synthetic-connector-private"))
                    } finally { session.closeAndJoin() }
                    assertEquals(TLSClientState.CLOSED, engine.state())
                }
            }
        }
    }

    @Test fun negotiatedHostsExchangeSessionBoundMessagesThroughTheHttpsRelay(): Unit = Fixture(negotiate = true).use { f ->
        WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
            runBlocking {
                withTimeout(10_000) {
                    val carrier = relay.connector.connect(this, relay.endpoint,
                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                    val session = TLSRecordSession(this, f.engine(), carrier, handshakeTimeoutMillis = 4_000)
                    val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
                    try {
                        val channel = NegotiatedTLSChannel.connect(session, scope, emptyList(), emptySet(), 65_536, timeoutMillis = 4_000)
                        try {
                            assertEquals(1uL, channel.negotiated.envelopeVersion)
                            for (payload in listOf("synthetic-negotiated-private".repeat(1_900).toByteArray(), byteArrayOf(1, 2, 3))) {
                                channel.send(payload); assertArrayEquals(payload, channel.receive())
                            }
                            assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("synthetic-negotiated-private"))
                        } finally { channel.closeAndJoin() }
                    } finally { session.closeAndJoin() }
                }
            }
        }
    }

    /** Synthetic echo proves ALPN, pins, scope and encrypted framing. It makes no Root snapshot claim. */
    @Test fun pendingSnapshotPurposeCrossesNativeTlsDirectlyAndThroughTheRelay(): Unit =
        Fixture(negotiate = true, commandMessages = true).use { f ->
            WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
                runBlocking {
                    withTimeout(20_000) {
                        for (useRelay in listOf(false, true)) {
                            val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
                            val requests = listOf(ChannelRequestCapability(0u, 1u, 1u, emptySet()))
                            val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                                scope, requests, emptySet(), 65_536, purpose = EnrolledChannelPurpose.PENDING_SNAPSHOT)
                            val channel = connector.connect(this,
                                if (useRelay) emptyFlow() else flowOf(ApprovalCarrierRoute { owner ->
                                    DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                                }), if (!useRelay) null else ApprovalCarrierRoute { owner ->
                                    relay.connector.connect(owner, relay.endpoint,
                                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                                })
                            try {
                                assertEquals(EnrolledChannelPurpose.PENDING_SNAPSHOT, channel.purpose)
                                assertEquals(scope, channel.negotiated.peer.scope)
                                val query = PendingRequestSnapshotFrame.Query(ByteArray(32) { 21 }, 8u, 32_768u,
                                    listOf(ByteArray(16) { 9 })).encode()
                                channel.send(query); assertArrayEquals(query, channel.receive())
                            } finally { channel.closeAndJoin() }
                        }
                        assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("dev.remozio.pending.snapshot"))
                    }
                }
            }
        }

    @Test fun pendingSnapshotPurposeRejectsWrongScopeBeforeApplicationData(): Unit =
        Fixture(negotiate = true, commandMessages = true).use { f ->
            runBlocking {
                withTimeout(10_000) {
                    val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 5 }, ByteArray(16) { 4 })
                    val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                        scope, listOf(ChannelRequestCapability(0u, 1u, 1u, emptySet())), emptySet(), 65_536,
                        purpose = EnrolledChannelPurpose.PENDING_SNAPSHOT)
                    var refused = false
                    try {
                        connector.connect(this, flowOf(ApprovalCarrierRoute { owner ->
                            DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                        }), null).closeAndJoin()
                    } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
                    catch (_: java.io.IOException) { refused = true }
                    assertTrue(refused)
                }
            }
        }

    @Test fun recoveryPurposeCarriesPreflightAndMaximumTokenOverNativeTlsAndOpaqueRelay(): Unit =
        Fixture(negotiate = true, pushRecovery = true, maximumPayloadBytes = 1024).use { f ->
            WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
                runBlocking {
                    withTimeout(20_000) {
                        for (useRelay in listOf(false, true)) {
                            val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
                            val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                                scope, emptyList(), emptySet(), PhonePushRecoveryFrame.MAXIMUM_BYTES,
                                purpose = EnrolledChannelPurpose.PUSH_RECOVERY)
                            val channel = connector.connect(this,
                                if (useRelay) emptyFlow() else flowOf(ApprovalCarrierRoute { owner ->
                                    DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                                }), if (!useRelay) null else ApprovalCarrierRoute { owner ->
                                    relay.connector.connect(owner, relay.endpoint,
                                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                                })
                            try {
                                assertEquals(EnrolledChannelPurpose.PUSH_RECOVERY, channel.purpose)
                                assertTrue(channel.negotiated.peer.requests.isEmpty()); assertTrue(channel.negotiated.peer.auditVersions.isEmpty())
                                val probeID = ByteArray(16) { 30 }; val resumeID = ByteArray(16) { 31 }
                                channel.send(PhonePushRecoveryFrame.Probe(probeID).encode())
                                val ready = PhonePushRecoveryFrame.decode(requireNotNull(channel.receive())) as PhonePushRecoveryFrame.Ready
                                assertArrayEquals(probeID, ready.correlationID.copyBytes())
                                val token = "synthetic-private-recovery-token-".repeat(200).take(4096)
                                channel.send(PhonePushRecoveryFrame.Resume(resumeID, PhonePushTokenOffer(token, "project", "123", "dev.sebastiano.remozio.android")).encode())
                                val response = PhonePushRecoveryFrame.decode(requireNotNull(channel.receive())) as PhonePushRecoveryFrame.State
                                assertArrayEquals(resumeID, response.correlationID.copyBytes()); assertEquals(scope, response.state.metadata.scope)
                                assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(token.toByteArray()), response.state.metadata.tokenDigest)
                                assertEquals(PhonePushRecoveryPhase.MAPPING_OBSERVED, response.state.phase)
                                assertEquals(4uL, response.state.observationAgeMilliseconds)
                            } finally { channel.closeAndJoin() }
                        }
                    }
                }
                assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("synthetic-private-recovery-token-"))
            }
        }

    @Test fun recoveryPurposeRefusalPrecedesAnyTokenOverNativeTls(): Unit =
        Fixture(negotiate = true, pushRecovery = true, recoverySupported = false).use { f ->
            runBlocking {
                withTimeout(10_000) {
                    val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
                    val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                        scope, emptyList(), emptySet(), PhonePushRecoveryFrame.MAXIMUM_BYTES, purpose = EnrolledChannelPurpose.PUSH_RECOVERY)
                    val channel = connector.connect(this, flowOf(ApprovalCarrierRoute { owner ->
                        DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                    }), null)
                    try {
                        channel.send(PhonePushRecoveryFrame.Probe(ByteArray(16) { 30 }).encode())
                        val response = PhonePushRecoveryFrame.decode(requireNotNull(channel.receive())) as PhonePushRecoveryFrame.Outcome
                        assertEquals(PhonePushRecoveryFailure.INCOMPATIBLE, response.failure)
                    } finally { channel.closeAndJoin() }
                }
            }
        }

    @Test fun registrationPurposeCarriesMaximumTokenDirectlyAndThroughTheRelayWithItsOwnBudget(): Unit =
        Fixture(negotiate = true, pushRegistration = true, maximumPayloadBytes = 1024).use { f ->
            WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
                runBlocking {
                    withTimeout(20_000) {
                        for (useRelay in listOf(false, true)) {
                            val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
                            val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                                scope, emptyList(), emptySet(), PhonePushRegistrationFrame.MAXIMUM_BYTES,
                                purpose = EnrolledChannelPurpose.PUSH_REGISTRATION)
                            val channel = connector.connect(this,
                                if (useRelay) emptyFlow() else flowOf(ApprovalCarrierRoute { owner ->
                                    DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                                }), if (!useRelay) null else ApprovalCarrierRoute { owner ->
                                    relay.connector.connect(owner, relay.endpoint,
                                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                                })
                            try {
                                assertEquals(EnrolledChannelPurpose.PUSH_REGISTRATION, channel.purpose)
                                assertTrue(channel.negotiated.peer.requests.isEmpty()); assertTrue(channel.negotiated.peer.auditVersions.isEmpty())
                                val token = "synthetic-private-provider-token-".repeat(200).take(4096)
                                val id = ByteArray(16) { 31 }
                                channel.send(PhonePushRegistrationFrame.Offer(id, PhonePushTokenOffer(token, "project", "123", "dev.sebastiano.remozio.android")).encode())
                                val response = PhonePushRegistrationFrame.decode(requireNotNull(channel.receive())) as PhonePushRegistrationFrame.Outcome
                                assertArrayEquals(id, response.correlationID.copyBytes())
                                assertEquals(PhonePushRegistrationOutcome.INCOMPATIBLE, response.outcome)
                            } finally { channel.closeAndJoin() }
                        }
                    }
                }
                assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("synthetic-private-provider-token-"))
            }
        }

    @Test fun registrationPurposeRejectsTheWrongEnrollmentBeforeApplicationData(): Unit =
        Fixture(negotiate = true, pushRegistration = true).use { f ->
            runBlocking {
                withTimeout(10_000) {
                    val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 5 }, ByteArray(16) { 4 })
                    val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                        scope, emptyList(), emptySet(), PhonePushRegistrationFrame.MAXIMUM_BYTES,
                        purpose = EnrolledChannelPurpose.PUSH_REGISTRATION)
                    var refused = false
                    try {
                        connector.connect(this, flowOf(ApprovalCarrierRoute { owner ->
                            DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                        }), null).closeAndJoin()
                    } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
                    catch (_: java.io.IOException) { refused = true }
                    assertTrue(refused)
                }
            }
        }

    @Test fun receiptPurposeCrossesNativeTlsDirectlyAndThroughTheRelay(): Unit =
        Fixture(negotiate = true, receiptRecovery = true).use { f ->
            WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
                runBlocking {
                    withTimeout(20_000) {
                        for (useRelay in listOf(false, true)) {
                            val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
                            val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
                                scope, emptyList(), emptySet(), PairingReceiptFrame.MAXIMUM_BYTES,
                                purpose = EnrolledChannelPurpose.PAIRING_RECEIPT)
                            val channel = connector.connect(this,
                                if (useRelay) emptyFlow() else flowOf(ApprovalCarrierRoute { owner ->
                                    DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
                                }), if (!useRelay) null else ApprovalCarrierRoute { owner ->
                                    relay.connector.connect(owner, relay.endpoint,
                                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                                })
                            try {
                                assertEquals(EnrolledChannelPurpose.PAIRING_RECEIPT, channel.purpose)
                                val setupID = ByteArray(16) { 31 }
                                channel.send(PairingReceiptFrame.Query(setupID).encode())
                                val response = PairingReceiptFrame.decode(requireNotNull(channel.receive())) as PairingReceiptFrame.Response
                                assertArrayEquals(setupID, response.setupID.copyBytes())
                                assertArrayEquals(ByteArray(64) { 8 }, requireNotNull(response.signature).copyBytes())
                            } finally { channel.closeAndJoin() }
                        }
                    }
                }
            }
        }

    @Test fun signedMessagesReachTheInboxThroughTheNegotiatedHttpsRelay(): Unit = Fixture(negotiate = true, commandMessages = true).use { f ->
        val limits = CborLimits(32768, 32, 4096)
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        fun id(value: Int, count: Int = 16) = ByteArray(count) { value.toByte() }
        fun scalar(n: java.math.BigInteger) = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        val point = (key.public as ECPublicKey).w
        val authority = byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
        val request = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 1u), id(1), id(2), id(8), id(9, 32),
            emptySet(), 1000u, 61000u, capture, listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
        fun message(body: ByteArray, type: ApprovalMessageType, purpose: SigningPurpose): ByteArray {
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private); update(SigningInput.make(1u, type, purpose, body, limits, limits)); sign()
            })
            return ApprovalMessage(1u, type, purpose, body, signature).encode(limits.maxBytes)
        }
        val issued = message(request.encode(limits), ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST)
        val terminal = message(RequestStatusPayload(id(1), id(2), id(8), request.requestDigest(limits, limits), request.challenge,
            2u, RequestPhase.EXPIRED, RequestStatusReason.AUTHORIZATION_EXPIRED, id(10), 60000u, null, null, false, 60000u, null).encode(limits),
            ApprovalMessageType.STATUS, SigningPurpose.STATUS)
        val enrollment = CommandRequestInbox(1, 4).add(id(1), id(2), authority, RequestLimits(limits, limits, limits, limits))
        WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
            runBlocking {
                withTimeout(10_000) {
                    val carrier = relay.connector.connect(this, relay.endpoint,
                        RelayAccessCredential(relay.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311)
                    val session = TLSRecordSession(this, f.engine(), carrier, handshakeTimeoutMillis = 4_000)
                    try {
                        val channel = NegotiatedTLSChannel.connect(session, ChannelScope(id(1), id(2), id(3), id(4)),
                            listOf(ChannelRequestCapability(0u, 1u, 1u, emptySet())), emptySet(), 65536, timeoutMillis = 4_000)
                        try {
                            val receiver = CommandRequestReceiver.bind(enrollment, channel, id(3), id(4)) { ElapsedInstant(0, 100u) }
                            val receiving = async { receiver.run() }
                            channel.send(issued)
                            val owner = enrollment.requestSessions.first { it.isNotEmpty() }.single()
                            assertNotNull(owner.snapshot(ElapsedInstant(0, 100u)).capture)
                            channel.send(terminal)
                            owner.revisions.first { it == 2uL }
                            assertNull(owner.snapshot(ElapsedInstant(0, 100u)).capture)
                            assertEquals(RequestPhase.EXPIRED, owner.snapshot(ElapsedInstant(0, 100u)).status!!.status.phase)
                            receiver.close(); receiving.await()
                        } finally { channel.closeAndJoin() }
                    } finally { session.closeAndJoin() }
                }
            }
        }
    }

    @Test fun negotiatedNativeHostRejectsWrongEnrollmentScope(): Unit = Fixture(negotiate = true).use { f ->
        runBlocking {
            withTimeout(8_000) {
                val socket = Socket("127.0.0.1", f.port).apply { soTimeout = 4_000 }
                val session = TLSRecordSession(this, f.engine(), SocketRecords(socket), handshakeTimeoutMillis = 4_000)
                try {
                    val wrong = ChannelScope(ByteArray(16), ByteArray(16), ByteArray(16), ByteArray(16))
                    var rejected = false
                    try { NegotiatedTLSChannel.connect(session, wrong, emptyList(), emptySet(), 65_536, timeoutMillis = 4_000) }
                    catch (_: IOException) { rejected = true }
                    assertTrue(rejected)
                } finally { session.closeAndJoin() }
                assertTrue(socket.isClosed)
            }
        }
    }

    @Test fun nativeListenerBindsEachTransportIdentityToItsOwnScope(): Unit = Fixture(negotiate = true, twoPhones = true).use { f ->
        runBlocking {
            withTimeout(20_000) {
                for ((identity, phoneID) in listOf(f.phone to 3, requireNotNull(f.secondPhone) to 5)) {
                    for (claimedPhone in listOf(phoneID, if (phoneID == 3) 5 else 3)) {
                        val socket = Socket("127.0.0.1", f.port).apply { soTimeout = 4_000 }
                        val session = TLSRecordSession(this, f.engine(identity = identity), SocketRecords(socket), handshakeTimeoutMillis = 4_000)
                        try {
                            val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { claimedPhone.toByte() }, ByteArray(16) { 4 })
                            if (claimedPhone == phoneID) {
                                val channel = NegotiatedTLSChannel.connect(session, scope, emptyList(), emptySet(), 65_536, timeoutMillis = 4_000)
                                channel.send(byteArrayOf(1, 2, 3)); assertArrayEquals(byteArrayOf(1, 2, 3), channel.receive())
                                channel.closeAndJoin()
                            } else {
                                var rejected = false
                                try { NegotiatedTLSChannel.connect(session, scope, emptyList(), emptySet(), 65_536, timeoutMillis = 4_000) }
                                catch (_: IOException) { rejected = true }
                                assertTrue(rejected)
                            }
                        } finally { session.closeAndJoin() }
                    }
                }
            }
        }
    }

    @Test fun nativeListenerRejectsExcessConnectionsBeforeStartingHandshake(): Unit = Fixture(negotiate = true, maximumConnections = 1).use { f ->
        f.connect(f.port).use { first ->
            first.startHandshake()
            f.connect(f.port).use { excess ->
                excess.soTimeout = 1_000
                try { excess.startHandshake(); fail("An excess connection completed TLS") }
                catch (timeout: java.net.SocketTimeoutException) { throw AssertionError("Excess connection was not closed promptly", timeout) }
                catch (_: IOException) { }
            }
        }
    }

    @Test fun nativeListenerCloseAbortsAnExistingHandshakeAndStopsAccepting(): Unit = Fixture(negotiate = true).use { f ->
        f.connect(f.port).use { socket ->
            socket.startHandshake()
            socket.soTimeout = 1_000
            f.stopNativeListener()
            try { assertEquals(-1, socket.inputStream.read()) }
            catch (timeout: java.net.SocketTimeoutException) { throw AssertionError("Listener close left an active channel", timeout) }
            catch (_: IOException) { }
        }
        try { f.connect(f.port).use { it.startHandshake(); fail("Stopped listener accepted a connection") } }
        catch (timeout: java.net.SocketTimeoutException) { throw AssertionError("Stopped listener retained pending I/O", timeout) }
        catch (_: IOException) { }
    }

    @Test fun nativeListenerRejectsUnknownIdentityAndWrongProtocol(): Unit = Fixture(negotiate = true).use { f ->
        for (mode in 0..2) {
            f.connect(f.port, identity = if (mode == 0) f.mac else f.phone).use { socket ->
                if (mode == 1) socket.sslParameters = socket.sslParameters.apply { applicationProtocols = arrayOf("wrong/1") }
                if (mode == 2) socket.enabledProtocols = arrayOf("TLSv1.2")
                assertThrows(IOException::class.java) { socket.startHandshake(); exchange(socket, byteArrayOf(1)) }
            }
        }
    }

    private class SocketRecords(private val socket: Socket) : EncryptedRecordTransport {
        override val maximumMessageBytes = 311
        override suspend fun send(ciphertext: ByteArray): Unit = withContext(Dispatchers.IO) {
            require(ciphertext.size <= maximumMessageBytes)
            socket.outputStream.write(ciphertext)
            socket.outputStream.flush()
        }
        override suspend fun receive(): ByteArray? = withContext(Dispatchers.IO) {
            val bytes = ByteArray(127)
            val count = socket.inputStream.read(bytes)
            if (count < 0) null else bytes.copyOf(count)
        }
        override fun close() { socket.close() }
    }

    @Test fun engineUsesWebSocketDirectlyWithoutAClientSocketBridge(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port, bridgeClient = false).use { relay ->
            f.engine().use { engine ->
                EngineWebSocketFixture(relay, engine).use { driver ->
                    driver.handshake()
                    val payload = "synthetic-direct-engine-request".repeat(2_000).toByteArray()
                    assertArrayEquals(payload, driver.exchange(payload))
                    assertTrue(relay.outerAuthenticated.get())
                    assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("synthetic-direct-engine-request"))
                }
            }
        }
    }

    @Test fun directWebSocketCannotOverrideTheEnginePin(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port, bridgeClient = false).use { relay ->
            f.engine(pin = f.phone.certificate).use { engine ->
                EngineWebSocketFixture(relay, engine).use { driver ->
                    assertThrows(IOException::class.java) { driver.handshake() }
                    assertEquals(TLSClientState.FAILED, engine.state())
                    assertTrue(relay.outerAuthenticated.get())
                }
            }
        }
    }

    @Test fun directWebSocketRejectsOuterTrustFailureBeforeInnerBytes(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port, trustOuter = false, bridgeClient = false).use { relay ->
            f.engine().use { engine ->
                EngineWebSocketFixture(relay, engine).use { driver ->
                    assertThrows(IOException::class.java) { driver.handshake() }
                    assertFalse(relay.outerAuthenticated.get())
                    assertEquals(0, relay.capture().size)
                    assertEquals(TLSClientState.NEW, engine.state())
                }
            }
        }
    }

    @Test fun directWebSocketTamperingCannotProduceAnEngineReply(): Unit = Fixture().use { f ->
        WebSocketTLSRelay(f.port, bridgeClient = false).use { relay ->
            f.engine().use { engine ->
                EngineWebSocketFixture(relay, engine).use { driver ->
                    driver.handshake(); relay.tamper.set(true)
                    assertThrows(IOException::class.java) { driver.exchange("synthetic-direct-tamper".toByteArray()) }
                    assertTrue(relay.outerAuthenticated.get()); assertTrue(relay.changed.get())
                }
            }
        }
    }

    private fun routingRecord(f: Fixture, wrongRoot: Boolean = false): StoredPhoneEnrollment {
        fun id(n: Int) = ByteArray(16) { n.toByte() }
        fun local(role: EnrollmentKeyRole, public: ByteArray, keyID: Int) = EnrollmentKeyReference(role, id(keyID),
            "remozio.${role.aliasPart}.v1.${"%032x".format(keyID)}", public)
        val decision = requireNotNull(f.routingDecision); val biometric = requireNotNull(f.routingBiometric)
        val authority = if (wrongRoot) KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair().public.encoded.takeLast(65).toByteArray() else requireNotNull(f.routingAuthorityPublicKey)
        return StoredPhoneEnrollment(PhoneEnrollment(id(9), id(1), id(2), id(3), id(4), "Synthetic routing host", authority,
            f.mac.certificate.publicKey.encoded, local(EnrollmentKeyRole.TRANSPORT, f.phone.certificate.publicKey.encoded, 10),
            local(EnrollmentKeyRole.DECISION, decision.public.encoded.takeLast(65).toByteArray(), 6),
            local(EnrollmentKeyRole.BIOMETRIC, biometric.public.encoded.takeLast(65).toByteArray(), 7), ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
    }
    private suspend fun routingChannel(f: Fixture, parent: kotlinx.coroutines.CoroutineScope, record: StoredPhoneEnrollment,
                                       relay: WebSocketTLSRelay? = null): PhoneRoutingChannel {
        val e = record.enrollment
        val connector = ApprovalChannelConnector(f.phone.keyManagers, f.mac.certificate.publicKey.encoded,
            ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
            emptyList(), emptySet(), PhoneRoutingFrame.MAXIMUM_BYTES, purpose = EnrolledChannelPurpose.ROUTING)
        val carrier = connector.connect(parent, if (relay != null) emptyFlow() else flowOf(ApprovalCarrierRoute { owner ->
            DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", f.port))
        }), relay?.let { selected -> ApprovalCarrierRoute { owner -> selected.connector.connect(owner, selected.endpoint,
            RelayAccessCredential(selected.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311) } })
        return PhoneRoutingChannel.bind(record, carrier, f::routingElapsedNanos, 5000)
    }
    private fun routingSignature(f: Fixture, record: StoredPhoneEnrollment, challenge: PhoneRoutingChallenge): ByteArray =
        challenge.sign(record.enrollment) { input -> Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initSign(requireNotNull(f.routingDecision).private); update(input); sign()
        } }

    @Test fun routingStatusUsesNativeTlsRootSignaturesAndAnOpaqueRelay(): Unit = Fixture(routing = true).use { f ->
        val record = routingRecord(f)
        for (useRelay in listOf(false, true)) WebSocketTLSRelay(f.port, bridgeClient = false, connectorMode = true).use { relay ->
            runBlocking { withTimeout(15_000) {
                val channel = routingChannel(f, this, record, if (useRelay) relay else null)
                try {
                    val result = channel.status() as PhoneRoutingResult.Verified
                    assertEquals(RoutingStatusMode.PRESENT, result.response.state.mode); assertEquals(1uL, result.response.state.revision)
                    assertEquals(RoutingStatusReason.MANUAL_PRESENT, result.response.state.reason); assertTrue(result.isFresh(5000))
                } finally { channel.closeAndJoin() }
            } }
            if (useRelay) {
                val request = relay.connectorRequest()
                assertEquals("synthetic-id", request.headers["CF-Access-Client-Id"])
                assertEquals("synthetic-secret", request.headers["CF-Access-Client-Secret"])
                assertEquals(dev.remozio.phone.transport.WebSocketUpgrade.PROTOCOL, request.headers["Sec-WebSocket-Protocol"])
                assertTrue(relay.capture().isNotEmpty())
                assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("dev.remozio.phone.routing"))
            }
        }
        assertEquals(1, f.routingControl("snapshot").getValue("routingEvents").jsonPrimitive.int)
    }
    @Test fun routingAwayAndHistoricalReceiptUseTheDurableRootJournal(): Unit = Fixture(routing = true).use { f ->
        val record = routingRecord(f)
        runBlocking { withTimeout(20_000) {
            val preparedChannel = routingChannel(f, this, record)
            val prepared = try { preparedChannel.challenge(1u) as PhoneRoutingResult.Verified } finally { preparedChannel.closeAndJoin() }
            val challenge = requireNotNull(prepared.challenge); val signature = routingSignature(f, record, challenge)
            val apply = routingChannel(f, this, record)
            val applied = try { apply.apply(challenge, signature) as PhoneRoutingResult.Verified } finally { apply.closeAndJoin() }
            assertEquals(RoutingStatusMode.AWAY, applied.response.state.mode); assertEquals(2uL, applied.response.appliedRevision)
            val present = f.routingControl("present"); assertEquals(3, present.getValue("revision").jsonPrimitive.int)
            // Explicit duplicate probes the retained receipt. Neither channel nor owner retries an application operation.
            val duplicate = routingChannel(f, this, record)
            val historical = try { duplicate.apply(challenge, signature) as PhoneRoutingResult.Verified } finally { duplicate.closeAndJoin() }
            assertEquals(RoutingStatusMode.PRESENT, historical.response.state.mode); assertEquals(3uL, historical.response.state.revision)
            assertEquals(2uL, historical.response.appliedRevision)
            val after = f.routingControl("snapshot")
            assertEquals(present.getValue("head"), after.getValue("head")); assertEquals(3, after.getValue("routingEvents").jsonPrimitive.int)
        } }
    }
    @Test fun routingStaleControlReturnsSignedConflictWithoutAnotherAuditWrite(): Unit = Fixture(routing = true).use { f ->
        val record = routingRecord(f)
        runBlocking { withTimeout(20_000) {
            val challenges = (0..1).map {
                val wire = routingChannel(f, this, record)
                try { requireNotNull((wire.challenge(1u) as PhoneRoutingResult.Verified).challenge) } finally { wire.closeAndJoin() }
            }
            val signatures = challenges.map { routingSignature(f, record, it) }
            for (index in 0..1) {
                val wire = routingChannel(f, this, record)
                val result = try { wire.apply(challenges[index], signatures[index]) as PhoneRoutingResult.Verified } finally { wire.closeAndJoin() }
                assertEquals(if (index == 0) RoutingStatusOutcome.APPLIED else RoutingStatusOutcome.CONFLICT, result.response.outcome)
                assertEquals(RoutingStatusMode.AWAY, result.response.state.mode); assertEquals(2uL, result.response.state.revision)
            }
            assertEquals(2, f.routingControl("snapshot").getValue("routingEvents").jsonPrimitive.int)
        } }
    }
    @Test fun routingExpiredRootChallengeCannotChangeMode(): Unit = Fixture(routing = true).use { f ->
        val record = routingRecord(f)
        runBlocking { withTimeout(15_000) {
            val prepare = routingChannel(f, this, record)
            val challenge = try { requireNotNull((prepare.challenge(1u) as PhoneRoutingResult.Verified).challenge) } finally { prepare.closeAndJoin() }
            val signature = routingSignature(f, record, challenge); f.routingControl("expire")
            val apply = routingChannel(f, this, record)
            try { apply.apply(challenge, signature); fail("Expired control changed routing") } catch (_: IOException) {} finally { apply.closeAndJoin() }
            val state = f.routingControl("snapshot"); assertEquals(1, state.getValue("revision").jsonPrimitive.int)
            assertEquals(1, state.getValue("routingEvents").jsonPrimitive.int)
        } }
    }
    @Test fun routingRequiresBothRootSupportAndTheEnrolledAuthorityPin(): Unit = Unit.also {
        for (unsupported in listOf(false, true)) Fixture(routing = true, routingSupported = !unsupported).use { f ->
            val record = routingRecord(f, wrongRoot = !unsupported)
            runBlocking { withTimeout(15_000) {
                var channel: PhoneRoutingChannel? = null
                try {
                    channel = routingChannel(f, this, record); channel.status(); fail("Unsupported or untrusted Root established routing")
                } catch (_: IOException) {} finally { channel?.closeAndJoin() }
            } }
            assertEquals(1, f.routingControl("snapshot").getValue("routingEvents").jsonPrimitive.int)
        }
    }
    @Test fun routingControllerClosureJoinsTheNativeTransportWithoutAnApplicationReply(): Unit = Fixture(routing = true).use { f ->
        val record = routingRecord(f)
        runBlocking { withTimeout(10_000) {
            val channel = routingChannel(f, this, record)
            try {
                f.closeControllerPipe(); assertTrue(withContext(Dispatchers.IO) { f.waitForPeerExit() })
                assertEquals(0, f.peerExitCode)
                try { channel.status(); fail("Closed fixture returned routing") } catch (_: IOException) {}
            } finally { channel.closeAndJoin() }
        } }
    }

    private fun exchange(socket: SSLSocket, payload: ByteArray): ByteArray {
        DataOutputStream(socket.outputStream).apply { writeInt(payload.size); write(payload); flush() }
        val input = DataInputStream(socket.inputStream)
        val count = input.readInt()
        require(count in 0..65_536)
        return ByteArray(count).also { input.readFully(it) }
    }

    private class Identity(val path: Path) {
        val store = KeyStore.getInstance("PKCS12").apply {
            Files.newInputStream(path).use { load(it, PASSWORD.toCharArray()) }
        }
        val certificate = store.getCertificate("fixture") as X509Certificate
        val clientManager = ClientTLSKeyManager(store.getKey("fixture", PASSWORD.toCharArray()) as PrivateKey, arrayOf(certificate))
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(store, PASSWORD.toCharArray())
        }.keyManagers
    }

    private class AuditStorage : AuditCiphertextStorage {
        var ciphertext: ByteArray? = null
        var writes = 0
        override fun read(maximumBytes: Int) = ciphertext?.copyOf()?.also { require(it.size <= maximumBytes) }
        override fun replace(ciphertext: ByteArray) { this.ciphertext = ciphertext.copyOf(); writes++ }
        override fun close() = Unit
    }
    private inner class AuditClient(val fixture: Fixture, val record: StoredPhoneEnrollment = routingRecord(fixture)) : AutoCloseable {
        val storage = AuditStorage()
        var advanced = 0uL
        fun now() = ElapsedInstant(1, fixture.routingElapsedNanos().toULong() / 1_000_000uL + advanced)
        private val limits = CborLimits(1_048_576, 8, 131_072)
        val cache = EncryptedAuditCache.open(storage,
            AuditArchiveCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), limits.maxBytes),
            AuditCacheBinding(record.enrollment.macID.copyBytes(), record.enrollment.accountID.copyBytes(), record.enrollment.authorityPublicKey.copyBytes()),
            AuditPageLimits(limits, CborLimits(4096, 4, 64), CborLimits(1_050_624, 8, 32), 2048,
                CborLimits(16_384, 8, 256), CborLimits(4096, 4, 64)), AuditEvidenceLimits(128, 4_194_304, 512, 16), limits)
        val session = AuditSyncSession(cache, 2, 5000u, ::now).also { it.start() }
        suspend fun open(parent: kotlinx.coroutines.CoroutineScope, relay: WebSocketTLSRelay? = null): PhoneAuditChannel {
            val e = record.enrollment
            val connector = ApprovalChannelConnector(fixture.phone.keyManagers, fixture.mac.certificate.publicKey.encoded,
                ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
                emptyList(), setOf(1u), PhoneAuditFrame.MAXIMUM_BYTES, purpose = EnrolledChannelPurpose.AUDIT)
            val carrier = connector.connect(parent, if (relay != null) emptyFlow() else flowOf(ApprovalCarrierRoute { owner ->
                DirectTCPConnector().connect(owner, InetSocketAddress("127.0.0.1", fixture.port))
            }), relay?.let { selected -> ApprovalCarrierRoute { owner -> selected.connector.connect(owner, selected.endpoint,
                RelayAccessCredential(selected.endpoint, "synthetic-id", "synthetic-secret"), maximumMessageBytes = 311) } })
            return PhoneAuditChannel.bind(record, carrier, ::now)
        }
        suspend fun exchange(parent: kotlinx.coroutines.CoroutineScope, query: AuditQuery, relay: WebSocketTLSRelay? = null): PhoneAuditResult.Unverified {
            val wire = open(parent, relay)
            return try { wire.exchange(query) as PhoneAuditResult.Unverified } finally { wire.closeAndJoin() }
        }
        suspend fun drain(parent: kotlinx.coroutines.CoroutineScope, useRelay: Boolean = false,
                          inspectRelay: (WebSocketTLSRelay) -> Unit = {}) {
            repeat(32) {
                when (session.state.value.phase) {
                    AuditSyncPhase.COMPLETE -> return
                    AuditSyncPhase.PAUSED -> session.resume()
                    AuditSyncPhase.SYNCING -> session.next()?.let { query ->
                        if (useRelay) WebSocketTLSRelay(fixture.port, bridgeClient = false, connectorMode = true).use { relay ->
                            exchange(parent, query, relay).acceptInto(session, record)
                            inspectRelay(relay)
                        } else { exchange(parent, query).acceptInto(session, record) }
                    }
                    else -> error("Native audit sync failed: " + session.state.value.phase)
                }
            }
            error("Native audit sync exceeded its response bound")
        }
        override fun close() = session.close()
    }
    @Test fun auditNativeJournalSyncsBoundedPagesDirectlyAndThroughAnOpaqueRelay(): Unit = Fixture(audit = true, maximumPayloadBytes = 1024).use { f ->
        val before = f.routingControl("audit-seed")
        val head = before.getValue("head").jsonPrimitive.int
        assertTrue(head > 8)
        for (useRelay in listOf(false, true)) AuditClient(f).use { client ->
            var relayExchanges = 0
            runBlocking { withTimeout(20_000) { client.drain(this, useRelay) { relay ->
                val request = relay.connectorRequest()
                assertEquals("synthetic-id", request.headers["CF-Access-Client-Id"])
                assertEquals("synthetic-secret", request.headers["CF-Access-Client-Secret"])
                assertEquals(dev.remozio.phone.transport.WebSocketUpgrade.PROTOCOL, request.headers["Sec-WebSocket-Protocol"])
                assertTrue(relay.capture().isNotEmpty())
                assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("dev.remozio.phone.audit"))
                assertFalse(String(relay.capture(), Charsets.ISO_8859_1).contains("dev.remozio.audit"))
                relayExchanges++
            } } }
            val state = client.session.state.value
            assertEquals(AuditSyncPhase.COMPLETE, state.phase); assertNotNull(state.lastCompletedAt)
            val epoch = state.history.epochs.single()
            assertEquals((1..head).map(Int::toULong), epoch.records.map { it.sequence }); assertTrue(epoch.gaps.isEmpty())
            assertTrue(client.storage.writes > 2); assertNotNull(client.storage.ciphertext)
            assertEquals(if (useRelay) client.storage.writes else 0, relayExchanges)
        }
        val after = f.routingControl("snapshot")
        assertEquals(before.getValue("head"), after.getValue("head"))
        assertEquals(before.getValue("revision"), after.getValue("revision"))
    }
    @Test fun auditFullyPrunedNativeJournalPreservesItsExplicitRetentionGap(): Unit = Fixture(audit = true).use { f ->
        val seeded = f.routingControl("audit-seed"); f.routingControl("audit-prune")
        AuditClient(f).use { client ->
            runBlocking { withTimeout(15_000) { client.drain(this) } }
            val epoch = client.session.state.value.history.epochs.single()
            assertEquals(AuditSyncPhase.COMPLETE, client.session.state.value.phase)
            assertTrue(epoch.records.isEmpty())
            assertEquals(listOf(AuditHistoryGap(0u, seeded.getValue("head").jsonPrimitive.int.toULong(), true)), epoch.gaps)
        }
    }
    @Test fun auditWrongEnrolledRootCannotWriteEvidenceFromAValidNativeTlsPeer(): Unit = Fixture(audit = true).use { f ->
        AuditClient(f, routingRecord(f, wrongRoot = true)).use { client ->
            runBlocking { withTimeout(15_000) {
                val query = requireNotNull(client.session.next()); val reply = client.exchange(this, query)
                try { reply.acceptInto(client.session, client.record); fail("Wrong Root key wrote history") } catch (_: IllegalArgumentException) {}
            } }
            assertEquals(0, client.storage.writes); assertTrue(client.cache.snapshot().proofs.isEmpty())
            assertNull(client.session.state.value.lastCompletedAt)
        }
    }
    @Test fun auditUnsupportedRootCannotCompleteOrReplaceEvidence(): Unit = Fixture(audit = true, auditSupported = false).use { f ->
        AuditClient(f).use { client ->
            runBlocking { withTimeout(15_000) {
                val query = requireNotNull(client.session.next())
                try { client.exchange(this, query); fail("Unsupported Root served audit") } catch (_: IOException) {}
                client.session.transportFailed(query)
            } }
            assertEquals(0, client.storage.writes); assertNull(client.session.state.value.lastCompletedAt)
        }
    }
    @Test fun auditRevokedEnrollmentCannotFetchTheNextPageOrEraseEarlierEvidence(): Unit = Fixture(audit = true).use { f ->
        AuditClient(f).use { client ->
            runBlocking { withTimeout(15_000) {
                val discovery = requireNotNull(client.session.next())
                client.exchange(this, discovery).acceptInto(client.session, client.record)
                val before = client.cache.snapshot().proofs.size; assertEquals(1, before)
                f.routingControl("audit-revoke")
                val query = requireNotNull(client.session.next())
                try { client.exchange(this, query); fail("Revoked phone fetched a page") } catch (_: IOException) {}
                client.session.transportFailed(query)
                assertEquals(before, client.cache.snapshot().proofs.size); assertEquals(1, client.storage.writes)
            } }
            assertNull(client.session.state.value.lastCompletedAt)
        }
    }
    @Test fun auditQueryExpiryAfterNativeReplyCannotAdvanceTheCache(): Unit = Fixture(audit = true).use { f ->
        AuditClient(f).use { client ->
            runBlocking { withTimeout(15_000) {
                val query = requireNotNull(client.session.next()); val reply = client.exchange(this, query)
                client.advanced += 5000u
                try { reply.acceptInto(client.session, client.record); fail("Expired query wrote history") } catch (_: IllegalArgumentException) {}
            } }
            assertEquals(0, client.storage.writes); assertNull(client.session.state.value.lastCompletedAt)
        }
    }
    @Test fun auditControllerClosureJoinsTheNativeTransportWithoutAHistoryReply(): Unit = Fixture(audit = true).use { f ->
        AuditClient(f).use { client ->
            runBlocking { withTimeout(15_000) {
                val query = requireNotNull(client.session.next()); val wire = client.open(this)
                f.closeControllerPipe(); assertTrue(f.waitForPeerExit()); assertEquals(0, f.peerExitCode)
                try { wire.exchange(query); fail("Closed fixture returned audit") } catch (_: IOException) {}
                finally { wire.closeAndJoin() }
            } }
            assertEquals(0, client.storage.writes); assertNull(client.session.state.value.lastCompletedAt)
        }
    }

    private class Fixture(private val phoneStartDate: String? = null, private val negotiate: Boolean = false, private val commandMessages: Boolean = false, private val twoPhones: Boolean = false, private val maximumConnections: Int = 8, private val receiptRecovery: Boolean = false, private val pushRegistration: Boolean = false, private val pushRecovery: Boolean = false, private val recoverySupported: Boolean = true, private val maximumPayloadBytes: Int = 65_536, private val routing: Boolean = false, private val routingSupported: Boolean = true, private val audit: Boolean = false, private val auditSupported: Boolean = true) : AutoCloseable {
        private val directory = Files.createTempDirectory("remozio-tls-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val mac: Identity
        val phone: Identity
        val secondPhone: Identity?
        private val process: Process
        val port: Int
        val routingAuthorityPublicKey: ByteArray?
        val routingDecision = if (routing || audit) routingKey() else null
        val routingBiometric = if (routing || audit) routingKey() else null
        private val routingStarted = System.nanoTime()
        fun routingElapsedNanos(): Long = System.nanoTime() - routingStarted
        private lateinit var controllerReader: java.io.BufferedReader
        private lateinit var controllerWriter: java.io.BufferedWriter
        private fun routingKey() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        init {
            var child: Process? = null
            try {
                mac = generate("mac")
                phone = generate("phone")
                secondPhone = if (twoPhones) generate("second-phone") else null
                val peer = requireNotNull(System.getProperty("remozio.test.tlsPeer")) { "Build the native TLS peer first" }
                child = ProcessBuilder(peer, mac.path.toString()).redirectError(directory.resolve("peer.log").toFile()).start()
                process = child
                controllerWriter = process.outputStream.bufferedWriter()
                controllerReader = process.inputStream.bufferedReader()
                controllerWriter.also {
                    val second = secondPhone?.let { identity -> ",\"secondPeerPublicKey\":\"" + Base64.getEncoder().encodeToString(identity.certificate.publicKey.encoded) + "\"" } ?: ""
                    val routingFields = if (routing || audit) ",\"routing\":" + routing + ",\"routingSupported\":" + routingSupported + ",\"decisionPublicKey\":\"" +
                        Base64.getEncoder().encodeToString(requireNotNull(routingDecision).public.encoded.takeLast(65).toByteArray()) +
                        "\",\"biometricPublicKey\":\"" + Base64.getEncoder().encodeToString(requireNotNull(routingBiometric).public.encoded.takeLast(65).toByteArray()) + "\"" else ""
                    it.write("{\"peerPublicKey\":\"" + Base64.getEncoder().encodeToString(phone.certificate.publicKey.encoded) + "\",\"negotiate\":" + negotiate + ",\"commandMessages\":" + commandMessages + ",\"maximumConnections\":" + maximumConnections + ",\"receiptRecovery\":" + receiptRecovery + ",\"pushRegistration\":" + pushRegistration + ",\"pushRecovery\":" + pushRecovery + ",\"recoverySupported\":" + recoverySupported + ",\"maximumPayloadBytes\":" + maximumPayloadBytes + second + routingFields + ",\"audit\":" + audit + ",\"auditSupported\":" + auditSupported + "}\n")
                    it.flush()
                }
                val reader = Executors.newSingleThreadExecutor()
                try {
                    val line = reader.submit<String?> { controllerReader.readLine() }.get(10, TimeUnit.SECONDS)
                    val ready = Json.parseToJsonElement(requireNotNull(line) { "TLS peer did not start" }).jsonObject
                    port = ready.getValue("port").jsonPrimitive.int
                    routingAuthorityPublicKey = ready["authorityPublicKey"]?.jsonPrimitive?.content?.let { Base64.getDecoder().decode(it) }
                    require(port in 1..65_535)
                } finally { reader.shutdownNow() }
            } catch (failure: Throwable) {
                child?.destroyForcibly()?.waitFor(3, TimeUnit.SECONDS)
                retainRoutingEvidence()
                clean()
                throw failure
            }
        }
        private fun generate(name: String): Identity {
            val path = directory.resolve("$name.p12")
            val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString()
            val arguments = mutableListOf(keytool, "-genkeypair", "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=synthetic-$name", "-validity", "1", "-storetype", "PKCS12", "-keystore", path.toString(),
                "-storepass", PASSWORD, "-keypass", PASSWORD, "-noprompt")
            if (name == "phone" && phoneStartDate != null) arguments.addAll(listOf("-startdate", phoneStartDate))
            val command = ProcessBuilder(arguments)
                .redirectErrorStream(true).redirectOutput(directory.resolve("$name-keytool.log").toFile()).start()
            if (!command.waitFor(15, TimeUnit.SECONDS)) { command.destroyForcibly(); error("Synthetic certificate generation timed out") }
            check(command.exitValue() == 0) { "Synthetic certificate generation failed" }
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            return Identity(path)
        }
        fun engine(pin: X509Certificate = mac.certificate, protocol: String = if (negotiate) "remozio/1" else "remozio-experiment/1", budget: Int = 65_536, identity: Identity = phone) =
            PinnedTLSClient(arrayOf(identity.clientManager), pin.publicKey.encoded, protocol, budget)
        fun connect(port: Int, identity: Identity? = phone, serverPin: X509Certificate = mac.certificate): SSLSocket {
            val context = SSLContext.getInstance("TLSv1.3")
            val trust = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = verify(chain)
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = verify(chain)
                private fun verify(chain: Array<X509Certificate>) {
                    if (chain.isEmpty() || !chain[0].encoded.contentEquals(serverPin.encoded)) throw CertificateException("Wrong synthetic peer pin")
                    chain[0].checkValidity()
                }
            }
            context.init(identity?.keyManagers ?: emptyArray(), arrayOf<TrustManager>(trust), null)
            return (context.socketFactory.createSocket("127.0.0.1", port) as SSLSocket).apply {
                soTimeout = 4_000
                enabledProtocols = arrayOf("TLSv1.3")
                sslParameters = sslParameters.apply { applicationProtocols = arrayOf(if (negotiate) "remozio/1" else "remozio-experiment/1") }
            }
        }
        fun routingControl(command: String): JsonObject {
            controllerWriter.write("{\"command\":\"" + command + "\"}\n"); controllerWriter.flush()
            val reader = Executors.newSingleThreadExecutor()
            return try {
                val line = reader.submit<String?> { controllerReader.readLine() }.get(10, TimeUnit.SECONDS)
                Json.parseToJsonElement(requireNotNull(line)).jsonObject
            } finally { reader.shutdownNow() }
        }
        fun stopNativeListener() { process.outputStream.write(115); process.outputStream.flush() }
        fun closeControllerPipe() { process.outputStream.close() }
        fun waitForPeerExit(): Boolean = process.waitFor(3, TimeUnit.SECONDS)
        val peerExitCode: Int get() = process.exitValue()
        override fun close() {
            mac.clientManager.close()
            phone.clientManager.close()
            secondPhone?.clientManager?.close()
            process.outputStream.close()
            process.destroy()
            if (!process.waitFor(3, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(3, TimeUnit.SECONDS) }
            retainRoutingEvidence()
            clean()
        }
        private fun retainRoutingEvidence() {
            if (!routing && !audit) return
            val property = if (audit) "remozio.test.auditTransportEvidence" else "remozio.test.routingEvidence"
            val destination = System.getProperty(property)?.let(Path::of) ?: return
            Files.createDirectories(destination)
            val log = directory.resolve("peer.log")
            if (Files.exists(log) && Files.size(log) <= 1_048_576) Files.copy(log, destination.resolve(directory.fileName.toString() + ".log"))
        }
        private fun clean() { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } } }
    }

    private class Relay(upstreamPort: Int) : AutoCloseable {
        private val listener = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port: Int = listener.localPort
        val tamper = AtomicBoolean(false)
        val changed = AtomicBoolean(false)
        private val recorded = ByteArrayOutputStream()
        private val workers = Executors.newFixedThreadPool(3)
        @Volatile private var incoming: Socket? = null
        @Volatile private var upstream: Socket? = null
        init {
            workers.submit {
                try {
                    val client = listener.accept().also { incoming = it }
                    val server = Socket("127.0.0.1", upstreamPort).also { upstream = it }
                    client.soTimeout = 5_000; server.soTimeout = 5_000
                    workers.submit { copy(client, server, true) }
                    workers.submit { copy(server, client, false) }
                } catch (_: IOException) { }
            }
        }
        private fun copy(from: Socket, to: Socket, alter: Boolean) {
            try {
                val buffer = ByteArray(4_096)
                while (true) {
                    val count = from.inputStream.read(buffer)
                    if (count < 0) break
                    if (alter && count > 0 && tamper.compareAndSet(true, false)) {
                        buffer[count - 1] = (buffer[count - 1].toInt() xor 1).toByte(); changed.set(true)
                    }
                    synchronized(recorded) {
                        check(recorded.size() + count <= 1_048_576)
                        recorded.write(buffer, 0, count)
                    }
                    var offset = 0
                    while (offset < count) {
                        val length = minOf(97, count - offset)
                        to.outputStream.write(buffer, offset, length); offset += length
                    }
                    to.outputStream.flush()
                }
            } catch (_: IOException) { }
            finally { runCatching { from.close() }; runCatching { to.close() } }
        }
        fun capture(): ByteArray = synchronized(recorded) { recorded.toByteArray() }
        override fun close() {
            listener.close(); incoming?.close(); upstream?.close()
            workers.shutdownNow(); check(workers.awaitTermination(6, TimeUnit.SECONDS)) { "Relay cleanup timed out" }
        }
    }

    private companion object { const val PASSWORD = "synthetic-only" }
}
