package dev.remozio.phone.ui

import dev.remozio.pairing.PairingSendCompletion
import dev.remozio.pairing.PairingTransport
import dev.remozio.pairing.PairingTransportEvents
import dev.remozio.pairing.PlatformPairingKeys
import dev.remozio.protocol.*
import kotlinx.coroutines.*
import kotlin.test.*

class ConnectionTestTest {
    // The "ascii" row of protocol/vectors/pairing-invitation-v1.json. Its keys are the P-256 points G and 2G.
    private val text = "remozio-pairing:v1:pwABAVABAQEBAQEBAQEBAQEBAQEBAlACAgICAgICAgICAgICAgICA2ZTdHVkaW8EWEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li_hp_m47n60p8D54WK84zV2sxXs7LtkBoN79R9QVYQQR88nsYjQNPfopSOAMEtRrDwIlp4nfyGzWmC0j8R2aZeAd3VRDbjtBAKT2axp90MNu6fa3mPOmCKZ4Et50ieHPRBgE"

    private fun point(x: String, y: String) = ("04$x$y").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** The points 3G, 4G and 5G, distinct from the invitation's keys. The transport fails as soon as it starts. */
    private class Keys(override val transportPublicKey: ByteArray, override val decisionPublicKey: ByteArray,
        override val biometricPublicKey: ByteArray) : PlatformPairingKeys {
        var opens = 0
        override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String): PairingTransport {
            opens++
            return object : PairingTransport {
                override fun start(events: PairingTransportEvents) = events.closed("pin mismatch")
                override fun requestBytes() {}
                override fun send(bytes: ByteArray, completion: PairingSendCompletion) = completion.done("closed")
                override fun cancel() {}
            }
        }
    }

    private fun keys() = Keys(
        point("5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C", "8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032"),
        point("E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852", "E0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6"),
        point("51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED", "E0C17DA8904A727D8AE1BF36BF8A79260D012F00D4D80888D1D0BB44FDA16DA4"))

    @Test fun invalidTextFailsWithoutOpeningATransport(): Unit = runBlocking {
        val keys = keys()
        assertEquals(ConnectionTestState.Failed, testConnection(this, "remozio-pairing:v1:", keys))
        assertEquals(0, keys.opens)
    }

    @Test fun aRejectedConnectionIsAFailedTestNotACrash(): Unit = runBlocking {
        val keys = keys()
        assertEquals(ConnectionTestState.Failed, testConnection(this, text, keys))
        assertEquals(1, keys.opens)
        assertTrue(isActive)
    }

    @Test fun aSilentComputerFailsWhenTheBudgetEnds(): Unit = runBlocking {
        val silent = object : PlatformPairingKeys by keys() {
            override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String) =
                object : PairingTransport {
                    var events: PairingTransportEvents? = null
                    override fun start(events: PairingTransportEvents) { this.events = events }
                    override fun requestBytes() {}
                    override fun send(bytes: ByteArray, completion: PairingSendCompletion) = completion.done("closed")
                    override fun cancel() { events?.closed("cancelled") }
                }
        }
        assertEquals(ConnectionTestState.Failed, testConnection(this, text, silent, timeoutMillis = 200))
        assertTrue(isActive)
    }

    /** Answers hello, takes the proposal, sends a transcript built around it, and records every frame it gets. */
    private class Computer(private val invitation: PairingInvitation) : PairingTransport {
        var events: PairingTransportEvents? = null
        val outgoing = ArrayDeque<ByteArray>()
        val frames = mutableListOf<PairingSetupFrame>()
        private var buffer = ByteArray(0)
        var cancels = 0
        private fun wire(frame: PairingSetupFrame) = frame.encode().let { body ->
            byteArrayOf((body.size ushr 24).toByte(), (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body }
        override fun start(events: PairingTransportEvents) {
            this.events = events; outgoing.addLast(wire(PairingSetupFrame.Hello)); events.opened()
        }
        override fun requestBytes() { outgoing.removeFirstOrNull()?.let { events!!.received(it) } }
        override fun send(bytes: ByteArray, completion: PairingSendCompletion) {
            buffer += bytes; completion.done(null)
            while (buffer.size >= 4) {
                val length = buffer.take(4).fold(0) { v, b -> (v shl 8) or (b.toInt() and 255) }
                if (buffer.size < 4 + length) return
                val frame = PairingSetupFrame.decode(buffer.copyOfRange(4, 4 + length))
                buffer = buffer.copyOfRange(4 + length, buffer.size); frames += frame
                if (frame is PairingSetupFrame.Proposal) {
                    val p = frame.value
                    outgoing.addLast(wire(PairingSetupFrame.Transcript(PairingTranscript(ByteArray(16) { 1 }, ByteArray(32) { 2 },
                        p.phone, ChannelOffer(ChannelRole.MAC, p.phone.scope, ByteArray(32) { 3 }, setOf(1u), emptyList(), emptySet()),
                        1u, 1u, invitation.authorityPublicKey.copyBytes(), invitation.transportPublicKey.copyBytes(),
                        p.transportKey, p.decisionKey, p.biometricKey, ByteArray(32) { 4 }, null, ByteArray(16) { 5 }, 1_000u, 2_000u))))
                }
            }
        }
        override fun cancel() { cancels++; events?.closed("cancelled") }
    }

    @Test fun aComputerThatAnswersGivesTheCodeAndReceivesNoProof(): Unit = runBlocking {
        val computer = Computer(PairingInvitation.importText(text))
        val answering = object : PlatformPairingKeys by keys() {
            override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String) = computer
        }
        val result = testConnection(this, text, answering)
        val reached = assertIs<ConnectionTestState.Reached>(result)
        assertTrue(reached.code.isNotBlank())
        assertEquals(1, computer.frames.size)
        assertIs<PairingSetupFrame.Proposal>(computer.frames.single())
        assertEquals(1, computer.cancels)
    }

    @Test fun theCallersCancellationEscapes(): Unit = runBlocking {
        val silent = object : PlatformPairingKeys by keys() {
            override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String) =
                object : PairingTransport {
                    var events: PairingTransportEvents? = null
                    override fun start(events: PairingTransportEvents) { this.events = events }
                    override fun requestBytes() {}
                    override fun send(bytes: ByteArray, completion: PairingSendCompletion) = completion.done("closed")
                    override fun cancel() { events?.closed("cancelled") }
                }
        }
        val job = launch { testConnection(this, text, silent) }
        delay(100); job.cancelAndJoin()
        assertTrue(job.isCancelled)
    }
}
