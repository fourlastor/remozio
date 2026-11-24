package dev.remozio.pairing

import dev.remozio.protocol.ChannelOffer
import dev.remozio.protocol.ChannelRole
import dev.remozio.protocol.PairingInvitation
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.PairingPhoneProposal
import dev.remozio.protocol.PairingSetupFrame
import dev.remozio.protocol.PairingSetupPreludeV2
import dev.remozio.protocol.PairingTranscript
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class IosPairingV2PreviewTest {
    private val vectors = Json.parseToJsonElement(TestVectors.pairingSetup).jsonObject
    private fun bytes(name: String) = vectors.getValue(name).jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val proposal = PairingPhoneProposal.decode(bytes("proposal"))
    private val transcript = PairingTranscript.decode(bytes("transcript"))
    private val mac = PairingInvitation(ByteArray(16) { 1 }, ByteArray(16) { 2 }, "Test Mac",
        transcript.macAuthorityKey.copyBytes(), transcript.macTransportKey.copyBytes(), 1u)
    private val invitation = PairingInvitationV2(mac, ByteArray(16) { 3 }, ByteArray(32) { 4 }, lifetimeMilliseconds = 30_000u)

    @Test fun importAcceptsV2AndRejectsLegacyAndMalformedInput() {
        val text = invitation.exportText()
        assertEquals("Test Mac", assertNotNull(IosPairingV2Preview.parseInvitation("  $text\n")).label)
        assertNull(IosPairingV2Preview.parseInvitation(mac.exportText()))
        assertNull(IosPairingV2Preview.parseInvitation(text + "!"))
        assertNull(IosPairingV2Preview.parseInvitation(text.padEnd(1_101, 'a')))
    }

    @Test fun previewUsesTheTransportExporterAndClosesAtTheTranscript(): Unit = runBlocking {
        val host = Host()
        val code = previewPairingV2(this, invitation, keys(host))
        assertEquals(assertNotNull(host.staged).verificationCode(), code)
        assertEquals(1, host.closeCount)
        assertEquals(1, host.proposalCount)
        assertContentEquals(ByteArray(32), host.borrowedExporter)
    }

    @Test fun missingExporterClosesWithoutAProposal(): Unit = runBlocking {
        val host = Host(offerExporter = false)
        assertFailsWith<IOException> { previewPairingV2(this, invitation, keys(host)) }
        assertEquals(0, host.proposalCount)
        assertEquals(1, host.closeCount)
    }

    @Test fun cancellationClosesWhileWaitingForTheChallenge(): Unit = runBlocking {
        val host = Host(sendChallenge = false)
        val attempt = async { previewPairingV2(this, invitation, keys(host)) }
        withTimeout(5_000) { host.requested.await() }
        attempt.cancelAndJoin()
        assertEquals(0, host.proposalCount)
        assertEquals(1, host.closeCount)
    }

    private fun keys(host: Host) = object : PlatformPairingKeys {
        override val transportPublicKey = proposal.transportKey.publicKey.copyBytes()
        override val decisionPublicKey = proposal.decisionKey.publicKey.copyBytes()
        override val biometricPublicKey = proposal.biometricKey.publicKey.copyBytes()
        override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String): PairingTransport {
            assertContentEquals(mac.macID.copyBytes(), macID)
            assertContentEquals(mac.accountID.copyBytes(), accountID)
            assertContentEquals(P256_SPKI_PREFIX + mac.transportPublicKey.copyBytes(), pin)
            assertEquals(PairingSetupPreludeV2.APPLICATION_PROTOCOL, applicationProtocol)
            return host
        }
    }

    private inner class Host(private val offerExporter: Boolean = true, sendChallenge: Boolean = true) : IosPairingV2Transport {
        private val challenge = ByteArray(32) { 5 }
        private val outgoing = ArrayDeque<ByteArray>()
        private var incoming = ByteArray(0)
        private lateinit var events: PairingTransportEvents
        val requested = CompletableDeferred<Unit>()
        var borrowedExporter: ByteArray? = null
        var staged: PairingTranscript? = null
        var proposalCount = 0
        var closeCount = 0

        init {
            if (sendChallenge) outgoing.addLast(wire(PairingSetupPreludeV2.Challenge(challenge).encode()))
        }

        override fun start(events: PairingTransportEvents) {
            this.events = events
            events.opened()
        }

        override fun requestBytes() {
            requested.complete(Unit)
            outgoing.removeFirstOrNull()?.let(events::received)
        }

        override fun takeInvitationExporter(): ByteArray? =
            if (offerExporter) ByteArray(32) { 6 }.also { borrowedExporter = it } else null

        override fun send(bytes: ByteArray, completion: PairingSendCompletion) {
            incoming += bytes
            if (incoming.size >= 4) {
                val size = incoming.take(4).fold(0) { value, byte -> (value shl 8) or (byte.toInt() and 255) }
                if (incoming.size == size + 4) {
                    val frame = PairingSetupPreludeV2.decode(incoming.copyOfRange(4, incoming.size)) as PairingSetupPreludeV2.Proposal
                    assertEquals(0, proposalCount++)
                    assertContentEquals(invitation.proof(frame.value, challenge, ByteArray(32) { 6 }), frame.tag.copyBytes())
                    val phone = frame.value
                    val session = PairingTranscript(ByteArray(16) { 7 }, ByteArray(32) { 8 }, phone.phone,
                        ChannelOffer(ChannelRole.MAC, phone.phone.scope, ByteArray(32) { 9 }, setOf(1u), emptyList(), emptySet()),
                        1u, 1u, mac.authorityPublicKey.copyBytes(), mac.transportPublicKey.copyBytes(),
                        phone.transportKey, phone.decisionKey, phone.biometricKey, ByteArray(32) { 10 }, null,
                        ByteArray(16) { 11 }, 1_000u, 2_000u)
                    staged = session
                    outgoing.addLast(wire(PairingSetupFrame.Transcript(session).encode()))
                    incoming = ByteArray(0)
                }
            }
            completion.done(null)
        }

        override fun cancel() {
            closeCount++
            events.closed("cancelled")
        }
    }

    private fun wire(body: ByteArray) = byteArrayOf((body.size ushr 24).toByte(), (body.size ushr 16).toByte(),
        (body.size ushr 8).toByte(), body.size.toByte()) + body
}
