package dev.remozio.pairing

import dev.remozio.protocol.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import kotlin.test.*

/** The platform attempt against a scripted computer that speaks the setup frames through the callback contract. */
class PlatformPairingAttemptTest {
    private val vectors = Json.parseToJsonElement(TestVectors.pairingSetup).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val vectorProposal = PairingPhoneProposal.decode(hex(vectors.getValue("proposal").jsonPrimitive.content))
    private val vectorTranscript = PairingTranscript.decode(hex(vectors.getValue("transcript").jsonPrimitive.content))
    private val scope = ((DeterministicCbor.decode(vectorProposal.phone.encode(), CborLimits(65_536, 5, 5_000)) as CborValue.Fields)
        .values.getValue(2u) as CborValue.ArrayValue).values.map { (it as CborValue.Bytes).copyBytes() }
    private val invitation = PairingInvitation(scope[0], scope[1], "Fixture", vectorTranscript.macAuthorityKey.copyBytes(),
        vectorTranscript.macTransportKey.copyBytes(), 1u)

    private fun wire(frame: ByteArray) = byteArrayOf((frame.size ushr 24).toByte(), (frame.size ushr 16).toByte(),
        (frame.size ushr 8).toByte(), frame.size.toByte()) + frame

    /** Sends hello, reads the proposal, answers with a transcript built around it. */
    private class Host(private val mac: PairingInvitation, private val foreignTransportKeyID: Boolean = false) : PairingTransport {
        var events: PairingTransportEvents? = null
        val outgoing = ArrayDeque<ByteArray>()
        var received = ByteArray(0)
        var proposal: PairingPhoneProposal? = null
        var cancels = 0
        override fun start(events: PairingTransportEvents) {
            this.events = events
            outgoing.addLast(PairingSetupFrame.Hello.encode().let { byteArrayOf(0, 0, 0, it.size.toByte()) + it })
            events.opened()
        }
        override fun requestBytes() { outgoing.removeFirstOrNull()?.let { events!!.received(it) } }
        override fun send(bytes: ByteArray, completion: PairingSendCompletion) {
            received += bytes; completion.done(null)
            if (received.size < 4) return
            val length = received.take(4).fold(0) { v, b -> (v shl 8) or (b.toInt() and 255) }
            if (received.size < 4 + length) return
            val frame = PairingSetupFrame.decode(received.copyOfRange(4, 4 + length)) as PairingSetupFrame.Proposal
            val p = frame.value; proposal = p
            val transcript = PairingTranscript(ByteArray(16) { 1 }, ByteArray(32) { 2 }, p.phone,
                ChannelOffer(ChannelRole.MAC, p.phone.scope, ByteArray(32) { 3 }, setOf(1u), emptyList(), emptySet()),
                1u, 1u, mac.authorityPublicKey.copyBytes(), mac.transportPublicKey.copyBytes(),
                if (foreignTransportKeyID) PairingKey(ByteArray(16) { 7 }, p.transportKey.publicKey.copyBytes()) else p.transportKey, p.decisionKey, p.biometricKey, ByteArray(32) { 4 }, null,
                ByteArray(16) { 5 }, 1_000u, 2_000u)
            val encoded = PairingSetupFrame.Transcript(transcript).encode()
            val wire = byteArrayOf((encoded.size ushr 24).toByte(), (encoded.size ushr 16).toByte(),
                (encoded.size ushr 8).toByte(), encoded.size.toByte()) + encoded
            outgoing.addLast(wire)
        }
        override fun cancel() { cancels++; events?.closed("cancelled") }
    }

    private class Keys(val host: Host) : PlatformPairingKeys {
        override lateinit var transportPublicKey: ByteArray
        override lateinit var decisionPublicKey: ByteArray
        override lateinit var biometricPublicKey: ByteArray
        var opened: List<Any>? = null
        override fun openTransport(macID: ByteArray, accountID: ByteArray, pin: ByteArray, applicationProtocol: String): PairingTransport {
            opened = listOf(macID, accountID, pin, applicationProtocol); return host
        }
    }

    private fun keys(host: Host) = Keys(host).apply {
        transportPublicKey = vectorProposal.transportKey.publicKey.copyBytes()
        decisionPublicKey = vectorProposal.decisionKey.publicKey.copyBytes()
        biometricPublicKey = vectorProposal.biometricKey.publicKey.copyBytes()
    }

    @Test fun theProposalCarriesThePlatformKeysAndTheTranscriptIsStaged(): Unit = runBlocking {
        val host = Host(invitation); val keys = keys(host)
        val parent = SupervisorJob()
        val channel = PairingSetupChannel.connectPlatform(CoroutineScope(parent), invitation, keys)
        try {
            val proposal = assertNotNull(host.proposal)
            assertContentEquals(keys.transportPublicKey, proposal.transportKey.publicKey.copyBytes())
            assertContentEquals(keys.decisionPublicKey, proposal.decisionKey.publicKey.copyBytes())
            assertContentEquals(keys.biometricPublicKey, proposal.biometricKey.publicKey.copyBytes())
            proposal.validateMacScope(invitation)
            assertTrue(channel.transcript.verificationCode().isNotEmpty())
            val (macID, accountID, pin, alpn) = assertNotNull(keys.opened)
            assertContentEquals(invitation.macID.copyBytes(), macID as ByteArray)
            assertContentEquals(invitation.accountID.copyBytes(), accountID as ByteArray)
            assertContentEquals(P256_SPKI_PREFIX + invitation.transportPublicKey.copyBytes(), pin as ByteArray)
            assertEquals(91, pin.size)
            assertEquals("remozio-pairing/1", alpn)
        } finally { channel.closeAndJoin(); parent.cancelAndJoin() }
        assertEquals(1, host.cancels)
    }

    @Test fun eachAttemptUsesFreshIdentifiers(): Unit = runBlocking {
        val first = Host(invitation); val second = Host(invitation)
        val parent = SupervisorJob()
        try {
            PairingSetupChannel.connectPlatform(CoroutineScope(parent), invitation, keys(first)).closeAndJoin()
            PairingSetupChannel.connectPlatform(CoroutineScope(parent), invitation, keys(second)).closeAndJoin()
        } finally { parent.cancelAndJoin() }
        val a = assertNotNull(first.proposal); val b = assertNotNull(second.proposal)
        assertFalse(a.transportKey.keyID == b.transportKey.keyID)
        assertFalse(a.phone.nonce == b.phone.nonce)
        assertFalse(a.phone.encode().contentEquals(b.phone.encode()))
    }

    @Test fun aTranscriptWithAnotherTransportKeyIDIsRefused(): Unit = runBlocking {
        val host = Host(invitation, foreignTransportKeyID = true)
        val parent = SupervisorJob()
        try { assertFails { PairingSetupChannel.connectPlatform(CoroutineScope(parent), invitation, keys(host)) } }
        finally { parent.cancelAndJoin() }
        assertEquals(1, host.cancels)
    }

    @Test fun platformKeysEqualToTheComputerKeysNeverOpenATransport(): Unit = runBlocking {
        val host = Host(invitation)
        val keys = keys(host).apply { transportPublicKey = invitation.transportPublicKey.copyBytes() }
        val parent = SupervisorJob()
        try { assertFails { PairingSetupChannel.connectPlatform(CoroutineScope(parent), invitation, keys) } }
        finally { parent.cancelAndJoin() }
        assertNull(keys.opened)
        assertNull(host.events)
    }

    @Test fun thePinPrefixIsTheP256SubjectPublicKeyInfoHeader() {
        assertEquals("3059301306072a8648ce3d020106082a8648ce3d030107034200",
            P256_SPKI_PREFIX.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') })
    }
}
