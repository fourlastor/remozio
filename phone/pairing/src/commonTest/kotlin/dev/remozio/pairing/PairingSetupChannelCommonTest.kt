package dev.remozio.pairing

import dev.remozio.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.serialization.json.*
import kotlin.test.*

/** Runs on every target, including iOS. Signature-bearing steps stay in the JVM test, which can sign. */
class PairingSetupChannelCommonTest {
    private val vectors = Json.parseToJsonElement(TestVectors.pairingSetup).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun frame(name: String) = hex(vectors.getValue("frames").jsonArray.first {
        it.jsonObject.getValue("name").jsonPrimitive.content == name }.jsonObject.getValue("hex").jsonPrimitive.content)
    private fun wire(frame: ByteArray) = byteArrayOf((frame.size ushr 24).toByte(), (frame.size ushr 16).toByte(),
        (frame.size ushr 8).toByte(), frame.size.toByte()) + frame

    private val proposal = PairingPhoneProposal.decode(hex(vectors.getValue("proposal").jsonPrimitive.content))
    // The shared transcript selects envelope version 2, but this channel only speaks version 1.
    // The test keeps the vector's keys and builds a version 1 transcript around the vector's proposal.
    private val vector = PairingTranscript.decode(hex(vectors.getValue("transcript").jsonPrimitive.content))
    private val transcript = PairingTranscript(ByteArray(16) { 9 }, ByteArray(32) { 10 }, proposal.phone,
        ChannelOffer(ChannelRole.MAC, proposal.phone.scope,
            ByteArray(32) { 11 }, setOf(1u), emptyList(), emptySet()),
        1u, 1u, vector.macAuthorityKey.copyBytes(), vector.macTransportKey.copyBytes(),
        proposal.transportKey, proposal.decisionKey, proposal.biometricKey, ByteArray(32) { 12 }, null, ByteArray(16) { 13 }, 1000u, 2000u)
    private val transcriptFrame: ByteArray get() = PairingSetupFrame.Transcript(transcript).encode()
    private val invitation: PairingInvitation get() {
        val scope = ((DeterministicCbor.decode(transcript.phone.encode(), CborLimits(65_536, 5, 5_000)) as CborValue.Fields)
            .values.getValue(2u) as CborValue.ArrayValue).values.map { (it as CborValue.Bytes).copyBytes() }
        return PairingInvitation(scope[0], scope[1], "Fixture", transcript.macAuthorityKey.copyBytes(),
            transcript.macTransportKey.copyBytes(), 1u)
    }

    private class Stream(initial: List<ByteArray>) : PairingByteStream {
        val sent = mutableListOf<ByteArray>()
        var closes = 0
        private val incoming = Channel<ByteArray?>(Channel.UNLIMITED).also { c -> initial.forEach { c.trySend(it) } }
        fun end() { incoming.trySend(null) }
        override suspend fun awaitOpen() {}
        override suspend fun send(bytes: ByteArray) { sent += bytes }
        override suspend fun receive(): ByteArray? = incoming.receive()
        override fun close() { closes++; incoming.trySend(null) }
        override suspend fun awaitClosed() {}
    }

    @Test fun helloProposalAndTranscriptStageTheTranscript() = runBlocking {
        val stream = Stream(listOf(wire(frame("hello")), wire(transcriptFrame)))
        val parent = SupervisorJob()
        val channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, invitation, proposal)
        try {
            assertContentEquals(transcript.encode(), channel.transcript.encode())
            val wireBytes = stream.sent.fold(ByteArray(0)) { a, b -> a + b }
            assertContentEquals(wire(PairingSetupFrame.Proposal(proposal).encode()), wireBytes)
        } finally { channel.closeAndJoin(); parent.cancelAndJoin() }
        assertEquals(1, stream.closes)
    }

    @Test fun wrongFirstFrameClosesTheStreamBeforeAnythingIsSent() = runBlocking {
        val stream = Stream(listOf(wire(frame("proposal"))))
        val parent = SupervisorJob()
        try { assertFails { PairingSetupChannel.authenticate(CoroutineScope(parent), stream, invitation, proposal) } }
        finally { parent.cancelAndJoin() }
        assertTrue(stream.sent.isEmpty())
        assertTrue(stream.closes >= 1)
    }

    @Test fun truncatedHelloClosesTheStream() = runBlocking {
        val stream = Stream(listOf(wire(frame("hello")).copyOf(3))).also { it.end() }
        val parent = SupervisorJob()
        try { assertFails { PairingSetupChannel.authenticate(CoroutineScope(parent), stream, invitation, proposal) } }
        finally { parent.cancelAndJoin() }
        assertTrue(stream.sent.isEmpty())
        assertTrue(stream.closes >= 1)
    }

    @Test fun cancellingTheParentClosesTheStream() = runBlocking {
        val stream = Stream(listOf(wire(frame("hello")), wire(transcriptFrame)))
        val parent = SupervisorJob()
        val channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, invitation, proposal)
        parent.cancelAndJoin()
        withTimeout(2_000) { while (stream.closes == 0) delay(10) }
        channel.closeAndJoin()
    }

    @Test fun aWrongConfirmedDigestIsRefusedBeforeAnythingIsSubmitted() = runBlocking {
        val stream = Stream(listOf(wire(frame("hello")), wire(transcriptFrame)))
        val parent = SupervisorJob()
        val channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, invitation, proposal)
        try {
            val before = stream.sent.size
            assertFails { channel.submitProof(ByteArray(32), ByteArray(64)) }
            assertEquals(before, stream.sent.size)
        } finally { channel.closeAndJoin(); parent.cancelAndJoin() }
    }
}
