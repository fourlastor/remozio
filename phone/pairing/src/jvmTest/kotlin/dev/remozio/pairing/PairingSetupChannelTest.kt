package dev.remozio.pairing

import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import org.junit.Test
import kotlin.test.*

class PairingSetupChannelTest {
    private fun key(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun point(key: KeyPair): ByteArray {
        val p = (key.public as ECPublicKey).w
        fun scalar(n: java.math.BigInteger): ByteArray = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        return byteArrayOf(4) + scalar(p.affineX) + scalar(p.affineY)
    }
    private fun sign(key: KeyPair, input: ByteArray): ByteArray = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
        initSign(key.private); update(input); sign()
    })
    private inner class Fixture {
        val authority = key(); val macTransport = key(); val transport = key(); val decision = key(); val biometric = key()
        val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val offer = ChannelOffer(ChannelRole.PHONE, scope, ByteArray(32) { 5 }, setOf(1u), emptyList(), emptySet())
        val proposal = PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 6 }, point(transport)),
            PairingKey(ByteArray(16) { 7 }, point(decision)), PairingKey(ByteArray(16) { 8 }, point(biometric)))
        val invitation = PairingInvitation(ByteArray(16) { 1 }, ByteArray(16) { 2 }, "Fixture", point(authority), point(macTransport), 1u)
        val transcript = transcriptFor(proposal)
        fun transcriptFor(claims: PairingPhoneProposal) = PairingTranscript(
            ByteArray(16) { 9 }, ByteArray(32) { 10 }, claims.phone,
            ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 11 }, setOf(1u), emptyList(), emptySet()), 1u, 1u,
            point(authority), point(macTransport), claims.transportKey, claims.decisionKey, claims.biometricKey,
            ByteArray(32) { 12 }, null, ByteArray(16) { 13 }, 1000u, 2000u)
        fun proof() = sign(biometric, transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC))
        fun receipt() = sign(authority, transcript.signingInput(PairingProofPurpose.MAC_COMMIT))
    }
    private fun wire(frame: PairingSetupFrame): ByteArray = frame.encode().let { ByteBuffer.allocate(it.size + 4).putInt(it.size).put(it).array() }
    private inner class Stream(val f: Fixture, val fragment: Int = 32768, val lostReceipt: Boolean = false,
        val wrongReceipt: Boolean = false, val omitTranscript: Boolean = false, val initial: ByteArray? = null,
    ) : PairingByteStream {
        val output = ByteArrayOutputStream()
        val input = ArrayDeque<ByteArray>()
        val suspended = CompletableDeferred<Unit>()
        val ended = CompletableDeferred<ByteArray?>()
        var proofSubmissions = 0; var proposalSubmissions = 0; var closes = 0
        var sentBytes = 0
        init { queue(initial ?: wire(PairingSetupFrame.Hello)) }
        fun queue(bytes: ByteArray) { bytes.toList().chunked(fragment).forEach { input.add(it.toByteArray()) } }
        override suspend fun awaitOpen() {}
        override suspend fun send(bytes: ByteArray) {
            sentBytes += bytes.size
            output.write(bytes); val all = output.toByteArray()
            if (all.size < 4) return
            val n = ByteBuffer.wrap(all).int
            if (all.size < n + 4) return
            check(all.size == n + 4); output.reset()
            when (val frame = PairingSetupFrame.decode(all.copyOfRange(4, all.size))) {
                is PairingSetupFrame.Proposal -> { proposalSubmissions++; frame.value.validate(f.transcript); if (!omitTranscript) queue(wire(PairingSetupFrame.Transcript(f.transcript))) }
                is PairingSetupFrame.Proof -> {
                    proofSubmissions++
                    require(frame.setupID == f.transcript.setupID && frame.digest == CborValue.Bytes(f.transcript.digest()))
                    require(f.transcript.verify(frame.signature.copyBytes(), point(f.biometric), PairingProofPurpose.PHONE_BIOMETRIC))
                    if (lostReceipt) throw IOException("Synthetic lost reply after proof")
                    val signature = if (wrongReceipt) sign(f.authority, f.transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC)) else f.receipt()
                    queue(wire(PairingSetupFrame.Receipt(f.transcript.setupID.copyBytes(), f.transcript.digest(), signature)))
                }
                else -> error("Unexpected setup message")
            }
        }
        override suspend fun receive(): ByteArray? {
            if (input.isNotEmpty()) return input.removeFirst()
            suspended.complete(Unit); return ended.await()
        }
        override fun close() { closes++; ended.complete(null) }
        override suspend fun awaitClosed() {}
    }
    @Test fun fragmentedAndCoalescedFramesProduceOneVerifiedReceipt(): Unit = runBlocking {
        for (fragment in listOf(1,32768)) {
            val f = Fixture(); val stream = Stream(f, fragment); val parent = SupervisorJob(); var channel: PairingSetupChannel? = null
            try {
                channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, f.invitation, f.proposal)
                assertContentEquals(f.transcript.encode(), channel.transcript.encode())
                val receipt = channel.submitProof(f.transcript.digest(), f.proof())
                assertTrue(f.transcript.verify(receipt, point(f.authority), PairingProofPurpose.MAC_COMMIT))
                assertEquals(1,stream.proofSubmissions)
                assertFails { channel.submitProof(f.transcript.digest(), f.proof()) }
            } finally { channel?.closeAndJoin(); parent.cancelAndJoin() }
            assertEquals(1,stream.closes)
        }
    }
    @Test fun lostOrInvalidReceiptClosesWithoutRepeatingSubmission(): Unit = runBlocking {
        for (lost in listOf(true,false)) {
            val f = Fixture(); val stream = Stream(f, lostReceipt = lost, wrongReceipt = !lost); val parent = SupervisorJob()
            val channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, f.invitation, f.proposal)
            try {
                assertFails { channel.submitProof(f.transcript.digest(), f.proof()) }
                assertFails { channel.submitProof(f.transcript.digest(), f.proof()) }
                assertEquals(1,stream.proofSubmissions)
            } finally { channel.closeAndJoin(); parent.cancelAndJoin() }
        }
    }
    @Test fun failedBeforeProofCallbackSendsZeroProofBytes(): Unit = runBlocking {
        val fixture = Fixture()
        val stream = Stream(fixture)
        val parent = SupervisorJob()
        val channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, fixture.invitation, fixture.proposal)
        try {
            val before = stream.sentBytes
            var checkpointCalls = 0
            assertFailsWith<IOException> {
                channel.submitProof(fixture.transcript.digest(), fixture.proof()) {
                    checkpointCalls++
                    throw IOException("Synthetic archive write failure")
                }
            }
            assertEquals(1, checkpointCalls)
            assertEquals(before, stream.sentBytes)
            assertEquals(0, stream.proofSubmissions)
            assertFails { channel.submitProof(fixture.transcript.digest(), fixture.proof()) }
            assertEquals(before, stream.sentBytes)
        } finally {
            channel.closeAndJoin()
            parent.cancelAndJoin()
        }
    }

    @Test fun invalidConfirmationAndProofSendNothing(): Unit = runBlocking {
        for (wrongDigest in listOf(true,false)) {
            val f = Fixture(); val stream = Stream(f); val parent = SupervisorJob()
            val channel = PairingSetupChannel.connect(CoroutineScope(parent), stream, f.invitation, f.proposal)
            try {
                assertFails { channel.submitProof(if (wrongDigest) ByteArray(32) else f.transcript.digest(), if (wrongDigest) f.proof() else ByteArray(64)) }
                assertEquals(0,stream.proofSubmissions)
            } finally { channel.closeAndJoin(); parent.cancelAndJoin() }
        }
    }
    @Test fun expiryAndParentCancellationCloseASuspendedExchange(): Unit = runBlocking {
        supervisorScope { for (expire in listOf(true,false)) {
            val f = Fixture(); val stream = Stream(f,omitTranscript=true); val parent = SupervisorJob()
            val pending = async { PairingSetupChannel.connect(CoroutineScope(parent),stream,f.invitation,f.proposal,if(expire) 500 else 300000) }
            withTimeout(2000) { stream.suspended.await() }
            if (!expire) parent.cancel()
            try { assertFails { withTimeout(2000) { pending.await() } } }
            finally { parent.cancelAndJoin() }
            assertEquals(1,stream.closes)
        } }
    }
    @Test fun authenticatedRouteSendsNoProposalAndHumanTranscriptWaitUsesTheLongerDeadline(): Unit = runBlocking {
        val f = Fixture(); val stream = Stream(f, omitTranscript = true); val parent = SupervisorJob()
        val channel = withTimeout(500) {
            PairingSetupChannel.authenticate(CoroutineScope(parent), stream, f.invitation, f.proposal)
        }
        try {
            assertEquals(0, stream.proposalSubmissions)
            assertFails { channel.transcript }
            val pending = async { channel.awaitTranscript() }
            stream.suspended.await()
            delay(600)
            assertFalse(pending.isCompleted)
            stream.ended.complete(wire(PairingSetupFrame.Transcript(f.transcript)))
            assertContentEquals(f.transcript.encode(), pending.await().encode())
            assertEquals(1, stream.proposalSubmissions)
            assertFails { channel.awaitTranscript() }
        } finally { channel.closeAndJoin(); parent.cancelAndJoin() }
    }
    @Test fun unknownVersionAndOversizedHeaderRejectBeforeProposal(): Unit = runBlocking {
        val f=Fixture()
        val fields=(DeterministicCbor.decode(PairingSetupFrame.Hello.encode(),CborLimits(132256,2,20)) as CborValue.Fields).values
        val badHello=DeterministicCbor.encode(CborValue.Fields(fields+(1uL to CborValue.Unsigned(2u))),CborLimits(132256,2,20))
        for (bytes in listOf(ByteBuffer.allocate(badHello.size+4).putInt(badHello.size).put(badHello).array(), ByteBuffer.allocate(4).putInt(132257).array())) {
            val stream=Stream(f,initial=bytes); val parent=SupervisorJob()
            try { assertFails { PairingSetupChannel.connect(CoroutineScope(parent),stream,f.invitation,f.proposal) }; assertEquals(0,stream.output.size()) }
            finally { parent.cancelAndJoin() }
        }
    }

    private inner class V2Stream(val fixture: Fixture, challenge: ByteArray = ByteArray(32) { 21 },
        val material: ByteArray = ByteArray(32) { 22 }, reply: PairingTranscript? = fixture.transcript,
    ) : PairingV2ByteStream {
        private val inbound = ArrayDeque<ByteArray>()
        val sent = ByteArrayOutputStream()
        private val ended = CompletableDeferred<ByteArray?>()

        init {
            val encoded = PairingSetupPreludeV2.Challenge(challenge).encode()
            inbound.add(ByteBuffer.allocate(4 + encoded.size).putInt(encoded.size).put(encoded).array())
            reply?.let { inbound.add(wire(PairingSetupFrame.Transcript(it))) }
        }

        override fun pairingExporter() = material.copyOf()
        override suspend fun awaitOpen() {}
        override suspend fun send(bytes: ByteArray) { sent.write(bytes) }
        override suspend fun receive(): ByteArray? = inbound.removeFirstOrNull() ?: ended.await()
        override fun close() { ended.complete(null) }
        override suspend fun awaitClosed() {}
    }

    @Test fun v2SendsOneProofAndChecksTheTranscript(): Unit = runBlocking {
        val f = Fixture()
        val stream = V2Stream(f)
        val credentials = PairingInvitationV2(f.invitation, ByteArray(16) { 19 }, ByteArray(32) { 20 },
            lifetimeMilliseconds = 10_000u)
        val channel = PairingSetupChannel.authenticate(this, stream, f.invitation, f.proposal)
        try {
            assertEquals(0, stream.sent.size())
            var checkpoint = false
            val result = channel.awaitTranscriptV2(credentials) {
                assertEquals(0, stream.sent.size())
                checkpoint = true
            }
            assertTrue(checkpoint)
            assertContentEquals(f.transcript.encode(), result.encode())
            val bytes = ByteBuffer.wrap(stream.sent.toByteArray())
            val size = bytes.int
            assertEquals(size, bytes.remaining())
            val proof = assertIs<PairingSetupPreludeV2.Proposal>(
                PairingSetupPreludeV2.decode(ByteArray(size).also { bytes.get(it) }))
            assertContentEquals(f.proposal.encode(), proof.value.encode())
            assertContentEquals(credentials.proof(f.proposal, ByteArray(32) { 21 }, stream.material), proof.tag.copyBytes())
            assertFails { channel.awaitTranscriptV2(credentials) }
            assertEquals(size + 4, stream.sent.size())
        } finally {
            channel.closeAndJoin()
        }
    }

    @Test fun v2RejectsLegacyProposalAndMissingExporterBeforeAnyWrite(): Unit = runBlocking {
        val f = Fixture()
        val credentials = PairingInvitationV2(f.invitation, ByteArray(16) { 19 }, ByteArray(32) { 20 },
            lifetimeMilliseconds = 10_000u)
        for (legacy in listOf(true, false)) {
            val stream = V2Stream(f, material = ByteArray(0))
            val channel = PairingSetupChannel.authenticate(this, stream, f.invitation, f.proposal)
            try {
                if (legacy) assertFails { channel.awaitTranscript() }
                else assertFails { channel.awaitTranscriptV2(credentials) }
                assertEquals(0, stream.sent.size())
            } finally {
                channel.closeAndJoin()
            }
        }
    }

    @Test fun v2CancellationAfterProofDoesNotRepeatSubmission(): Unit = runBlocking {
        val f = Fixture()
        val stream = V2Stream(f, reply = null)
        val credentials = PairingInvitationV2(f.invitation, ByteArray(16) { 19 }, ByteArray(32) { 20 },
            lifetimeMilliseconds = 10_000u)
        val channel = PairingSetupChannel.authenticate(this, stream, f.invitation, f.proposal)
        try {
            assertFailsWith<TimeoutCancellationException> {
                withTimeout(500) { channel.awaitTranscriptV2(credentials) }
            }
            val bytes = stream.sent.toByteArray()
            assertTrue(bytes.size > 4)
            assertFails { channel.awaitTranscriptV2(credentials) }
            assertContentEquals(bytes, stream.sent.toByteArray())
        } finally {
            channel.closeAndJoin()
        }
    }

    @Test fun v2RejectsATranscriptThatChangesTheProvedDecisionKey(): Unit = runBlocking {
        val f = Fixture()
        val credentials = PairingInvitationV2(f.invitation, ByteArray(16) { 19 }, ByteArray(32) { 20 },
            lifetimeMilliseconds = 10_000u)
        val changed = PairingPhoneProposal(f.offer, f.proposal.transportKey,
            PairingKey(f.proposal.decisionKey.keyID.copyBytes(), point(key())), f.proposal.biometricKey)
        val response = f.transcriptFor(changed)
        f.invitation.validateMacClaims(response)
        val stream = V2Stream(f, reply = response)
        val channel = PairingSetupChannel.authenticate(this, stream, f.invitation, f.proposal)
        try {
            assertFailsWith<IllegalArgumentException> { channel.awaitTranscriptV2(credentials) }
            val sent = ByteBuffer.wrap(stream.sent.toByteArray())
            val size = sent.int
            assertEquals(size, sent.remaining())
            val proof = assertIs<PairingSetupPreludeV2.Proposal>(
                PairingSetupPreludeV2.decode(ByteArray(size).also { sent.get(it) }))
            assertContentEquals(f.proposal.encode(), proof.value.encode())
            assertFails { channel.transcript }
        } finally {
            channel.closeAndJoin()
        }
    }

}
