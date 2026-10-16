package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class PairingReceiptChannelTest {
    private fun id(value: Int) = ByteArray(16) { value.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = key()
    private fun record(phone: Int = 3): StoredPhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val point = key().public.encoded
            return EnrollmentKeyReference(role, id(role.ordinal + 10),
                "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
                if (role == EnrollmentKeyRole.TRANSPORT) point else point.takeLast(65).toByteArray())
        }
        val enrollment = PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic Mac",
            authority.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { 5 }, null)
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        fun offer(role: ChannelRole, nonce: Int) = ChannelOffer(role, scope, ByteArray(32) { nonce.toByte() }, setOf(1uL), emptyList(), emptySet())
        fun claim(ref: EnrollmentKeyReference) = PairingKey(ref.keyID.copyBytes(), ref.publicKey.copyBytes().takeLast(65).toByteArray())
        val transcript = PairingTranscript(id(70), ByteArray(32) { 71 }, offer(ChannelRole.PHONE, 72), offer(ChannelRole.MAC, 73),
            1u, 1u, enrollment.authorityPublicKey.copyBytes(), enrollment.transportPublicKey.copyBytes().takeLast(65).toByteArray(),
            claim(enrollment.transportKey), claim(enrollment.decisionKey), claim(enrollment.biometricKey), enrollment.enrollmentTag.copyBytes(),
            null, id(74), 1000u, 2000u)
        return StoredPhoneEnrollment(enrollment, EnrollmentPhase.PREPARED, PreparedPairing(transcript, null, 1u))
    }
    private fun sign(record: StoredPhoneEnrollment, signingKey: KeyPair = authority,
                     purpose: PairingProofPurpose = PairingProofPurpose.MAC_COMMIT) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(signingKey.private); update(checkNotNull(record.pairing).transcript.signingInput(purpose)); sign()
    }
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private inner class Peer(record: StoredPhoneEnrollment, private val reply: ByteArray?) : ApprovalByteStream {
        val transcript = checkNotNull(record.pairing).transcript
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, transcript.phone.scope, ByteArray(32) { 9 },
            setOf(1u), emptyList(), emptySet()), 1u)
        val offer = owner.offer()
        val output = ByteArrayOutputStream()
        val input = ArrayDeque<ByteArray>()
        val waiting = CompletableDeferred<Unit>()
        var phase = 0
        var queries = 0
        var closes = 0
        override suspend fun awaitOpen() = Unit
        override suspend fun send(bytes: ByteArray) {
            output.write(bytes)
            val all = output.toByteArray()
            if (all.size < 4) return
            val count = ByteBuffer.wrap(all).int
            if (all.size < count + 4) return
            check(all.size == count + 4); output.reset()
            val body = all.copyOfRange(4, all.size)
            when (phase++) {
                0 -> { owner.receiveOffer(body); input.add(frame(offer)) }
                1 -> { owner.receiveConfirmation(body); input.add(frame(owner.confirmation())) }
                else -> {
                    val envelope = SessionEnvelope.decode(body, PairingReceiptFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID)
                    assertEquals(0uL, envelope.sequence)
                    val query = assertIs<PairingReceiptFrame.Query>(PairingReceiptFrame.decode(envelope.payload.copyBytes()))
                    assertEquals(transcript.setupID, query.setupID); queries++
                    if (reply != null) input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, reply).encode(PairingReceiptFrame.MAXIMUM_BYTES)))
                }
            }
        }
        override suspend fun receive(): ByteArray {
            if (input.isNotEmpty()) return input.removeFirst()
            waiting.complete(Unit); awaitCancellation()
        }
        override fun close() { closes++; owner.close() }
        override suspend fun awaitClosed() = Unit
    }
    private suspend fun connect(record: StoredPhoneEnrollment, peer: Peer,
        purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.PAIRING_RECEIPT) = NegotiatedTLSChannel.connect(
        peer, checkNotNull(record.pairing).transcript.phone.scope, emptyList(), emptySet(), PairingReceiptFrame.MAXIMUM_BYTES, purpose = purpose)

    @Test fun committedReceiptCanRecoverAnExpiredSetupWithoutAnotherProof() = runTest {
        val record = record(); val signature = sign(record)
        val peer = Peer(record, PairingReceiptFrame.Response(checkNotNull(record.pairing).transcript.setupID.copyBytes(), signature).encode())
        val channel = PairingReceiptChannel.bind(record, connect(record, peer))
        assertContentEquals(signature, channel.recover())
        assertEquals(1, peer.queries)
        assertFails { channel.recover() }; assertEquals(1, peer.queries)
        channel.closeAndJoin(); assertEquals(1, peer.closes)
    }
    @Test fun unavailableReceiptIsNotAnEnrollmentOutcome() = runTest {
        val record = record()
        val peer = Peer(record, PairingReceiptFrame.Response(checkNotNull(record.pairing).transcript.setupID.copyBytes(), null).encode())
        val channel = PairingReceiptChannel.bind(record, connect(record, peer))
        assertNull(channel.recover()); assertEquals(1, peer.queries)
        channel.closeAndJoin(); assertEquals(1, peer.closes)
    }
    @Test fun wrongSetupAuthorityPurposeAndMessageTypeCannotReturnAProof() = runTest {
        val record = record(); val setup = checkNotNull(record.pairing).transcript.setupID.copyBytes()
        val replies = listOf(
            PairingReceiptFrame.Response(id(99), sign(record)).encode(),
            PairingReceiptFrame.Response(setup, sign(record, key())).encode(),
            PairingReceiptFrame.Response(setup, sign(record, purpose = PairingProofPurpose.PHONE_BIOMETRIC)).encode(),
            PairingReceiptFrame.Query(setup).encode(), byteArrayOf(1),
        )
        for (reply in replies) {
            val peer = Peer(record, reply)
            val channel = PairingReceiptChannel.bind(record, connect(record, peer))
            assertFails { channel.recover() }; assertEquals(1, peer.queries)
            channel.closeAndJoin(); assertEquals(1, peer.closes)
        }
    }
    @Test fun wrongPurposeOrEnrollmentStopsBeforeTheQuery() = runTest {
        val record = record()
        val legacy = Peer(record, null)
        assertFails { PairingReceiptChannel.bind(record, connect(record, legacy, EnrolledChannelPurpose.APPROVALS)) }
        assertEquals(0, legacy.queries); assertEquals(1, legacy.closes)
        val other = Peer(record, null)
        val channel = connect(record, other)
        assertFails { PairingReceiptChannel.bind(record(phone = 6), channel) }
        assertEquals(0, other.queries); assertEquals(1, other.closes)
    }
    @Test fun cancellationClosesTheReadAndCannotResubmitAnything() = runTest {
        val record = record(); val peer = Peer(record, null)
        val channel = PairingReceiptChannel.bind(record, connect(record, peer))
        val reading = async { channel.recover() }
        peer.waiting.await(); reading.cancel(); reading.join()
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        assertFails { channel.recover() }; assertEquals(1, peer.queries)
    }
}
