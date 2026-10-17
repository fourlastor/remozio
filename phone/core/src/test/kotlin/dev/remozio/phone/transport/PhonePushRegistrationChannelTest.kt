package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class PhonePushRegistrationChannelTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun record(phone: Int = 3, phase: EnrollmentPhase = EnrollmentPhase.ACTIVE): StoredPhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val bytes = key()
            return EnrollmentKeyReference(role, id(role.ordinal + 10),
                "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
                if (role == EnrollmentKeyRole.TRANSPORT) bytes else bytes.takeLast(65).toByteArray())
        }
        return StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host", key().takeLast(65).toByteArray(),
            key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { 5 }, null), phase)
    }
    private fun offer(token: String = "synthetic-token") = PhonePushTokenOffer(token, "project", "123", "dev.remozio.android")
    private fun binding(record: StoredPhoneEnrollment, token: String = "synthetic-token", tag: ByteArray = record.enrollment.enrollmentTag.copyBytes()): GatewayTokenBinding {
        val e = record.enrollment
        return GatewayTokenBinding(id(6), e.macID.copyBytes(), e.accountID.copyBytes(), id(7), id(8), e.phoneID.copyBytes(), e.epoch.copyBytes(),
            id(9), MessageDigest.getInstance("SHA-256").digest(token.toByteArray()), ByteArray(32) { 10 }, tag)
    }
    private fun metadata(binding: GatewayTokenBinding) = PhonePushRegistrationMetadata(GatewayTokenCandidate(binding, 1u, id(11), 1000u, 2000u))
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private inner class Peer(record: StoredPhoneEnrollment,
                             private val reply: (PhonePushRegistrationFrame) -> ByteArray?) : ApprovalByteStream {
        private val e = record.enrollment
        val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 12 }, setOf(1u), emptyList(), emptySet()), 1u)
        private val offer = owner.offer()
        private val output = ByteArrayOutputStream()
        private val input = ArrayDeque<ByteArray>()
        val waiting = CompletableDeferred<Unit>()
        var phase = 0
        var queries = 0
        var closes = 0
        override suspend fun awaitOpen() = Unit
        override suspend fun send(bytes: ByteArray) {
            output.write(bytes); val all = output.toByteArray()
            if (all.size < 4) return
            val count = ByteBuffer.wrap(all).int
            if (all.size < count + 4) return
            check(all.size == count + 4); output.reset()
            val body = all.copyOfRange(4, all.size)
            when (phase++) {
                0 -> { owner.receiveOffer(body); input.add(frame(offer)) }
                1 -> { owner.receiveConfirmation(body); input.add(frame(owner.confirmation())) }
                else -> {
                    val envelope = SessionEnvelope.decode(body, PhonePushRegistrationFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID); assertEquals(0uL, envelope.sequence)
                    val request = PhonePushRegistrationFrame.decode(envelope.payload.copyBytes()); queries++
                    reply(request)?.let { input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, it).encode(PhonePushRegistrationFrame.MAXIMUM_BYTES))) }
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
    private suspend fun connect(peer: Peer, purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.PUSH_REGISTRATION,
                                maximum: Int = PhonePushRegistrationFrame.MAXIMUM_BYTES) = NegotiatedTLSChannel.connect(
        peer, peer.scope, emptyList(), emptySet(), maximum, purpose = purpose)
    private suspend fun bind(record: StoredPhoneEnrollment, peer: Peer, timeout: Long = 1000) =
        PhonePushRegistrationChannel.bind(record, connect(peer), timeout) { id(30) }

    @Test fun prepareChecksScopeTagAndDigestThenClosesWithoutAnotherExchange() = runTest {
        val record = record(); val m = metadata(binding(record))
        val peer = Peer(record) { request ->
            assertEquals("synthetic-token", assertIs<PhonePushRegistrationFrame.Offer>(request).offer.token)
            PhonePushRegistrationFrame.Prepared(request.correlationID.copyBytes(), m).encode()
        }
        val channel = bind(record, peer)
        val result = assertIs<PhonePushPreparation.Ready>(channel.prepare(offer()))
        assertContentEquals(m.candidateID, result.metadata.candidateID)
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        assertFails { channel.prepare(offer()) }; assertEquals(1, peer.queries)
    }
    @Test fun providerProofUsesASeparateExchangeAndDoesNotClaimMappingInstalled() = runTest {
        val record = record(); val b = binding(record); val m = metadata(b)
        val peer = Peer(record) { request ->
            assertEquals(b, assertIs<PhonePushRegistrationFrame.Proof>(request).proof.binding)
            PhonePushRegistrationFrame.Outcome(request.correlationID.copyBytes(), PhonePushRegistrationOutcome.PROOF_COMMITTED).encode()
        }
        val result = bind(record, peer).prove(m, PushData.TokenChallenge(b.candidateID, b.challenge, b.enrollmentTag), offer())
        assertEquals(PhonePushRegistrationOutcome.PROOF_COMMITTED, result); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
    }
    @Test fun unavailableIsAnExplicitStatusAndDoesNotYieldCandidateMetadata() = runTest {
        val record = record(); val peer = Peer(record) { request ->
            PhonePushRegistrationFrame.Outcome(request.correlationID.copyBytes(), PhonePushRegistrationOutcome.UNAVAILABLE).encode()
        }
        assertEquals(PhonePushRegistrationOutcome.UNAVAILABLE, assertIs<PhonePushPreparation.Status>(bind(record, peer).prepare(offer())).outcome)
        assertEquals(1, peer.closes)
    }
    @Test fun wrongMetadataScopeTagAndTokenCannotBePublished() = runTest {
        val record = record()
        val values = listOf(metadata(binding(record(phone = 99))), metadata(binding(record, token = "other")), metadata(binding(record, tag = ByteArray(32))))
        for (m in values) {
            val peer = Peer(record) { request -> PhonePushRegistrationFrame.Prepared(request.correlationID.copyBytes(), m).encode() }
            assertFails { bind(record, peer).prepare(offer()) }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun wrongCorrelationRoleAndMalformedResponseCloseTheConnection() = runTest {
        val record = record()
        val replies: List<(PhonePushRegistrationFrame) -> ByteArray?> = listOf(
            { PhonePushRegistrationFrame.Prepared(id(99), metadata(binding(record))).encode() },
            { request -> PhonePushRegistrationFrame.Offer(request.correlationID.copyBytes(), offer()).encode() },
            { byteArrayOf(1) },
        )
        for (reply in replies) {
            val peer = Peer(record, reply); assertFails { bind(record, peer).prepare(offer()) }
            assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun wrongChallengeAndRotatedTokenStopBeforeProofTransmission() = runTest {
        val record = record(); val b = binding(record); val m = metadata(b)
        for (mode in 0..2) {
            val peer = Peer(record) { error("Must not send a proof") }; val channel = bind(record, peer)
            val challenge = PushData.TokenChallenge(if (mode == 0) id(99) else b.candidateID, b.challenge,
                if (mode == 1) ByteArray(32) else b.enrollmentTag)
            assertFails { channel.prove(m, challenge, offer(if (mode == 2) "rotated-token" else "synthetic-token")) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun inactiveWrongPurposeWrongScopeAndTooSmallChannelsSendNoApplicationData() = runTest {
        val record = record()
        for (mode in 0..3) {
            val peer = Peer(record) { error("Must not send application data") }
            val raw = connect(peer, if (mode == 1) EnrolledChannelPurpose.APPROVALS else EnrolledChannelPurpose.PUSH_REGISTRATION,
                if (mode == 3) PhonePushRegistrationFrame.MAXIMUM_BYTES - 1 else PhonePushRegistrationFrame.MAXIMUM_BYTES)
            val retained = when (mode) {
                0 -> StoredPhoneEnrollment(record.enrollment, EnrollmentPhase.PREPARED)
                2 -> record(phone = 99)
                else -> record
            }
            assertFails { PhonePushRegistrationChannel.bind(retained, raw) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun cancellationAndDeadlineNeverResubmitAnUncertainExchange() = runTest {
        val record = record(); val peer = Peer(record) { null }; val channel = bind(record, peer)
        val pending = async { channel.prepare(offer()) }; peer.waiting.await(); pending.cancel(); pending.join()
        assertFails { channel.prepare(offer()) }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        val silent = Peer(record) { null }; val timed = bind(record, silent, 10)
        assertFailsWith<TimeoutCancellationException> { timed.prepare(offer()) }
        assertEquals(1, silent.queries); assertEquals(1, silent.closes)
    }
}
