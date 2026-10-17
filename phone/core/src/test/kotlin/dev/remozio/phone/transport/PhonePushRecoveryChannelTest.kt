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

class PhonePushRecoveryChannelTest {
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
                             private val reply: (PhonePushRecoveryFrame) -> ByteArray?) : ApprovalByteStream {
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
                    val envelope = SessionEnvelope.decode(body, PhonePushRecoveryFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID); val sequence = queries.toULong(); assertEquals(sequence, envelope.sequence)
                    val request = PhonePushRecoveryFrame.decode(envelope.payload.copyBytes()); queries++
                    reply(request)?.let { input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), sequence, it).encode(PhonePushRecoveryFrame.MAXIMUM_BYTES))) }
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
    private suspend fun connect(peer: Peer, purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.PUSH_RECOVERY,
                                maximum: Int = PhonePushRecoveryFrame.MAXIMUM_BYTES) = NegotiatedTLSChannel.connect(
        peer, peer.scope, emptyList(), emptySet(), maximum, purpose = purpose)
    private suspend fun bind(record: StoredPhoneEnrollment, peer: Peer, timeout: Long = 1000,
                             clock: () -> Long = { 0L }, repeatedID: Boolean = false): PhonePushRecoveryChannel {
        var next = 30
        return PhonePushRecoveryChannel.bind(record, connect(peer), timeout, { id(if (repeatedID) 30 else next++) }, clock)
    }
    private fun readyThen(record: StoredPhoneEnrollment, resume: (PhonePushRecoveryFrame.Resume) -> ByteArray?) = Peer(record) { request ->
        when (request) {
            is PhonePushRecoveryFrame.Probe -> PhonePushRecoveryFrame.Ready(request.correlationID.copyBytes()).encode()
            is PhonePushRecoveryFrame.Resume -> resume(request)
            else -> error("Unexpected phone role")
        }
    }
    private fun state(request: PhonePushRecoveryFrame.Resume, metadata: PhonePushRegistrationMetadata,
                      phase: PhonePushRecoveryPhase = PhonePushRecoveryPhase.PROOF_COMMITTED, age: ULong? = null) =
        PhonePushRecoveryFrame.State(request.correlationID.copyBytes(), PhonePushRecoveryState(metadata, phase, age)).encode()
    @Test fun readinessPrecedesTokenAndTheOperationClosesAfterTwoExchanges() = runTest {
        val record = record(); val m = metadata(binding(record))
        val peer = readyThen(record) { request -> assertEquals("synthetic-token", request.offer.token); state(request, m) }
        val channel = bind(record, peer)
        val result = assertIs<PhonePushRecoveryResult.Current>(channel.recover(offer()))
        assertContentEquals(m.candidateID, result.state.metadata.candidateID)
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase)
        assertEquals(2, peer.queries); assertEquals(1, peer.closes)
        assertFails { channel.recover(offer()) }; assertEquals(2, peer.queries)
    }
    @Test fun unavailablePreflightSendsNoTokenOrResume() = runTest {
        val record = record(); val peer = Peer(record) { request ->
            assertIs<PhonePushRecoveryFrame.Probe>(request)
            PhonePushRecoveryFrame.Outcome(request.correlationID.copyBytes(), PhonePushRecoveryFailure.UNAVAILABLE).encode()
        }
        val result = assertIs<PhonePushRecoveryResult.Failure>(bind(record, peer).recover(offer()))
        assertEquals(PhonePushRecoveryFailure.UNAVAILABLE, result.failure)
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
    }
    @Test fun wrongPreflightCorrelationAndRoleCannotReleaseToken() = runTest {
        val record = record()
        val replies: List<(PhonePushRecoveryFrame) -> ByteArray?> = listOf(
            { PhonePushRecoveryFrame.Ready(id(99)).encode() },
            { request -> PhonePushRecoveryFrame.State(request.correlationID.copyBytes(), PhonePushRecoveryState(metadata(binding(record)), PhonePushRecoveryPhase.PROOF_COMMITTED)).encode() },
            { byteArrayOf(1) },
        )
        for (reply in replies) {
            val peer = Peer(record) { request -> assertIs<PhonePushRecoveryFrame.Probe>(request); reply(request) }
            assertFails { bind(record, peer).recover(offer()) }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun observationAgeIncludesTheConservativeResumeRoundTrip() = runTest {
        val record = record(); val m = metadata(binding(record)); var now = 0L
        val peer = readyThen(record) { request -> now = 12_000_001; state(request, m, PhonePushRecoveryPhase.MAPPING_OBSERVED, 7u) }
        val result = assertIs<PhonePushRecoveryResult.Current>(bind(record, peer, clock = { now }).recover(offer()))
        assertEquals(PhonePushRecoveryPhase.MAPPING_OBSERVED, result.state.phase)
        assertEquals(20uL, result.state.observationAgeMilliseconds)
        assertEquals(2000uL, result.state.metadata.expiresAtUnixMillis)
    }
    @Test fun observationThatAgesOutInTransitReturnsOnlyProofCommitment() = runTest {
        val record = record(); var now = 0L
        val peer = readyThen(record) { request -> now = 1; state(request, metadata(binding(record)), PhonePushRecoveryPhase.MAPPING_OBSERVED, 4999u) }
        val result = assertIs<PhonePushRecoveryResult.Current>(bind(record, peer, clock = { now }).recover(offer()))
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase); assertNull(result.state.observationAgeMilliseconds)
    }
    @Test fun resultFreshnessAlsoIncludesCallerDelayAfterTheExchangeCompletes() = runTest {
        val record = record(); var now = 0L
        val peer = readyThen(record) { state(it, metadata(binding(record)), PhonePushRecoveryPhase.MAPPING_OBSERVED, 7u) }
        val result = assertIs<PhonePushRecoveryResult.Current>(bind(record, peer, clock = { now }).recover(offer()))
        now = 4_992_000_001L
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase)
        assertNull(result.state.observationAgeMilliseconds)
    }
    @Test fun aResultFirstReadAfterExpiryCannotRestartItsObservationWindow() = runTest {
        val record = record(); var now = 0L
        val peer = readyThen(record) { state(it, metadata(binding(record)), PhonePushRecoveryPhase.MAPPING_OBSERVED, 0u) }
        val result = assertIs<PhonePushRecoveryResult.Current>(bind(record, peer, clock = { now }).recover(offer()))
        now = 6_000_000_000L
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase)
        now = 0L
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase)
    }
    @Test fun aNegativeElapsedClockCannotPublishOrReviveAnObservedMapping() = runTest {
        val record = record(); var now = 10L
        val peer = readyThen(record) { state(it, metadata(binding(record)), PhonePushRecoveryPhase.MAPPING_OBSERVED, 0u) }
        val result = assertIs<PhonePushRecoveryResult.Current>(bind(record, peer, clock = { now }).recover(offer()))
        now = 9L
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase)
        now = 11L
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, result.state.phase)
    }
    @Test fun wrongScopeTagOrTokenMetadataCannotBePublished() = runTest {
        val record = record()
        for (m in listOf(metadata(binding(record(phone = 99))), metadata(binding(record, token = "other")), metadata(binding(record, tag = ByteArray(32))))) {
            val peer = readyThen(record) { state(it, m) }
            assertFails { bind(record, peer).recover(offer()) }; assertEquals(2, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun responseRoleAndCorrelationRemainBoundAfterPreflight() = runTest {
        val record = record()
        val replies: List<(PhonePushRecoveryFrame.Resume) -> ByteArray?> = listOf(
            { PhonePushRecoveryFrame.Outcome(id(99), PhonePushRecoveryFailure.UNAVAILABLE).encode() },
            { PhonePushRecoveryFrame.Ready(it.correlationID.copyBytes()).encode() },
        )
        for (reply in replies) {
            val peer = readyThen(record, reply); assertFails { bind(record, peer).recover(offer()) }
            assertEquals(2, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun invalidBindingsSendNoApplicationData() = runTest {
        val record = record()
        for (mode in 0..3) {
            val peer = Peer(record) { error("Must not send application data") }
            val raw = connect(peer, if (mode == 1) EnrolledChannelPurpose.APPROVALS else EnrolledChannelPurpose.PUSH_RECOVERY,
                if (mode == 3) PhonePushRecoveryFrame.MAXIMUM_BYTES - 1 else PhonePushRecoveryFrame.MAXIMUM_BYTES)
            val retained = when (mode) { 0 -> StoredPhoneEnrollment(record.enrollment, EnrollmentPhase.PREPARED); 2 -> record(phone = 99); else -> record }
            assertFails { PhonePushRecoveryChannel.bind(retained, raw) }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun cancellationAndTimeoutNeverReplayAnUncertainResume() = runTest {
        val record = record(); val peer = readyThen(record) { null }; val channel = bind(record, peer)
        val pending = async { channel.recover(offer()) }; peer.waiting.await(); pending.cancel(); pending.join()
        assertFails { channel.recover(offer()) }; assertEquals(2, peer.queries); assertEquals(1, peer.closes)
        val silent = Peer(record) { null }; val timed = bind(record, silent, timeout = 10)
        assertFailsWith<TimeoutCancellationException> { timed.recover(offer()) }
        assertEquals(1, silent.queries); assertEquals(1, silent.closes)
    }
    @Test fun duplicatePreflightAndResumeCorrelationsStopBeforeToken() = runTest {
        val record = record(); val peer = readyThen(record) { error("Duplicate correlation sent private fields") }
        assertFails { bind(record, peer, repeatedID = true).recover(offer()) }
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
    }
}
