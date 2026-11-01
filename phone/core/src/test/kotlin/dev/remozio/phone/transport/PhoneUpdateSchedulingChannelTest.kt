package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class PhoneUpdateSchedulingChannelTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private val controlLimits = CborLimits(1024, 2, 32)
    private val responseLimits = CborLimits(2048, 2, 32)
    private val signingLimits = CborLimits(4096, 2, 32)
    private inner class Fixture(private val phone: Int = 3) {
        val root = key(); val decision = key(); val biometric = key()
        var nanos = 1_000_000L
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded, local(EnrollmentKeyRole.TRANSPORT, key()),
            local(EnrollmentKeyRole.DECISION, decision), local(EnrollmentKeyRole.BIOMETRIC, biometric), ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        var current = record
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        val update = ByteArray(32) { 8 }
        fun query(action: UpdateSchedulingAction = UpdateSchedulingAction.DEFER_UPDATE) = PhoneUpdateSchedulingQuery.begin(
            record, update, 1u, 0u, action, { nanos }, 1000)
        fun control(query: PhoneUpdateSchedulingFrame.Challenge) = UpdateSchedulingControl(id(20), id(21), id(phone), id(4),
            id(6), ByteArray(32) { 7 }, record.enrollment.decisionKey.keyID.copyBytes(), query.updateID.copyBytes(),
            query.generation, query.revision, 1000u, 31_000u, query.action).encode(controlLimits)
        fun challenge(query: PhoneUpdateSchedulingFrame): ByteArray {
            val q = assertIs<PhoneUpdateSchedulingFrame.Challenge>(query)
            val payload = RootUpdateSchedulingChallenge(q.queryNonce.copyBytes(), control(q), responseLimits).encode(responseLimits)
            val signature = sign(root, RootUpdateSchedulingChallengeSigningInput.make(1u, payload, responseLimits, signingLimits))
            return PhoneUpdateSchedulingFrame.ChallengeResponse(q.queryNonce.copyBytes(), payload, signature).encode()
        }
        fun status(query: PhoneUpdateSchedulingFrame, scope: ChannelScope = this.scope,
                   nonce: ByteArray = query.queryNonce.copyBytes(), generation: ULong = 1u, revision: ULong = 0u,
                   action: UpdateSchedulingAction? = null, digest: ByteArray? = null, signer: KeyPair = root): ByteArray {
            val payload = UpdateSchedulingStatusResponse(scope, nonce, update, generation, revision, action, digest).encode()
            val signature = sign(signer, UpdateSchedulingStatusSigningInput.make(1u, payload, signingLimits))
            return PhoneUpdateSchedulingFrame.StateResponse(nonce, payload, signature).encode()
        }
        fun accepted(query: PhoneUpdateSchedulingFrame): ByteArray {
            val q = assertIs<PhoneUpdateSchedulingFrame.Apply>(query)
            val control = UpdateSchedulingControl.decode(q.canonicalControl.copyBytes(), controlLimits)
            assertTrue(UpdateSchedulingSignature.verify(q.signature.copyBytes(), record.enrollment.decisionKey.publicKey.copyBytes(),
                1u, q.canonicalControl.copyBytes(), controlLimits, signingLimits))
            return status(query, revision = control.expectedRevision + 1u, action = control.action,
                digest = MessageDigest.getInstance("SHA-256").digest(q.canonicalControl.copyBytes()))
        }
    }
    private inner class Peer(val fixture: Fixture, requests: List<ChannelRequestCapability> = emptyList(),
                             private val reply: (PhoneUpdateSchedulingFrame) -> ByteArray?) : ApprovalByteStream {
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, fixture.scope, ByteArray(32) { 12 }, setOf(1u), requests, emptySet()), 1u)
        private val offer = owner.offer()
        private val output = ByteArrayOutputStream()
        private val input = ArrayDeque<ByteArray>()
        val waiting = CompletableDeferred<Unit>()
        var phase = 0; var queries = 0; var closes = 0
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
                    val envelope = SessionEnvelope.decode(body, PhoneUpdateSchedulingFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID); assertEquals(0uL, envelope.sequence)
                    val query = PhoneUpdateSchedulingFrame.decode(envelope.payload.copyBytes()); queries++
                    reply(query)?.let { input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, it).encode(PhoneUpdateSchedulingFrame.MAXIMUM_BYTES))) }
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
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private suspend fun connect(peer: Peer, purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.UPDATE_SCHEDULING,
                                maximum: Int = PhoneUpdateSchedulingFrame.MAXIMUM_BYTES) =
        NegotiatedTLSChannel.connect(peer, peer.fixture.scope, emptyList(), emptySet(), maximum, purpose = purpose)
    private suspend fun bind(f: Fixture, peer: Peer, timeout: Long = 1000) = PhoneUpdateSchedulingChannel.bind(
        f.record, connect(peer), { f.nanos }, { f.current }, timeout) { ByteArray(32) { 31 } }
    private suspend fun signed(f: Fixture): Pair<PhoneUpdateSchedulingChallenge, ByteArray> {
        val peer = Peer(f) { f.challenge(it) }
        val challenge = bind(f, peer).challenge(f.query())
        return challenge to challenge.sign(f.current) { sign(f.decision, it) }
    }
    @Test fun statusIsSignedBoundFreshAndOneUse() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.status(it) }; val channel = bind(f, peer)
        val result = channel.status()
        assertEquals(1uL, result.response.generation); assertEquals(0uL, result.response.revision)
        assertNull(result.response.controlDigest); assertTrue(result.matchesEnrollment(f.current)); assertTrue(result.isFresh(1000))
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        assertFails { channel.status() }; assertEquals(1, peer.queries)
    }
    @Test fun wrongRootScopeNonceRoleAndMalformedRepliesCannotEstablishState() = runTest {
        val f = Fixture()
        val replies: List<(PhoneUpdateSchedulingFrame) -> ByteArray?> = listOf(
            { f.status(it, signer = key()) }, { f.status(it, scope = Fixture(99).scope) },
            { f.status(it, nonce = ByteArray(32) { 99 }) }, { it.encode() }, { byteArrayOf(1) },
            { PhoneUpdateSchedulingFrame.Failure(it.queryNonce.copyBytes(), PhoneUpdateSchedulingFailure.INCOMPATIBLE).encode() },
        )
        for (reply in replies) {
            val peer = Peer(f, reply = reply); val channel = bind(f, peer)
            assertFails { channel.status() }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { channel.status() }; assertEquals(1, peer.queries)
        }
    }
    @Test fun eachExplicitChoiceTransfersOneRootVerifiedDecisionChallenge() = runTest {
        for (action in UpdateSchedulingAction.entries) {
            val f = Fixture(); val peer = Peer(f) { query ->
                assertEquals(action, assertIs<PhoneUpdateSchedulingFrame.Challenge>(query).action); f.challenge(query)
            }
            val challenge = bind(f, peer).challenge(f.query(action))
            val signature = challenge.sign(f.current) { sign(f.decision, it) }
            assertEquals(64, signature.size); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { challenge.sign(f.current) { sign(f.decision, it) } }
        }
    }
    @Test fun theOriginalQueryDeadlineIncludesDelayBeforeTheChannelOperation() = runTest {
        val f = Fixture(); val query = f.query(); f.nanos += 1_000_000_000
        val peer = Peer(f) { error("Expired query sent an application frame") }
        assertFails { bind(f, peer).challenge(query) }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }
    @Test fun enrollmentChangesBeforeSendOrAfterTheReplyCloseTheExchange() = runTest {
        for (afterReply in listOf(false, true)) {
            val f = Fixture(); val peer = Peer(f) { query ->
                if (afterReply) f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
                f.status(query)
            }
            val channel = bind(f, peer)
            if (!afterReply) f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
            assertFails { channel.status() }; assertEquals(if (afterReply) 1 else 0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun aCommittedReplyBindsTheExactSignedControlAndItsNextRevision() = runTest {
        val f = Fixture(); val (challenge, signature) = signed(f); val peer = Peer(f) { f.accepted(it) }
        val result = bind(f, peer).apply(challenge, signature)
        assertEquals(1uL, result.response.revision); assertEquals(UpdateSchedulingAction.DEFER_UPDATE, result.response.requestedAction)
        assertNotNull(result.response.controlDigest); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        assertFails { challenge.bytes(f.current) }
    }
    @Test fun wrongDigestGenerationRevisionOrActionCannotAcknowledgeAControl() = runTest {
        for (mode in 0..3) {
            val f = Fixture(); val (challenge, signature) = signed(f)
            val peer = Peer(f) { query ->
                val bytes = assertIs<PhoneUpdateSchedulingFrame.Apply>(query).canonicalControl.copyBytes()
                f.status(query, generation = if (mode == 1) 2u else 1u, revision = if (mode == 2) 2u else 1u,
                    action = if (mode == 3) UpdateSchedulingAction.CANCEL_DRAIN else UpdateSchedulingAction.DEFER_UPDATE,
                    digest = if (mode == 0) ByteArray(32) else MessageDigest.getInstance("SHA-256").digest(bytes))
            }
            assertFails { bind(f, peer).apply(challenge, signature) }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun biometricSignaturesAndExpiredChallengesStopBeforeSending() = runTest {
        for (expired in listOf(false, true)) {
            val f = Fixture(); val (challenge, signature) = signed(f)
            val bad = if (expired) signature else sign(f.biometric, UpdateSchedulingSigningInput.make(
                1u, challenge.bytes(f.current), controlLimits, signingLimits))
            if (expired) f.nanos += 30_000_000_000L
            val peer = Peer(f) { error("Unusable control sent an application frame") }
            assertFails { bind(f, peer).apply(challenge, bad) }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun inactiveWrongPurposeScopeAndSmallChannelsCannotSendSchedulingData() = runTest {
        for (mode in 0..3) {
            val f = Fixture(); val peer = Peer(f) { error("Invalid channel sent scheduling data") }
            val raw = connect(peer, if (mode == 1) EnrolledChannelPurpose.APPROVALS else EnrolledChannelPurpose.UPDATE_SCHEDULING,
                if (mode == 3) 4095 else 4096)
            val record = when (mode) { 0 -> StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED); 2 -> Fixture(99).record; else -> f.record }
            assertFails { PhoneUpdateSchedulingChannel.bind(record, raw, { f.nanos }, { record }) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun responseAgeIncludesSleepAndClockRegressionCannotRecover() = runTest {
        val f = Fixture(); val late = Peer(f) { query -> f.nanos += 1_000_000_000; f.status(query) }
        assertFails { bind(f, late).status() }; assertEquals(1, late.queries)
        val peer = Peer(f) { f.status(it) }; val result = bind(f, peer).status()
        f.nanos += 500_000_001; assertEquals(501L, result.ageMilliseconds())
        f.nanos -= 1_000_000; assertNull(result.ageMilliseconds())
        f.nanos += 20_000_000; assertFalse(result.isFresh(1000))
    }
    @Test fun timeoutAndCancellationCloseWithoutRetryingAnApplicationMessage() = runTest {
        for (cancel in listOf(false, true)) {
            val f = Fixture(); val peer = Peer(f) { null }; val channel = bind(f, peer, if (cancel) 1000 else 100)
            if (cancel) {
                val operation = async { channel.status() }; peer.waiting.await(); operation.cancelAndJoin()
            } else { assertFailsWith<TimeoutCancellationException> { channel.status() } }
            assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { channel.status() }; assertEquals(1, peer.queries)
        }
    }
    @Test fun invalidClockOrNonceStopsBeforeSendingTheApplicationQuery() = runTest {
        val f = Fixture(); val first = Peer(f) { error("Invalid clock sent scheduling data") }
        val invalidClock = PhoneUpdateSchedulingChannel.bind(f.record, connect(first), { -1L }, { f.current }, 1000) { ByteArray(32) }
        assertFails { invalidClock.status() }; assertEquals(0, first.queries); assertEquals(1, first.closes)
        val second = Peer(f) { error("Invalid nonce sent scheduling data") }
        val invalidNonce = PhoneUpdateSchedulingChannel.bind(f.record, connect(second), { f.nanos }, { f.current }, 1000) { ByteArray(31) }
        assertFails { invalidNonce.status() }; assertEquals(0, second.queries); assertEquals(1, second.closes)
    }
    @Test fun aSlowFramePreparationCannotOutliveTheOriginalQuery() = runTest {
        val f = Fixture(); val query = f.query(); val peer = Peer(f) { error("Expired prepared query reached the wire") }
        var checks = 0
        val channel = PhoneUpdateSchedulingChannel.bind(f.record, connect(peer), { f.nanos }, {
            checks += 1; if (checks == 4) f.nanos += 1_000_000_000L; f.current
        }, 60_000) { ByteArray(32) { 31 } }
        assertFails { channel.challenge(query) }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }
    @Test fun noncePreparationCannotSendAControlAfterItsOriginalLifetime() = runTest {
        val f = Fixture(); val (challenge, signature) = signed(f)
        val peer = Peer(f) { error("Expired prepared control reached the wire") }
        val channel = PhoneUpdateSchedulingChannel.bind(f.record, connect(peer), { f.nanos }, { f.current }, 60_000) {
            f.nanos += 30_000_000_000L; ByteArray(32) { 31 }
        }
        assertFails { channel.apply(challenge, signature) }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun cancellingASuspendedEnrollmentReadDuringBindClosesWithoutAnApplicationQuery() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Cancelled binding sent scheduling data") }
        val raw = connect(peer); val entered = CompletableDeferred<Unit>()
        val operation = async {
            PhoneUpdateSchedulingChannel.bind(f.record, raw, { f.nanos }, {
                entered.complete(Unit); awaitCancellation()
            })
        }
        entered.await(); operation.cancelAndJoin()
        assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun aChangedEnrollmentAfterASuspendedReadStopsBeforeSending() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Changed enrollment sent scheduling data") }
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); var reads = 0
        val channel = PhoneUpdateSchedulingChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 2) { entered.complete(Unit); release.await() }
            f.current
        })
        val operation = async { assertFailsWith<java.io.IOException> { channel.status() } }
        entered.await(); f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
        release.complete(Unit); operation.await()
        assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun aFinalSuspendedEnrollmentReadCannotPublishAReplyAfterRevocation() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.status(it) }
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); var reads = 0
        val channel = PhoneUpdateSchedulingChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 5) { entered.complete(Unit); release.await() }
            f.current
        })
        val operation = async { assertFailsWith<java.io.IOException> { channel.status() } }
        entered.await(); f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
        release.complete(Unit); operation.await()
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun cancellationReturnedByAnEnrollmentReadCannotSendAnApplicationFrame() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Cancelled lookup sent scheduling data") }; var reads = 0
        val channel = PhoneUpdateSchedulingChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 2) currentCoroutineContext().cancel()
            f.current
        })
        val operation = async { channel.status() }
        assertFailsWith<CancellationException> { operation.await() }
        assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

}
