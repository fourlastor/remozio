package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class PhoneUpdateProgressChannelTest {
    private fun id(value: Int) = ByteArray(16) { value.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private inner class Fixture(private val phone: Int = 3) {
        val root = key()
        var nanos = 1_000_000L
        fun local(role: EnrollmentKeyRole) = key().let { pair -> EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray()) }
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC),
            ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        var current = record
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        fun reply(query: PhoneUpdateProgressFrame, scope: ChannelScope = this.scope,
                  nonce: ByteArray = query.queryNonce.copyBytes(), signer: KeyPair = root,
                  phase: UpdateSchedulingProgressPhase = UpdateSchedulingProgressPhase.READY,
                  actions: ULong = 3u, readyAge: ULong? = 100u): ByteArray {
            val intent = UpdateSchedulingStatusResponse(scope, nonce, ByteArray(32) { 8 }, 1u, 0u, null)
            val bytes = UpdateSchedulingProgressResponse(intent, phase, UpdateSchedulingDesignation.THIS_ACCOUNT,
                UpdateSchedulingSecurityStatus.UNKNOWN, readyAge, actions, emptyList(), UpdateSchedulingAdmissionState.OPEN).encode()
            val input = UpdateSchedulingProgressSigningInput.make(1u, bytes, CborLimits(8192, 2, 32))
            return PhoneUpdateProgressFrame.Response(nonce, bytes, sign(signer, input)).encode()
        }
    }
    private inner class Peer(val fixture: Fixture, requests: List<ChannelRequestCapability> = emptyList(),
                             audit: Set<ULong> = emptySet(), private val reply: (PhoneUpdateProgressFrame) -> ByteArray?) : ApprovalByteStream {
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, fixture.scope, ByteArray(32) { 12 }, setOf(1u), requests, audit), 1u)
        private val offer = owner.offer()
        private val output = ByteArrayOutputStream()
        private val input = ArrayDeque<ByteArray>()
        val waiting = CompletableDeferred<Unit>()
        var phase = 0; var queries = 0; var closes = 0
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
                    val envelope = SessionEnvelope.decode(body, PhoneUpdateProgressFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID); assertEquals(0uL, envelope.sequence)
                    val query = PhoneUpdateProgressFrame.decode(envelope.payload.copyBytes()); queries++
                    reply(query)?.let { input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, it)
                        .encode(PhoneUpdateProgressFrame.MAXIMUM_BYTES))) }
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
    private suspend fun connect(peer: Peer, purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.UPDATE_PROGRESS,
                                maximum: Int = PhoneUpdateProgressFrame.MAXIMUM_BYTES,
                                requests: List<ChannelRequestCapability> = emptyList(), audit: Set<ULong> = emptySet()) =
        NegotiatedTLSChannel.connect(peer, peer.fixture.scope, requests, audit, maximum, purpose = purpose)
    private suspend fun bind(f: Fixture, peer: Peer, timeout: Long = 1000) =
        PhoneUpdateProgressChannel.bind(f.record, connect(peer), { f.nanos }, { f.current }, timeout) { ByteArray(32) { 31 } }

    @Test fun oneReadProducesAFreshRootVerifiedObservationWithoutAControlDigest() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it) }; val channel = bind(f, peer)
        val result = channel.read()
        assertTrue(result.matchesEnrollment(f.current)); assertTrue(result.isFresh(1000))
        assertNull(result.response.status.controlDigest); assertEquals(100uL, result.readyAgeUpperBoundMilliseconds())
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        assertFails { channel.read() }; assertEquals(1, peer.queries)
        assertEquals("PhoneUpdateProgressObservation(redacted)", result.toString())
        assertEquals("PhoneUpdateProgressChannel(redacted)", channel.toString())
    }

    @Test fun wrongRootScopeNonceRoleAndMalformedRepliesCannotEstablishProgress() = runTest {
        val f = Fixture()
        val scopes = listOf(ChannelScope(id(99), id(21), id(3), id(4)), ChannelScope(id(20), id(99), id(3), id(4)),
            ChannelScope(id(20), id(21), id(99), id(4)), ChannelScope(id(20), id(21), id(3), id(99)))
        val replies: List<(PhoneUpdateProgressFrame) -> ByteArray?> = listOf<(PhoneUpdateProgressFrame) -> ByteArray?>(
            { f.reply(it, signer = key()) }, { f.reply(it, nonce = ByteArray(32) { 99 }) }, { it.encode() }, { byteArrayOf(1) },
            { PhoneUpdateProgressFrame.Failure(it.queryNonce.copyBytes(), PhoneUpdateProgressFailure.INCOMPATIBLE).encode() },
        ) + scopes.map { scope -> { query: PhoneUpdateProgressFrame -> f.reply(query, scope = scope) } }
        for (reply in replies) {
            val peer = Peer(f, reply = reply); val channel = bind(f, peer)
            assertFails { channel.read() }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { channel.read() }; assertEquals(1, peer.queries)
        }
    }

    @Test fun inactiveForeignSmallAndWrongPurposeChannelsCannotSendAQuery() = runTest {
        for (mode in 0..4) {
            val f = Fixture(); val peer = Peer(f) { error("Invalid binding sent progress data") }
            val purpose = when (mode) { 1 -> EnrolledChannelPurpose.APPROVALS; 4 -> EnrolledChannelPurpose.UPDATE_SCHEDULING
                else -> EnrolledChannelPurpose.UPDATE_PROGRESS }
            val raw = connect(peer, purpose, if (mode == 3) 8191 else 8192)
            val record = when (mode) { 0 -> StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
                2 -> Fixture(99).record; else -> f.record }
            assertFails { PhoneUpdateProgressChannel.bind(record, raw, { f.nanos }, { record }) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }

    @Test fun commandAndAuditCapabilitiesCannotBeBorrowedForProgress() = runTest {
        val capability = ChannelRequestCapability(1u, 1u, 1u, emptySet())
        for (mode in 0..3) {
            val f = Fixture()
            val peer = Peer(f, if (mode == 0) listOf(capability) else emptyList(),
                if (mode == 1) setOf(1u) else emptySet()) { error("Mixed channel sent progress data") }
            val raw = connect(peer, requests = if (mode == 2) listOf(capability) else emptyList(),
                audit = if (mode == 3) setOf(1u) else emptySet())
            assertFails { PhoneUpdateProgressChannel.bind(f.record, raw, { f.nanos }, { f.current }) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }

    @Test fun enrollmentChangesBeforeSendAndAfterReplyPreventPublication() = runTest {
        for (afterReply in listOf(false, true)) {
            val f = Fixture(); val peer = Peer(f) {
                if (afterReply) f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
                f.reply(it)
            }
            val channel = bind(f, peer)
            if (!afterReply) f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
            assertFails { channel.read() }; assertEquals(if (afterReply) 1 else 0, peer.queries); assertEquals(1, peer.closes)
        }
    }

    @Test fun changedEnrollmentAfterASuspendedLookupStopsBeforeSending() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Revoked binding sent progress data") }
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); var reads = 0
        val channel = PhoneUpdateProgressChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 2) { entered.complete(Unit); release.await() }; f.current
        })
        val operation = async { assertFailsWith<IOException> { channel.read() } }
        entered.await(); f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
        release.complete(Unit); operation.await(); assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun finalSuspendedLookupCannotPublishAfterRevocation() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it) }
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); var reads = 0
        val channel = PhoneUpdateProgressChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 5) { entered.complete(Unit); release.await() }; f.current
        })
        val operation = async { assertFailsWith<IOException> { channel.read() } }
        entered.await(); f.current = StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)
        release.complete(Unit); operation.await(); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun cancellationDuringBindClosesTheNegotiatedChannel() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Cancelled binding sent progress data") }
        val raw = connect(peer); val entered = CompletableDeferred<Unit>()
        val operation = async { PhoneUpdateProgressChannel.bind(f.record, raw, { f.nanos }, {
            entered.complete(Unit); awaitCancellation()
        }) }
        entered.await(); operation.cancelAndJoin(); assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun cancellationReturnedByEnrollmentCannotSendAnApplicationFrame() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Cancelled lookup sent progress data") }; var reads = 0
        val channel = PhoneUpdateProgressChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 2) currentCoroutineContext().cancel(); f.current
        })
        val operation = async { channel.read() }; assertFailsWith<CancellationException> { operation.await() }
        assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun slowNoncePreparationCannotExtendTheOriginalDeadline() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Expired query reached the wire") }
        val channel = PhoneUpdateProgressChannel.bind(f.record, connect(peer), { f.nanos }, { f.current }, 1000) {
            f.nanos += 1_000_000_000L; ByteArray(32) { 31 }
        }
        assertFails { channel.read() }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun sleepAndClockRegressionRetireTheObservationWithoutResettingItsAge() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it) }; val result = bind(f, peer).read()
        f.nanos += 500_000_001; assertEquals(501L, result.ageMilliseconds()); assertEquals(601uL, result.readyAgeUpperBoundMilliseconds())
        f.nanos -= 1_000_000; assertNull(result.ageMilliseconds()); assertNull(result.readyAgeUpperBoundMilliseconds())
        f.nanos += 20_000_000; assertFalse(result.isFresh(1000))
        val late = Peer(f) { f.nanos += 1_000_000_000; f.reply(it) }
        assertFails { bind(f, late).read() }; assertEquals(1, late.queries)
    }

    @Test fun explicitCloseDuringFinalLookupPreventsPublicationAndClosesOnce() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it) }
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); var reads = 0
        val channel = PhoneUpdateProgressChannel.bind(f.record, connect(peer), { f.nanos }, {
            if (++reads == 5) { entered.complete(Unit); release.await() }; f.current
        })
        val operation = async { assertFailsWith<IOException> { channel.read() } }
        entered.await(); channel.close(); channel.close(); release.complete(Unit); operation.await()
        channel.closeAndJoin(); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
    }

    @Test fun timeoutAndCancellationNeverRetryTheApplicationQuery() = runTest {
        for (cancel in listOf(false, true)) {
            val f = Fixture(); val peer = Peer(f) { null }; val channel = bind(f, peer, if (cancel) 1000 else 100)
            if (cancel) {
                val operation = async { channel.read() }; peer.waiting.await(); operation.cancelAndJoin()
            } else assertFailsWith<TimeoutCancellationException> { channel.read() }
            assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { channel.read() }; assertEquals(1, peer.queries)
        }
    }

    @Test fun invalidClockAndNonceStopBeforeSending() = runTest {
        for (badClock in listOf(false, true)) {
            val f = Fixture(); val peer = Peer(f) { error("Invalid query reached the wire") }
            val channel = PhoneUpdateProgressChannel.bind(f.record, connect(peer), { if (badClock) -1L else f.nanos },
                { f.current }, 1000) { ByteArray(if (badClock) 32 else 31) }
            assertFails { channel.read() }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }

    @Test fun irreversibleProgressIsAnObservationAndNeverAControlAcknowledgment() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it, phase = UpdateSchedulingProgressPhase.ACTIVATING, actions = 0u) }
        val result = bind(f, peer).read()
        assertTrue(result.response.phase.irreversible); assertEquals(0uL, result.response.availableActions)
        assertNull(result.response.status.controlDigest); result.close(); assertNull(result.ageMilliseconds())
        assertFalse(result.matchesEnrollment(StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED)))
    }
}
