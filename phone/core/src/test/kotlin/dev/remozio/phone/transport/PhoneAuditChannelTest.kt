package dev.remozio.phone.transport

import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class PhoneAuditChannelTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private val bound = CborLimits(65536, 8, 2048)
    private fun fields(vararg values: Pair<ULong, CborValue>) = DeterministicCbor.encode(CborValue.Fields(mapOf(*values)), bound)
    private fun number(n: ULong) = CborValue.Unsigned(n)
    private fun bytes(n: Int) = CborValue.Bytes(id(n))
    private class Storage : AuditCiphertextStorage {
        var writes = 0; var closed = false; var failWrite = false
        var ciphertext: ByteArray? = null
        override fun read(maximumBytes: Int): ByteArray? = ciphertext?.copyOf()
        override fun replace(ciphertext: ByteArray) {
            check(!closed); writes++
            if (failWrite) throw IOException("Synthetic storage refusal")
            this.ciphertext = ciphertext.copyOf()
        }
        override fun close() { closed = true }
    }
    private inner class Fixture(phone: Int = 3) : AutoCloseable {
        val root = key(); private val decision = key(); private val biometric = key()
        var now = 100uL; var clockEpoch = 1L
        fun clock() = ElapsedInstant(clockEpoch, now)
        private fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic audit host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, decision), local(EnrollmentKeyRole.BIOMETRIC, biometric),
            ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        val storage = Storage()
        val cache = EncryptedAuditCache.open(storage,
            AuditArchiveCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), bound.maxBytes),
            AuditCacheBinding(id(20), id(21), record.enrollment.authorityPublicKey.copyBytes()),
            AuditPageLimits(bound, bound, bound, 8, bound, bound), AuditEvidenceLimits(100, 1_000_000, 100, 20), bound)
        val session = AuditSyncSession(cache, 20, 1000u, ::clock).also { it.start() }
        fun query() = assertNotNull(session.next())
        private fun descriptor() = fields(0uL to number(1u), 1uL to bytes(20), 2uL to bytes(21), 3uL to bytes(30),
            4uL to number(7u), 5uL to number(1u), 6uL to CborValue.Null, 7uL to CborValue.Null, 8uL to CborValue.Null)
        fun body(query: PhoneAuditFrame, nonce: ByteArray = query.queryNonce.copyBytes(), mac: Int = 20): ByteArray = when (query) {
            is PhoneAuditFrame.HistoryQuery -> {
                val available = query.requestedEpoch?.copyBytes()?.contentEquals(id(30)) == true
                val disposition = when {
                    query.requestedEpoch == null -> AuditHistoryDisposition.DISCOVERY
                    !available -> AuditHistoryDisposition.UNAVAILABLE
                    checkNotNull(query.requestedAfter) > 1u -> AuditHistoryDisposition.CURSOR_AHEAD
                    else -> AuditHistoryDisposition.AVAILABLE
                }
                fields(0uL to number(1u), 1uL to bytes(mac), 2uL to bytes(21), 3uL to CborValue.Bytes(nonce),
                    4uL to (query.requestedEpoch ?: CborValue.Null), 5uL to (query.requestedAfter?.let(::number) ?: CborValue.Null),
                    6uL to number(disposition.tag), 7uL to CborValue.Bytes(descriptor()), 8uL to number(0u), 9uL to number(1u),
                    10uL to (if (available) CborValue.Bytes(descriptor()) else CborValue.Null),
                    11uL to (if (available) number(0u) else CborValue.Null), 12uL to (if (available) number(1u) else CborValue.Null))
            }
            is PhoneAuditFrame.PageQuery -> {
                val record = AuditEventMetadata(id(31), id(mac), id(21), id(30), 1u, id(32), null, null,
                    AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND, null, null, AuditAuthentication.SYSTEM,
                    AuditOutcome.ACCEPTED, AuditReason.NONE, null, null).encode(bound)
                fields(0uL to number(1u), 1uL to bytes(mac), 2uL to bytes(21), 3uL to query.journalEpoch,
                    4uL to number(query.epochCreationGeneration), 5uL to number(query.requestedAfter), 6uL to number(0u),
                    7uL to number(1u), 8uL to CborValue.Bytes(nonce), 9uL to CborValue.ArrayValue(listOf(CborValue.Bytes(record))))
            }
            else -> error("Not an audit query")
        }
        fun reply(query: PhoneAuditFrame, body: ByteArray = body(query), signer: KeyPair = root,
                  nonce: ByteArray = query.queryNonce.copyBytes()): ByteArray {
            val input = when (query) {
                is PhoneAuditFrame.HistoryQuery -> AuditHistoryStatusSigningInput.make(1u, body, bound, bound)
                is PhoneAuditFrame.PageQuery -> AuditBatchSigningInput.make(1u, body, bound, bound)
                else -> error("Not an audit query")
            }
            val signature = sign(signer, input)
            return when (query) {
                is PhoneAuditFrame.HistoryQuery -> PhoneAuditFrame.HistoryResponse(nonce, body, signature).encode()
                else -> PhoneAuditFrame.PageResponse(nonce, body, signature).encode()
            }
        }
        override fun close() = session.close()
    }
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private inner class Peer(val fixture: Fixture, requests: List<ChannelRequestCapability> = emptyList(),
                             auditVersions: Set<ULong> = setOf(1u), private val reply: (PhoneAuditFrame) -> ByteArray?) : ApprovalByteStream {
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, fixture.scope, ByteArray(32) { 12 }, setOf(1u), requests, auditVersions), 1u)
        private val offer = owner.offer()
        private val output = ByteArrayOutputStream()
        private val input = ArrayDeque<ByteArray>()
        val waiting = CompletableDeferred<Unit>(); val joining = CompletableDeferred<Unit>()
        var joinGate: CompletableDeferred<Unit>? = null
        var phase = 0; var queries = 0; var closes = 0; var joins = 0
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
                    val envelope = SessionEnvelope.decode(body, PhoneAuditFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID); assertEquals(0uL, envelope.sequence)
                    val request = PhoneAuditFrame.decode(envelope.payload.copyBytes()); queries++
                    reply(request)?.let { input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, it).encode(PhoneAuditFrame.MAXIMUM_BYTES))) }
                }
            }
        }
        override suspend fun receive(): ByteArray {
            if (input.isNotEmpty()) return input.removeFirst()
            waiting.complete(Unit); awaitCancellation()
        }
        override fun close() { closes++; owner.close() }
        override suspend fun awaitClosed() { joins++; joining.complete(Unit); joinGate?.await() }
    }
    private suspend fun connect(peer: Peer, purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.AUDIT,
                                maximum: Int = PhoneAuditFrame.MAXIMUM_BYTES, requests: List<ChannelRequestCapability> = emptyList(),
                                auditVersions: Set<ULong> = setOf(1u)) =
        NegotiatedTLSChannel.connect(peer, peer.fixture.scope, requests, auditVersions, maximum, purpose = purpose)
    private suspend fun bind(f: Fixture, peer: Peer, timeout: Long = 5000, maximum: Int = PhoneAuditFrame.MAXIMUM_BYTES) =
        PhoneAuditChannel.bind(f.record, connect(peer, maximum = maximum), f::clock, timeout)

    @Test fun historyAndPageReachTheOriginalVerifierBeforeCacheOrCompletionAdvances() = runTest {
        Fixture().use { f ->
            repeat(2) { index ->
                val query = f.query(); val peer = Peer(f) { f.reply(it) }; val channel = bind(f, peer)
                val payload = assertIs<PhoneAuditResult.Unverified>(channel.exchange(query))
                assertSame(query, payload.query); assertTrue(payload.matchesEnrollment(f.record))
                assertEquals(index, f.storage.writes); assertNull(f.session.state.value.lastCompletedAt)
                f.now++
                payload.acceptInto(f.session, f.record)
                assertEquals(index + 1, f.storage.writes); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
                assertFails { payload.acceptInto(f.session, f.record) }
                assertFails { channel.exchange(query) }; assertEquals(1, peer.queries)
            }
            assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
            assertNotNull(f.session.state.value.lastCompletedAt); assertEquals(2, f.cache.snapshot().proofs.size)
            assertNotNull(f.storage.ciphertext)
        }
    }
    @Test fun badRootSignatureAndWrongInnerNonceCannotAdvanceTheCache() = runTest {
        for (wrongSignature in listOf(false, true)) Fixture().use { f ->
            val query = f.query()
            val peer = Peer(f) { frame ->
                if (wrongSignature) f.reply(frame, signer = key())
                else f.reply(frame, body = f.body(frame, nonce = ByteArray(32) { 99 }))
            }
            val payload = assertIs<PhoneAuditResult.Unverified>(bind(f, peer).exchange(query))
            assertEquals(0, f.storage.writes)
            assertFails { payload.acceptInto(f.session, f.record) }
            assertEquals(0, f.storage.writes); assertTrue(f.cache.snapshot().proofs.isEmpty())
            assertEquals(AuditSyncFailure.INVALID_RESPONSE, f.session.state.value.failure); assertNull(f.session.state.value.lastCompletedAt)
        }
    }
    @Test fun changedOrRemovedEnrollmentAndCancelledQueryCannotAcceptTheReply() = runTest {
        for (mode in 0..2) Fixture().use { f ->
            val query = f.query(); val peer = Peer(f) { f.reply(it) }
            val payload = assertIs<PhoneAuditResult.Unverified>(bind(f, peer).exchange(query))
            val current = when (mode) {
                0 -> Fixture(99).use { it.record }
                1 -> StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.REMOVED)
                else -> f.record.also { f.session.cancel() }
            }
            assertFails { payload.acceptInto(f.session, current) }; assertEquals(0, f.storage.writes)
            assertNull(f.session.state.value.lastCompletedAt)
        }
    }
    @Test fun unsignedUnavailableAndIncompatibleNeverBecomeEmptyHistory() = runTest {
        for (reason in PhoneAuditFailure.entries) Fixture().use { f ->
            val query = f.query(); val peer = Peer(f) { PhoneAuditFrame.Failure(it.queryNonce.copyBytes(), reason).encode() }
            val result = assertIs<PhoneAuditResult.Failure>(bind(f, peer).exchange(query))
            assertEquals(reason, result.reason); assertSame(query, result.query)
            f.session.transportFailed(query)
            assertEquals(AuditSyncPhase.FAILED, f.session.state.value.phase); assertNull(f.session.state.value.lastCompletedAt)
            assertEquals(0, f.storage.writes); assertEquals(1, peer.closes)
        }
    }
    @Test fun wrongOuterNonceResponseRoleAndMalformedFramesCloseWithoutAnotherQuery() = runTest {
        for (mode in 0..3) Fixture().use { f ->
            val query = f.query(); val peer = Peer(f) { frame -> when (mode) {
                0 -> f.reply(frame, nonce = ByteArray(32) { 99 })
                1 -> frame.encode()
                2 -> byteArrayOf(1)
                else -> PhoneAuditFrame.PageResponse(frame.queryNonce.copyBytes(), byteArrayOf(1), ByteArray(64)).encode()
            } }
            val channel = bind(f, peer)
            assertFails { channel.exchange(query) }; assertFails { channel.exchange(query) }
            assertEquals(1, peer.queries); assertEquals(1, peer.closes); assertEquals(0, f.storage.writes)
        }
    }
    @Test fun queryExpiryBetweenTransportAndVerificationCannotPublishFreshness() = runTest {
        Fixture().use { f ->
            val peer = Peer(f) { f.reply(it) }; val payload = assertIs<PhoneAuditResult.Unverified>(bind(f, peer).exchange(f.query()))
            f.now += 1000u
            assertFails { payload.acceptInto(f.session, f.record) }
            assertEquals(0, f.storage.writes); assertNull(f.session.state.value.lastCompletedAt)
        }
    }
    @Test fun regressingChangedAndExpiredElapsedClocksCannotReturnAPayload() = runTest {
        for (mode in 0..2) Fixture().use { f ->
            val query = f.query(); val peer = Peer(f) { frame ->
                when (mode) { 0 -> f.now--; 1 -> f.clockEpoch++; else -> f.now += 5000u }
                f.reply(frame)
            }
            assertFails { bind(f, peer).exchange(query) }
            assertEquals(1, peer.queries); assertEquals(1, peer.closes); assertEquals(0, f.storage.writes)
        }
    }
    @Test fun cancellationAndTimeoutCloseTheTransportWithoutMutatingEvidence() = runTest {
        for (cancel in listOf(false, true)) Fixture().use { f ->
            val query = f.query(); val peer = Peer(f) { null }; val channel = bind(f, peer, timeout = 100)
            val operation = async { runCatching { channel.exchange(query) } }
            peer.waiting.await()
            if (cancel) operation.cancelAndJoin() else assertTrue(operation.await().isFailure)
            f.session.cancel(); assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertEquals(0, f.storage.writes); assertNull(f.session.state.value.lastCompletedAt)
        }
    }
    @Test fun bindingRequiresActiveScopePurposeAuditSupportAndBoundedPayloads() = runTest {
        for (mode in 0..8) Fixture().use { f ->
            val command = ChannelRequestCapability(0u, 1u, 1u, emptySet())
            val other = if (mode == 2) Fixture(99) else null
            try {
                val peer = Peer(other ?: f, requests = if (mode == 3) listOf(command) else emptyList(),
                    auditVersions = if (mode == 4) emptySet() else setOf(1u)) { error("Invalid binding sent data") }
                val channel = connect(peer, purpose = if (mode == 1) EnrolledChannelPurpose.APPROVALS else EnrolledChannelPurpose.AUDIT,
                    maximum = when (mode) { 7 -> PhoneAuditFrame.OVERHEAD_BYTES; 8 -> PhoneAuditFrame.MAXIMUM_BYTES + 1; else -> PhoneAuditFrame.MAXIMUM_BYTES },
                    requests = if (mode == 5) listOf(command) else emptyList(), auditVersions = if (mode == 6) emptySet() else setOf(1u))
                val record = if (mode == 0) StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED) else f.record
                assertFails { PhoneAuditChannel.bind(record, channel, f::clock) }
                assertEquals(0, peer.queries); assertEquals(1, peer.closes)
            } finally { other?.close() }
        }
    }
    @Test fun smallerPayloadBudgetAndDefensiveReplyBytesPreserveTheVerifiedHandoff() = runTest {
        Fixture().use { f ->
            val peer = Peer(f) { f.reply(it) }; val payload = assertIs<PhoneAuditResult.Unverified>(bind(f, peer, maximum = 1024).exchange(f.query()))
            val body = payload.canonicalBody; val signature = payload.signature
            body.fill(0); signature.fill(0)
            assertFalse(body.contentEquals(payload.canonicalBody)); assertFalse(signature.contentEquals(payload.signature))
            payload.acceptInto(f.session, f.record); assertEquals(1, f.storage.writes)
        }
    }
    @Test fun storageRefusalCannotAdvanceCompletionOrRetryTheSameSession() = runTest {
        Fixture().use { f ->
            val peer = Peer(f) { f.reply(it) }; val payload = assertIs<PhoneAuditResult.Unverified>(bind(f, peer).exchange(f.query()))
            f.storage.failWrite = true
            assertFails { payload.acceptInto(f.session, f.record) }
            assertEquals(AuditSyncFailure.STORAGE, f.session.state.value.failure)
            assertNull(f.session.state.value.lastCompletedAt); assertTrue(f.cache.snapshot().proofs.isEmpty())
            assertFails { f.session.start() }; assertEquals(1, peer.queries)
        }
    }
    @Test fun explicitCloseAndJoinWaitsForTheOwnedStream() = runTest {
        Fixture().use { f ->
            val peer = Peer(f) { f.reply(it) }; peer.joinGate = CompletableDeferred()
            val channel = bind(f, peer)
            channel.exchange(f.query())
            val joined = async { channel.closeAndJoin() }
            peer.joining.await(); assertFalse(joined.isCompleted)
            peer.joinGate!!.complete(Unit); joined.await()
            assertEquals(1, peer.closes); assertEquals(1, peer.joins)
        }
    }
}
