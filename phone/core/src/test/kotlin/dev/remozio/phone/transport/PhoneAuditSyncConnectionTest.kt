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
import kotlinx.coroutines.test.*
import kotlin.test.*

class PhoneAuditSyncConnectionTest {
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
        var writes = 0; var closed = false; var failWrite = false; var failClose = false
        var ciphertext: ByteArray? = null
        override fun read(maximumBytes: Int): ByteArray? = ciphertext?.copyOf()
        override fun replace(ciphertext: ByteArray) {
            check(!closed); writes++
            if (failWrite) throw IOException("Synthetic storage refusal")
            this.ciphertext = ciphertext.copyOf()
        }
        override fun close() { if (failClose) throw IOException("Synthetic close failure"); closed = true }
    }
    private inner class Fixture(phone: Int = 3, val budget: Int = 20) : AutoCloseable {
        val root = key(); private val decision = key(); private val biometric = key()
        var now = 100uL; var clockEpoch = 1L; var current = true
        val peers = mutableListOf<Peer>()
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
        val session = AuditSyncSession(cache, budget, 1000u, ::clock)
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

    private class Wire(private val channel: PhoneAuditChannel,
                       private val afterReply: suspend () -> Unit = {},
                       private val cleanup: suspend () -> Unit = {}) : AuditExchange {
        override suspend fun exchange(query: AuditQuery) = channel.exchange(query).also { afterReply() }
        override fun close() = channel.close()
        override suspend fun closeAndJoin() { channel.closeAndJoin(); cleanup() }
    }
    private suspend fun Fixture.wire(reply: (PhoneAuditFrame) -> ByteArray? = { this.reply(it) },
                                     afterReply: suspend () -> Unit = {}, cleanup: suspend () -> Unit = {}): AuditExchange {
        val peer = Peer(this, reply = reply).also(peers::add)
        return Wire(bind(this, peer), afterReply, cleanup)
    }
    private fun connection(f: Fixture, timeout: Long = 5000,
                           gate: suspend ((StoredPhoneEnrollment) -> Unit) -> Boolean = { action ->
                               if (f.current) { action(f.record); true } else false
                           },
                           open: suspend (CoroutineScope, StoredPhoneEnrollment) -> AuditExchange = { _, _ -> f.wire() },
                           limits: () -> AuditRoundLimits = { AuditRoundLimits(f.budget, timeout) },
                           observeLimits: (AuditRoundLimits) -> Unit = {}) =
        PhoneAuditSyncConnection(f.record, f.session, { scope, record, selected -> observeLimits(selected); open(scope, record) },
            gate, limits, Dispatchers.Unconfined)

    @Test fun settingsAreCapturedOnceAndSharedByEveryQueryUntilTheNextRound() = runTest {
        Fixture().use { f ->
            var selected = AuditRoundLimits(20, 1000); val original = selected
            var reads = 0; val observed = mutableListOf<AuditRoundLimits>()
            val next = AuditRoundLimits(1, 5000)
            val owner = connection(f, limits = { reads++; selected }, observeLimits = observed::add,
                open = { _, _ -> f.wire(afterReply = { selected = next }) })
            assertTrue(owner.refresh()); assertEquals(1, reads); assertEquals(2, observed.size)
            assertTrue(observed.all { it === original }); assertEquals(AuditSyncPhase.COMPLETE, owner.state.value.phase)
            val retained = owner.state.value.history.proofs.map { Triple(it.kind, it.canonicalBody, it.signature) }
            assertTrue(owner.refresh()); assertEquals(2, reads); assertSame(next, observed.last())
            assertEquals(retained, owner.state.value.history.proofs.take(retained.size).map { Triple(it.kind, it.canonicalBody, it.signature) }); assertFalse(f.storage.closed)
            owner.closeAndJoin()
        }
    }

    @Test fun explicitContinuationUsesNewLimitsWithoutDroppingPausedEvidenceOrReopeningTheCache() = runTest {
        Fixture(budget = 1).use { f ->
            var selected = AuditRoundLimits(1, 1000); val observed = mutableListOf<AuditRoundLimits>()
            val owner = connection(f, limits = { selected }, observeLimits = observed::add)
            assertTrue(owner.refresh()); assertEquals(AuditSyncPhase.PAUSED, owner.state.value.phase)
            val retained = owner.state.value.history.proofs.single()
            selected = AuditRoundLimits(2, 5000)
            assertTrue(owner.resume()); assertEquals(AuditSyncPhase.COMPLETE, owner.state.value.phase)
            assertEquals(listOf(1000L, 5000L), observed.map { it.timeoutMillis })
            assertEquals(listOf(1, 2), observed.map { it.responseBudget })
            assertEquals(retained.canonicalBody, owner.state.value.history.proofs.first().canonicalBody)
            assertEquals(retained.signature, owner.state.value.history.proofs.first().signature); assertFalse(f.storage.closed)
            assertEquals(2, f.storage.writes); owner.closeAndJoin()
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun savingALongerTimeoutCannotExtendAnInflightRoundOrReadSettingsFromBusyCalls() = runTest {
        Fixture().use { f ->
            var selected = AuditRoundLimits(20, 1000); var reads = 0
            val owner = connection(f, limits = { reads++; selected }, open = { _, _ -> f.wire(reply = { null }) })
            val running = async { owner.refresh() }
            while (f.peers.isEmpty()) yield()
            f.peers.single().waiting.await(); selected = AuditRoundLimits(20, 60_000)
            assertFalse(owner.refresh()); assertFalse(owner.resume()); assertEquals(1, reads)
            advanceTimeBy(1000); runCurrent(); assertFalse(running.await())
            assertEquals(1, f.peers.single().joins); assertEquals(1, reads)
            assertNull(owner.state.value.lastCompletedAt); assertEquals(AuditSyncFailure.TRANSPORT, owner.state.value.failure)
            owner.closeAndJoin()
        }
    }

    @Test fun completesSignedHistoryAndPageWithOneJoinedStreamPerQuery() = runTest {
        Fixture().use { f ->
            val owner = connection(f)
            assertTrue(owner.refresh())
            assertEquals(AuditSyncPhase.COMPLETE, owner.state.value.phase)
            assertEquals(2, owner.state.value.history.proofs.size)
            assertEquals(2, f.storage.writes); assertEquals(2, f.peers.size)
            assertTrue(f.peers.all { it.queries == 1 && it.joins == 1 })
            assertNotNull(owner.state.value.lastCompletedAt); assertFalse(f.storage.closed)
            owner.closeAndJoin(); assertTrue(f.storage.closed); assertEquals(AuditSyncPhase.CLOSED, owner.state.value.phase)
        }
    }

    @Test fun responseBudgetPausesAndExplicitResumeKeepsTheOriginalRound() = runTest {
        Fixture(budget = 1).use { f ->
            val owner = connection(f)
            assertTrue(owner.refresh()); assertEquals(AuditSyncPhase.PAUSED, owner.state.value.phase)
            assertEquals(1, f.storage.writes); assertNull(owner.state.value.lastCompletedAt)
            assertFalse(owner.refresh()); assertEquals(1, f.peers.size)
            assertTrue(owner.resume()); assertEquals(AuditSyncPhase.COMPLETE, owner.state.value.phase)
            assertEquals(2, f.peers.size); assertEquals(2, f.storage.writes)
            owner.closeAndJoin()
        }
    }

    @Test fun revocationAfterReplyCannotWriteOrPublishSuccess() = runTest {
        Fixture().use { f ->
            val owner = connection(f, open = { _, _ -> f.wire(afterReply = { f.current = false }) })
            assertFalse(owner.refresh()); assertEquals(0, f.storage.writes)
            assertNull(owner.state.value.lastCompletedAt); assertEquals(AuditSyncPhase.FAILED, owner.state.value.phase)
            assertEquals(1, f.peers.single().joins); owner.closeAndJoin()
        }
    }

    @Test fun absentOrWrongCurrentEnrollmentCannotOpenTheFirstStream() = runTest {
        Fixture().use { f ->
            f.current = false; val owner = connection(f)
            assertFalse(owner.refresh()); assertTrue(f.peers.isEmpty()); owner.closeAndJoin()
        }
        Fixture().use { f ->
            Fixture(phone = 99).use { other ->
                val owner = connection(f, gate = { action -> action(other.record); true })
                assertFalse(owner.refresh()); assertTrue(f.peers.isEmpty()); owner.closeAndJoin()
                assertFailsWith<IllegalArgumentException> {
                    PhoneAuditSyncConnection(other.record, f.session, { _, _, _ -> error("No transport") },
                        { true }, { AuditRoundLimits(20, 1000) }, Dispatchers.Unconfined)
                }
            }
        }
    }

    @Test fun busyRefreshDoesNotQueueAndCancellationJoinsWithoutClosingTheCache() = runTest {
        Fixture().use { f ->
            var block = true
            val owner = connection(f, open = { _, _ -> if (block) f.wire(reply = { null }) else f.wire() })
            val running = async { owner.refresh() }
            while (f.peers.isEmpty()) yield()
            f.peers.single().waiting.await()
            assertFalse(owner.refresh()); assertFalse(owner.resume()); assertEquals(1, f.peers.size)
            running.cancelAndJoin(); assertEquals(1, f.peers.single().joins)
            assertEquals(AuditSyncPhase.CANCELLED, owner.state.value.phase); assertFalse(f.storage.closed)
            block = false; assertTrue(owner.refresh()); owner.closeAndJoin()
        }
    }

    @Test fun retirementWaitsForTheActualStreamJoinBeforeClosingTheCache() = runTest {
        Fixture().use { f ->
            val joinGate = CompletableDeferred<Unit>()
            val owner = connection(f, open = { _, _ ->
                val peer = Peer(f) { null }.also { f.peers.add(it); it.joinGate = joinGate }
                Wire(bind(f, peer))
            })
            val running = async { owner.refresh() }
            while (f.peers.isEmpty()) yield()
            val peer = f.peers.single(); peer.waiting.await()
            val retiring = async { owner.closeAndJoin() }
            peer.joining.await(); assertFalse(retiring.isCompleted); assertFalse(f.storage.closed)
            assertEquals(0, f.storage.writes)
            joinGate.complete(Unit); retiring.await(); running.join()
            assertTrue(f.storage.closed); assertEquals(AuditSyncPhase.CLOSED, owner.state.value.phase)
        }
    }

    @Test fun retirementUnderTheEnrollmentMutexCancelsItsWaitingAcceptanceWithoutDeadlock() = runTest {
        Fixture().use { f ->
            val mutex = kotlinx.coroutines.sync.Mutex()
            val replied = CompletableDeferred<Unit>()
            val owner = connection(f, gate = { action ->
                mutex.lock()
                try { if (f.current) { action(f.record); true } else false } finally { mutex.unlock() }
            }, open = { _, _ -> f.wire(afterReply = { mutex.lock(); replied.complete(Unit) }) })
            val running = async { owner.refresh() }
            replied.await() // The transport has replied, but acceptance must wait for the held enrollment mutex.
            withTimeout(1000) { owner.closeAndJoin() }
            f.current = false; mutex.unlock(); running.join()
            assertEquals(0, f.storage.writes); assertTrue(f.storage.closed)
            assertNull(owner.state.value.lastCompletedAt)
        }
    }

    @Test fun timeoutClosesTheQueryAndAllowsOnlyAFreshRound() = runTest {
        Fixture().use { f ->
            var block = true
            val owner = connection(f, timeout = 100, open = { _, _ -> if (block) f.wire(reply = { null }) else f.wire() })
            assertFalse(owner.refresh()); assertEquals(0, f.storage.writes)
            assertEquals(1, f.peers.single().joins); assertEquals(AuditSyncFailure.TRANSPORT, owner.state.value.failure)
            block = false; assertTrue(owner.refresh()); assertEquals(3, f.peers.size); owner.closeAndJoin()
        }
    }

    @Test fun wrongSignatureAndStorageFailureCannotAdvanceCompletion() = runTest {
        Fixture().use { f ->
            val wrong = key()
            val owner = connection(f, open = { _, _ -> f.wire(reply = { f.reply(it, signer = wrong) }) })
            assertFalse(owner.refresh()); assertEquals(0, f.storage.writes)
            assertEquals(AuditSyncFailure.INVALID_RESPONSE, owner.state.value.failure)
            assertNull(owner.state.value.lastCompletedAt); owner.closeAndJoin()
        }
        Fixture().use { f ->
            f.storage.failWrite = true; val owner = connection(f)
            assertFalse(owner.refresh()); assertEquals(AuditSyncFailure.STORAGE, owner.state.value.failure)
            assertNull(owner.state.value.lastCompletedAt); assertTrue(owner.state.value.history.proofs.isEmpty())
            assertFalse(owner.refresh()); assertEquals(1, f.peers.size); owner.closeAndJoin()
        }
    }

    @Test fun unsettledCleanupKeepsTheCacheOwnedAndBlocksNewOperations() = runTest {
        Fixture().use { f ->
            var fail = true
            val owner = connection(f, open = { _, _ -> f.wire(cleanup = { if (fail) throw IOException("Unsettled stream") }) })
            assertFalse(owner.refresh()); assertFalse(f.storage.closed)
            assertEquals(1, owner.state.value.history.proofs.size)
            assertFailsWith<IllegalStateException> { owner.refresh() }
            assertFailsWith<IOException> { owner.closeAndJoin() }
            assertFalse(f.storage.closed)
            fail = false; owner.closeAndJoin(); assertTrue(f.storage.closed)
        }
    }

    @Test fun lateOpeningTransportIsJoinedBeforeRetirementReleasesTheCache() = runTest {
        Fixture().use { f ->
            val opening = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
            val owner = connection(f, open = { _, _ ->
                opening.complete(Unit)
                withContext(NonCancellable) { release.await(); f.wire() }
            })
            val running = async { owner.refresh() }; opening.await()
            val retiring = async { owner.closeAndJoin() }
            yield(); assertFalse(retiring.isCompleted); assertFalse(f.storage.closed)
            release.complete(Unit); retiring.await(); running.join()
            assertTrue(f.storage.closed); assertEquals(1, f.peers.single().joins); assertEquals(0, f.storage.writes)
        }
    }

    @Test fun aResultForAnotherQueryCannotReachTheCache() = runTest {
        Fixture().use { f ->
            Fixture().use { other ->
                other.session.start(); val foreignQuery = other.query()
                val foreign = other.wire()
                val result = foreign.exchange(foreignQuery)
                foreign.closeAndJoin()
                val owner = connection(f, open = { _, _ -> object : AuditExchange {
                    override suspend fun exchange(query: AuditQuery) = result
                    override fun close() = Unit
                    override suspend fun closeAndJoin() = Unit
                } })
                assertFalse(owner.refresh()); assertEquals(0, f.storage.writes)
                assertNull(owner.state.value.lastCompletedAt); owner.closeAndJoin()
            }
        }
    }

    @Test fun anOperationCannotRetireItselfOrDeadlockItsParentJob() = runTest {
        Fixture().use { f ->
            lateinit var owner: PhoneAuditSyncConnection
            owner = connection(f, open = { _, _ -> owner.closeAndJoin(); error("Must not return") })
            assertFalse(owner.refresh()); assertEquals(0, f.storage.writes)
            assertFalse(f.storage.closed)
            owner.closeAndJoin(); assertTrue(f.storage.closed)
        }
    }

    @Test fun failedCacheClosureCannotBeMistakenForAReleasedOwnerOnRetry() = runTest {
        val f = Fixture(); val owner = connection(f)
        assertTrue(owner.refresh()); f.storage.failClose = true
        assertFailsWith<IOException> { owner.closeAndJoin() }
        assertFalse(f.storage.closed)
        f.storage.failClose = false
        assertFailsWith<IllegalStateException> { owner.closeAndJoin() }
        assertFalse(f.storage.closed)
    }
}
