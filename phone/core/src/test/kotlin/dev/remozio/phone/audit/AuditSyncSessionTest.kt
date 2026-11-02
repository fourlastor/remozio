package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import kotlin.test.*

class AuditSyncSessionTest {
    private val bound = CborLimits(65536, 8, 2048)
    private val limits = AuditPageLimits(bound, bound, bound, 8, bound, bound)
    private val capacity = AuditEvidenceLimits(100, 1000000, 100, 20)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun bytes(n: Int) = CborValue.Bytes(id(n))
    private class Disk { var bytes: ByteArray? = null }
    private class Storage(val disk: Disk) : AuditCiphertextStorage {
        var writes = 0
        var failAfterWrite = false
        var closed = false
        override fun read(maximumBytes: Int) = disk.bytes?.copyOf()?.also { check(it.size <= maximumBytes) }
        override fun replace(ciphertext: ByteArray) {
            check(!closed); disk.bytes = ciphertext.copyOf(); writes++
            if (failAfterWrite) throw IOException("Injected ambiguous write")
        }
        override fun close() { closed = true }
    }
    private data class Epoch(val id: Int, var head: Int, val previous: Int? = null,
                             val cause: AuditEpochCause = AuditEpochCause.RESTART, var retained: Int = 0)
    private inner class Fixture(val budget: Int = 20, head: Int = 4, val withLocalTimes: Boolean = false) {
        private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val publicKey: ByteArray get() = (keys.public as ECPublicKey).w.let { point ->
            fun scalar(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        val binding = AuditCacheBinding(id(1), id(2), publicKey)
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val disk = Disk(); val storage = Storage(disk)
        val localDisk = Disk(); val localStorage = Storage(localDisk)
        var phoneNow = 50_000L
        var clockReads = 0
        fun cache(storage: Storage, metadata: Storage = localStorage) = EncryptedAuditCache.open(storage,
            AuditArchiveCipher(key, bound.maxBytes), binding, limits, capacity, bound,
            localSync = { verified -> if (withLocalTimes) AuditLocalSyncArchive.open(metadata, key, binding, verified) {
                clockReads++; phoneNow
            } else null })
        val cache = cache(storage)
        var now = 100uL
        val session by lazy { AuditSyncSession(cache, budget, 1000u) { ElapsedInstant(1, now) } }
        val epochs = linkedMapOf(3 to Epoch(3, head))
        var current = 3
        var duplicateEventID = false
        fun next() = assertNotNull(session.next())
        fun respond(query: AuditQuery = next()) {
            val body = when (query) {
                is AuditHistoryQuery -> history(query)
                is AuditPageQuery -> page(query)
            }
            now++
            session.accept(query, body, sign(body, query))
        }
        fun drain() {
            repeat(40) {
                when (session.state.value.phase) {
                    AuditSyncPhase.PAUSED -> session.resume()
                    AuditSyncPhase.SYNCING -> session.next()?.let(::respond)
                    else -> return
                }
            }
            error("Sync did not finish")
        }
        fun receiver() = AuditPageReceiver(id(1), id(2), publicKey, limits, 1, 1000u) { ElapsedInstant(1, now) }
        fun sign(body: ByteArray, query: AuditQuery) = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(keys.private)
            update(if (query is AuditHistoryQuery) AuditHistoryStatusSigningInput.make(1u, body, bound, bound)
                else AuditBatchSigningInput.make(1u, body, bound, bound))
            sign()
        })
        private fun header(epoch: Epoch) = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to bytes(1), 2uL to bytes(2), 3uL to bytes(epoch.id),
            4uL to CborValue.Unsigned(7u), 5uL to CborValue.Unsigned(epoch.cause.tag),
            6uL to (epoch.previous?.let(::bytes) ?: CborValue.Null),
            7uL to (epoch.previous?.let { CborValue.Unsigned(0u) } ?: CborValue.Null), 8uL to CborValue.Null,
        )), bound)
        fun history(query: AuditHistoryQuery): ByteArray {
            val requested = query.requestedEpoch?.let { it[0].toInt() }
            val queried = requested?.let(epochs::get)
            val active = epochs.getValue(current)
            val disposition = when {
                requested == null -> AuditHistoryDisposition.DISCOVERY
                queried == null -> AuditHistoryDisposition.UNAVAILABLE
                checkNotNull(query.requestedAfter) > queried.head.toULong() -> AuditHistoryDisposition.CURSOR_AHEAD
                else -> AuditHistoryDisposition.AVAILABLE
            }
            return DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to bytes(1), 2uL to bytes(2), 3uL to CborValue.Bytes(query.queryNonce),
                4uL to (requested?.let(::bytes) ?: CborValue.Null),
                5uL to (query.requestedAfter?.let(CborValue::Unsigned) ?: CborValue.Null),
                6uL to CborValue.Unsigned(disposition.tag), 7uL to CborValue.Bytes(header(active)),
                8uL to CborValue.Unsigned(active.retained.toULong()), 9uL to CborValue.Unsigned(active.head.toULong()),
                10uL to (queried?.let { CborValue.Bytes(header(it)) } ?: CborValue.Null),
                11uL to (queried?.let { CborValue.Unsigned(it.retained.toULong()) } ?: CborValue.Null),
                12uL to (queried?.let { CborValue.Unsigned(it.head.toULong()) } ?: CborValue.Null),
            )), bound)
        }
        fun page(query: AuditPageQuery): ByteArray {
            val epoch = epochs.getValue(query.journalEpoch[0].toInt())
            val after = maxOf(query.requestedAfter.toInt(), epoch.retained)
            val records = (after + 1..minOf(after + 2, epoch.head)).map { sequence ->
                val record = AuditEventMetadata(id(if (duplicateEventID) 1 else sequence), id(1), id(2), id(epoch.id), sequence.toULong(),
                    id(8), null, null, AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND, null, null,
                    AuditAuthentication.SYSTEM, AuditOutcome.PENDING, AuditReason.NONE, null, null)
                CborValue.Bytes(record.encode(bound))
            }
            return DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to bytes(1), 2uL to bytes(2), 3uL to bytes(epoch.id),
                4uL to CborValue.Unsigned(7u), 5uL to CborValue.Unsigned(query.requestedAfter),
                6uL to CborValue.Unsigned(epoch.retained.toULong()), 7uL to CborValue.Unsigned(epoch.head.toULong()),
                8uL to CborValue.Bytes(query.queryNonce), 9uL to CborValue.ArrayValue(records),
            )), bound)
        }
    }

    @Test fun newBudgetAndQueryLifetimeApplyAtExplicitBoundariesWithoutResettingEvidence() {
        val f = Fixture(head = 4)
        f.session.start(responseBudget = 1, queryLifetimeMs = 10u)
        val original = f.next(); f.respond(original); val retained = f.session.state.value.history.proofs.single()
        assertEquals(AuditSyncPhase.PAUSED, f.session.state.value.phase)
        f.session.resume(responseBudget = 2, queryLifetimeMs = 2000u)
        val page = assertIs<AuditPageQuery>(f.next()); assertEquals(0uL, page.requestedAfter)
        original.close(); f.now += 1001u; f.respond(page)
        assertEquals(AuditSyncPhase.SYNCING, f.session.state.value.phase)
        assertEquals(retained.canonicalBody, f.session.state.value.history.proofs.first().canonicalBody)
        assertEquals(retained.signature, f.session.state.value.history.proofs.first().signature)
        f.respond(); assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(listOf(1uL, 2uL, 3uL, 4uL), f.session.state.value.history.epochs.single().records.map { it.sequence })
        assertFalse(f.storage.closed); f.session.close()
    }

    @Test fun activeQueryCannotBeExtendedByStartingOrResumingWithDifferentLimits() {
        val f = Fixture(head = 1); f.session.start(responseBudget = 1, queryLifetimeMs = 10u)
        val query = f.next()
        assertFailsWith<IllegalStateException> { f.session.start(responseBudget = 100, queryLifetimeMs = 60_000u) }
        assertFailsWith<IllegalStateException> { f.session.resume(responseBudget = 100, queryLifetimeMs = 60_000u) }
        f.now += 11u
        assertFailsWith<AuditPageException> { f.respond(query) }
        assertEquals(AuditSyncFailure.INVALID_RESPONSE, f.session.state.value.failure)
        assertEquals(0, f.storage.writes); assertNull(f.session.state.value.lastCompletedAt)
        f.session.close()
    }

    @Test fun persistsBeforeAdvancingAndResumesWithoutChasingAnExpandingHead() {
        val f = Fixture(budget = 2)
        assertEquals(AuditSyncPhase.IDLE, f.session.state.value.phase)
        assertNull(f.session.state.value.lastCompletedAt)
        f.session.start(); f.respond()
        assertNull(f.session.state.value.lastCompletedAt)
        val firstPage = f.next() as AuditPageQuery
        assertEquals(0uL, firstPage.requestedAfter)
        assertFailsWith<IllegalStateException> { f.session.next() }
        f.respond(firstPage)
        assertEquals(AuditSyncPhase.PAUSED, f.session.state.value.phase)
        assertEquals(2, f.storage.writes)
        assertEquals(listOf(1uL, 2uL), f.session.state.value.history.epochs.single().records.map { it.sequence })
        assertNull(f.session.state.value.lastCompletedAt)
        f.session.resume(); f.epochs.getValue(3).head = 9
        val second = f.next() as AuditPageQuery
        assertEquals(2uL, second.requestedAfter)
        assertFalse(firstPage.queryNonce.contentEquals(second.queryNonce))
        f.respond(second)
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(ElapsedInstant(1, f.now), f.session.state.value.lastCompletedAt)
        assertEquals(listOf(AuditHistoryGap(4u, 9u, false)), f.session.state.value.history.epochs.single().gaps)
        assertTrue(checkNotNull(f.session.state.value.currentObservation).receivedAt.milliseconds < f.now)
        assertNull(f.session.next())
        assertFailsWith<IllegalStateException> { f.respond(second) }
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
    }

    @Test fun restoresNewEpochWithoutDiscardingAheadOrUnavailableOldHistory() {
        val f = Fixture(head = 3); f.session.start(); f.drain()
        f.epochs.getValue(3).head = 1
        f.epochs[4] = Epoch(4, 1, 3, AuditEpochCause.RESTORATION); f.current = 4
        f.session.start(); f.respond()
        val first = f.next() as AuditPageQuery
        assertContentEquals(id(4), first.journalEpoch)
        f.respond(first)
        val old = f.next() as AuditHistoryQuery
        assertContentEquals(id(3), old.requestedEpoch); assertEquals(3uL, old.requestedAfter)
        f.respond(old)
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        var saved = f.session.state.value.history
        assertEquals(3, saved.epochs.single { it.epoch == bytes(3) }.records.size)
        assertEquals(AuditHistoryDisposition.CURSOR_AHEAD, saved.proofs.last().historyStatus?.disposition)
        f.epochs.remove(3); f.epochs[5] = Epoch(5, 1, 4); f.current = 5
        f.session.start(); f.drain(); saved = f.session.state.value.history
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(3, saved.epochs.single { it.epoch == bytes(3) }.records.size)
        assertEquals(1, saved.epochs.single { it.epoch == bytes(5) }.records.size)
        assertTrue(saved.proofs.any { it.historyStatus?.disposition == AuditHistoryDisposition.UNAVAILABLE })
    }

    @Test fun fillsCachedHolesAndSkipsAlreadyRetainedRecords() {
        val f = Fixture()
        val receiver = f.receiver(); val query = receiver.begin(id(3), 7u, 2u)
        val body = f.page(query); f.cache.append(receiver.receive(query, body, f.sign(body, query))); receiver.close()
        f.session.start(); f.respond()
        val gap = f.next() as AuditPageQuery
        assertEquals(0uL, gap.requestedAfter)
        f.respond(gap)
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(listOf(1uL, 2uL, 3uL, 4uL), f.session.state.value.history.epochs.single().records.map { it.sequence })
    }

    @Test fun rejectsInvalidExpiredAndStaleRepliesWithoutUpdatingSuccessfulSync() {
        val f = Fixture(head = 0); f.session.start()
        val invalid = f.next() as AuditHistoryQuery
        assertFailsWith<AuditPageException> { f.session.accept(invalid, f.history(invalid), ByteArray(64)) }
        assertEquals(AuditSyncFailure.INVALID_RESPONSE, f.session.state.value.failure)
        assertEquals(0, f.storage.writes); assertNull(f.session.state.value.lastCompletedAt)
        f.session.start(); val fresh = f.next() as AuditHistoryQuery
        assertFailsWith<IllegalStateException> { f.session.transportFailed(invalid) }
        assertEquals(AuditSyncPhase.SYNCING, f.session.state.value.phase)
        f.respond(fresh); val completed = f.session.state.value.lastCompletedAt
        f.session.start(); val expired = f.next() as AuditHistoryQuery
        f.now += 1000u
        assertFailsWith<AuditPageException> { f.respond(expired) }
        assertEquals(completed, f.session.state.value.lastCompletedAt)
        f.session.start(); val cancelled = f.next(); f.session.cancel()
        f.session.start(); val replacement = f.next()
        assertFailsWith<IllegalStateException> { f.respond(cancelled) }
        f.respond(replacement)
        f.session.start(); val closing = f.next() as AuditHistoryQuery
        val closingBody = f.history(closing); val writesBeforeClose = f.storage.writes
        f.session.close(); assertTrue(f.storage.closed)
        assertFailsWith<IllegalStateException> { f.session.accept(closing, closingBody, f.sign(closingBody, closing)) }
        assertEquals(writesBeforeClose, f.storage.writes)
        assertEquals(AuditSyncPhase.CLOSED, f.session.state.value.phase)
        assertTrue(f.session.state.value.history.proofs.isNotEmpty())
        assertFailsWith<IllegalStateException> { f.session.start() }
    }

    @Test fun uncertainPersistenceRequiresReopenAndDoesNotClaimSuccessfulSync() {
        val f = Fixture(head = 0); f.session.start(); f.storage.failAfterWrite = true
        assertFailsWith<IOException> { f.respond() }
        assertEquals(AuditSyncFailure.STORAGE, f.session.state.value.failure)
        assertTrue(f.session.state.value.history.proofs.isEmpty())
        assertNull(f.session.state.value.lastCompletedAt)
        assertFailsWith<IllegalStateException> { f.session.start() }
        f.session.cancel(); assertFailsWith<IllegalStateException> { f.session.start() }
        f.session.close()
        val reopened = AuditSyncSession(f.cache(Storage(f.disk)), 20, 1000u) { ElapsedInstant(1, f.now) }
        assertEquals(1, reopened.state.value.history.proofs.size)
        assertNull(reopened.state.value.lastCompletedAt)
        assertNull(reopened.state.value.currentObservation)
        reopened.close()
    }

    @Test fun keepsConflictingProofsWithoutClaimingTheRoundSucceeded() {
        val f = Fixture(head = 1); f.session.start(); f.drain()
        val completed = f.session.state.value.lastCompletedAt
        f.epochs.getValue(3).head = 2; f.duplicateEventID = true
        f.session.start(); f.respond()
        assertEquals(AuditSyncFailure.CONFLICT, assertFailsWith<AuditSyncException> { f.respond() }.reason)
        val state = f.session.state.value
        assertEquals(completed, state.lastCompletedAt)
        assertEquals(1, state.history.epochs.single().records.size)
        assertEquals(setOf(AuditEvidenceConflict.EVENT_ID), state.history.proofs.last().conflicts)
    }

    @Test fun detectsCausalHeadRegressionAndReconcilesTheCurrentEpochCursor() {
        val f = Fixture(); f.session.start(); f.respond()
        f.epochs.getValue(3).head = 2
        assertEquals(AuditSyncFailure.HISTORY_CHANGED, assertFailsWith<AuditSyncException> { f.respond() }.reason)
        assertNull(f.session.state.value.lastCompletedAt)
        f.session.start(); f.respond()
        val reconcile = f.next() as AuditHistoryQuery
        assertContentEquals(id(3), reconcile.requestedEpoch); assertEquals(4uL, reconcile.requestedAfter)
        f.respond(reconcile)
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(AuditHistoryDisposition.CURSOR_AHEAD, f.session.state.value.history.proofs.last().historyStatus?.disposition)
        assertEquals(listOf(AuditHistoryGap(2u, 4u, false)), f.session.state.value.history.epochs.single().gaps)
    }

    @Test fun retentionAndTransportFailuresRemainVisible() {
        val f = Fixture(head = 4); f.epochs.getValue(3).retained = 2
        f.session.start(); f.drain()
        assertEquals(listOf(AuditHistoryGap(0u, 2u, true)), f.session.state.value.history.epochs.single().gaps)
        val completed = f.session.state.value.lastCompletedAt
        f.session.start(); val query = f.next(); f.session.transportFailed(query)
        assertEquals(AuditSyncFailure.TRANSPORT, f.session.state.value.failure)
        assertEquals(completed, f.session.state.value.lastCompletedAt)
        f.session.start(); f.drain()
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
    }

    @Test fun concurrentRepliesHaveOneDurableWinner() {
        val f = Fixture(head = 0); f.session.start(); val query = f.next() as AuditHistoryQuery
        val body = f.history(query); val signature = f.sign(body, query)
        val start = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        try {
            val results = (1..2).map { pool.submit<Boolean> {
                check(start.await(5, TimeUnit.SECONDS))
                try { f.session.accept(query, body, signature); true } catch (_: IllegalStateException) { false }
            } }
            start.countDown()
            assertEquals(1, results.count { it.get(5, TimeUnit.SECONDS) })
            assertEquals(1, f.storage.writes)
            assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        } finally { pool.shutdownNow(); f.session.close() }
    }

    @Test fun savedSyncTimesSurviveReopeningWithoutRestoringALiveRoundOrElapsedAuthority() {
        val f = Fixture(budget = 1, withLocalTimes = true)
        assertNull(f.session.state.value.localTimes)
        f.session.start(); f.respond()
        assertEquals(AuditSyncPhase.PAUSED, f.session.state.value.phase)
        val partial = assertNotNull(f.session.state.value.localTimes)
        assertEquals(50_000L, partial.lastResponse.unixMilliseconds); assertNull(partial.lastCompleted)
        f.phoneNow = 40_000 // A phone-clock regression changes the observation; it does not reorder by timestamp.
        f.session.resume(10); f.drain()
        val completed = assertNotNull(f.session.state.value.localTimes)
        assertEquals(completed.lastResponse, completed.lastCompleted)
        assertEquals(40_000L, completed.lastResponse.unixMilliseconds)
        val reads = f.clockReads
        f.session.close(); assertTrue(f.localStorage.closed)
        f.cache(Storage(f.disk), Storage(f.localDisk)).use { cache ->
            val restarted = AuditSyncSession(cache, 5, 1000u) { ElapsedInstant(88, 1u) }
            assertEquals(AuditSyncPhase.IDLE, restarted.state.value.phase)
            assertEquals(completed, restarted.state.value.localTimes)
            assertNull(restarted.state.value.lastCompletedAt); assertNull(restarted.state.value.lastResponseAt)
            assertEquals(reads, f.clockReads)
            restarted.close()
        }
    }

    @Test fun invalidExpiredOrUnpersistedRepliesCannotAdvanceSavedSyncTimes() {
        val f = Fixture(withLocalTimes = true); f.session.start()
        var q = f.next(); var body = f.history(q as AuditHistoryQuery)
        assertFails { f.session.accept(q, body, ByteArray(64)) }
        assertNull(f.localDisk.bytes); assertEquals(0, f.clockReads)
        f.session.start(); q = f.next(); body = f.history(q as AuditHistoryQuery)
        f.now += 1001u
        assertFails { f.session.accept(q, body, f.sign(body, q)) }
        assertNull(f.localDisk.bytes); assertEquals(0, f.clockReads)
        f.session.start(); f.respond()
        val known = f.session.state.value.localTimes; val saved = f.localDisk.bytes?.copyOf(); val reads = f.clockReads
        q = f.next(); body = f.page(q as AuditPageQuery); f.storage.failAfterWrite = true
        assertFailsWith<IOException> { f.session.accept(q, body, f.sign(body, q)) }
        assertEquals(known, f.session.state.value.localTimes); assertContentEquals(saved, f.localDisk.bytes)
        assertEquals(reads, f.clockReads); assertEquals(AuditSyncFailure.STORAGE, f.session.state.value.failure)
        f.session.close()
    }

    @Test fun anAmbiguousMetadataWriteCannotFailACompletedSyncOrInventVisibleFreshness() {
        val f = Fixture(head = 0, withLocalTimes = true); f.localStorage.failAfterWrite = true
        f.session.start(); f.respond()
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(1, f.session.state.value.history.proofs.size); assertNull(f.session.state.value.localTimes)
        val proofs = f.disk.bytes?.copyOf(); val reads = f.clockReads
        f.session.close()
        f.cache(Storage(f.disk), Storage(f.localDisk)).use {
            // Readback may recover the committed metadata only after its referenced proof verifies.
            assertNotNull(it.localSyncTimes()?.lastCompleted); assertEquals(reads, f.clockReads)
            assertEquals(1, it.snapshot().proofs.size)
        }
        assertContentEquals(proofs, f.disk.bytes)
    }

    @Test fun aConflictRecordsOnlyAResponseAndInvalidPhoneTimeDoesNotDamageSignedHistory() {
        val f = Fixture(head = 1, withLocalTimes = true); f.session.start(); f.drain()
        val completed = assertNotNull(f.session.state.value.localTimes).lastCompleted
        f.epochs.getValue(3).head = 2; f.duplicateEventID = true
        f.session.start(); f.respond()
        val partial = assertNotNull(f.session.state.value.localTimes)
        assertFailsWith<AuditSyncException> { f.respond() }
        assertEquals(AuditSyncFailure.CONFLICT, f.session.state.value.failure)
        val failed = assertNotNull(f.session.state.value.localTimes)
        assertEquals(completed, failed.lastCompleted); assertTrue(failed.lastResponse.proofID != partial.lastResponse.proofID)
        f.session.close()
        val other = Fixture(head = 0, withLocalTimes = true); other.phoneNow = -1
        other.session.start(); other.respond()
        assertEquals(AuditSyncPhase.COMPLETE, other.session.state.value.phase)
        assertEquals(1, other.session.state.value.history.proofs.size); assertNull(other.session.state.value.localTimes)
        assertNull(other.localDisk.bytes); other.session.close()
    }


    @Test fun aLaterMetadataFailureKeepsThePreviousConfirmedTimeAndAllNewSignedEvidence() {
        val f = Fixture(head = 0, withLocalTimes = true)
        f.session.start(); f.respond()
        val known = assertNotNull(f.session.state.value.localTimes)
        f.phoneNow = 60_000; f.epochs.getValue(3).head = 1; f.localStorage.failAfterWrite = true
        f.session.start(); f.respond(); f.respond()
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(3, f.session.state.value.history.proofs.size)
        assertEquals(known, f.session.state.value.localTimes)
        f.localStorage.failAfterWrite = false; f.phoneNow = 70_000
        f.session.start(); f.respond()
        assertEquals(AuditSyncPhase.COMPLETE, f.session.state.value.phase)
        assertEquals(70_000L, f.session.state.value.localTimes?.lastCompleted?.unixMilliseconds)
        assertEquals(4, f.session.state.value.history.proofs.size)
        f.session.close()
    }

}
