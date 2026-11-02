package dev.remozio.android.audit

import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.transport.PhoneAuditResult
import dev.remozio.protocol.*
import java.io.IOException
import java.security.Signature
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlinx.coroutines.flow.collect
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class ForegroundAuditConnectionsTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun key() = pair().public.encoded
    private inner class Peer(n: Int, dispatcher: CoroutineDispatcher, private val blockExchange: Boolean = false,
                             private val cleanup: CompletableDeferred<Unit>? = null, budget: Int = 2) {
        var exchanges = 0; var joins = 0; var cacheClosed = false
        val cleanupEntered = CompletableDeferred<Unit>()
        private fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val pair = key()
            return EnrollmentKeyReference(role, id(10 + role.ordinal), "remozio.${role.aliasPart}.v1.${"%032x".format(10 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) pair else pair.takeLast(65).toByteArray())
        }
        private val root = pair()
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(n), id(20 + n), id(21), id(30 + n), id(4), "Same label",
            root.public.encoded.takeLast(65).toByteArray(), key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION),
            local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        private val bound = CborLimits(65536, 8, 2048)
        private val e = record.enrollment
        private var archive: ByteArray? = null
        private val cache = EncryptedAuditCache.open(object : AuditCiphertextStorage {
            override fun read(maximumBytes: Int): ByteArray? = archive?.copyOf()
            override fun replace(ciphertext: ByteArray) { archive = ciphertext.copyOf() }
            override fun close() { cacheClosed = true }
        }, AuditArchiveCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), bound.maxBytes),
            AuditCacheBinding(e.macID.copyBytes(), e.accountID.copyBytes(), e.authorityPublicKey.copyBytes()),
            AuditPageLimits(bound, bound, bound, 8, bound, bound), AuditEvidenceLimits(100, 1_000_000, 100, 20), bound)
        private val session = AuditSyncSession(cache, budget, 1000u) { ElapsedInstant(1, 100u) }
        val connection = PhoneAuditSyncConnection(record, session,
            open = { _, _, _ -> object : AuditExchange {
                override suspend fun exchange(query: AuditQuery): PhoneAuditResult {
                    exchanges++
                    if (blockExchange) awaitCancellation()
                    throw IOException("Synthetic transport failure")
                }
                override fun close() = Unit
                override suspend fun closeAndJoin() { joins++; cleanupEntered.complete(Unit); cleanup?.await() }
            } }, withCurrent = { action -> action(record); true }, roundLimits = { AuditRoundLimits(budget, 1000) }, dispatcher = dispatcher)
        fun pauseWithSignedHistory() {
            fun fields(vararg values: Pair<ULong, CborValue>) = DeterministicCbor.encode(CborValue.Fields(mapOf(*values)), bound)
            fun number(n: ULong) = CborValue.Unsigned(n)
            session.start(); val query = assertIs<AuditHistoryQuery>(session.next())
            val descriptor = fields(0uL to number(1u), 1uL to e.macID, 2uL to e.accountID,
                3uL to CborValue.Bytes(id(70)), 4uL to number(1u), 5uL to number(0u),
                6uL to CborValue.Null, 7uL to CborValue.Null, 8uL to CborValue.Null)
            val body = fields(0uL to number(1u), 1uL to e.macID, 2uL to e.accountID,
                3uL to CborValue.Bytes(query.queryNonce), 4uL to CborValue.Null, 5uL to CborValue.Null,
                6uL to number(0u), 7uL to CborValue.Bytes(descriptor), 8uL to number(0u), 9uL to number(1u),
                10uL to CborValue.Null, 11uL to CborValue.Null, 12uL to CborValue.Null)
            val signature = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initSign(root.private); update(AuditHistoryStatusSigningInput.make(1u, body, bound, bound)); sign()
            }
            session.accept(query, body, signature)
            assertEquals(AuditSyncPhase.PAUSED, session.state.value.phase)
        }
    }
    private fun ForegroundAuditConnections.peers() = assertIs<ForegroundAuditState.Ready>(state.value).peers

    @Test fun slowCacheLoadingDoesNotBlockAnotherMacAndReconciliationKeepsItsOwner() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher); val b = Peer(2, dispatcher)
        val loading = CompletableDeferred<Unit>(); val acquisitions = mutableListOf<CborValue.Bytes>()
        val host = ForegroundAuditConnections({ listOf(a.record, b.record) }, { id ->
            acquisitions.add(id)
            if (id == a.record.enrollment.recordID) { loading.await(); a.connection } else b.connection
        })
        val run = launch { host.runForeground() }
        try {
            runCurrent(); assertEquals(0, a.exchanges); assertEquals(1, b.exchanges)
            assertIs<ForegroundAuditPeerState.Loading>(host.peers()[0].state.value)
            val healthy = host.peers()[1]; assertSame(b.connection, assertIs<ForegroundAuditPeerState.Ready>(healthy.state.value).connection)
            host.enrollmentsChanged(); runCurrent(); assertSame(healthy, host.peers()[1]); assertEquals(2, acquisitions.size)
            loading.complete(Unit); runCurrent(); assertEquals(1, a.exchanges)
            assertEquals(AuditSyncFailure.TRANSPORT, b.connection.state.value.failure)
            assertFailsWith<UnsupportedOperationException> { (host.peers() as MutableList).clear() }
        } finally { loading.complete(Unit); run.cancelAndJoin(); a.connection.closeAndJoin(); b.connection.closeAndJoin() }
    }

    @Test fun oneFailedLoadIsVisibleAndCanRetryWithoutRestartingAnotherMac() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher); val b = Peer(2, dispatcher)
        var fail = true
        val host = ForegroundAuditConnections({ listOf(a.record, b.record) }, { id ->
            if (id == a.record.enrollment.recordID) { if (fail) throw IOException("Synthetic cache failure"); a.connection } else b.connection
        })
        val run = launch { host.runForeground() }
        try {
            runCurrent(); assertIs<ForegroundAuditPeerState.Unavailable>(host.peers()[0].state.value); assertEquals(1, b.exchanges)
            fail = false; host.enrollmentsChanged(); runCurrent()
            assertIs<ForegroundAuditPeerState.Ready>(host.peers()[0].state.value); assertEquals(1, a.exchanges); assertEquals(1, b.exchanges)
        } finally { run.cancelAndJoin(); a.connection.closeAndJoin(); b.connection.closeAndJoin() }
    }

    @Test fun activityReplacementWaitsForActualStreamJoinAndRetainsTheCache() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val cleanup = CompletableDeferred<Unit>()
        val a = Peer(1, dispatcher, blockExchange = true, cleanup = cleanup); var acquisitions = 0
        val host = ForegroundAuditConnections({ listOf(a.record) }, { acquisitions++; a.connection })
        val first = launch { host.runForeground() }; runCurrent(); assertEquals(1, a.exchanges)
        first.cancel(); runCurrent(); assertTrue(a.cleanupEntered.isCompleted); assertFalse(first.isCompleted)
        val second = launch { host.runForeground() }
        try {
            runCurrent(); assertEquals(1, acquisitions); assertFalse(a.cacheClosed)
            cleanup.complete(Unit); first.join(); runCurrent()
            assertEquals(2, acquisitions); assertEquals(2, a.exchanges); assertFalse(a.cacheClosed)
        } finally { cleanup.complete(Unit); first.cancelAndJoin(); second.cancelAndJoin(); a.connection.closeAndJoin() }
        assertIs<ForegroundAuditState.Stopped>(host.state.value); assertEquals(2, a.joins); assertTrue(a.cacheClosed)
    }

    @Test fun changedIncarnationJoinsOldStreamBeforeAcquiringItsReplacement() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val cleanup = CompletableDeferred<Unit>()
        val old = Peer(1, dispatcher, blockExchange = true, cleanup = cleanup); val fresh = Peer(1, dispatcher)
        var row = old; var acquisitions = 0
        val host = ForegroundAuditConnections({ listOf(row.record) }, { acquisitions++; row.connection })
        val run = launch { host.runForeground() }
        try {
            runCurrent(); row = fresh; host.enrollmentsChanged(); runCurrent()
            assertTrue(old.cleanupEntered.isCompleted); assertEquals(1, acquisitions); assertEquals(0, fresh.exchanges)
            cleanup.complete(Unit); runCurrent(); assertEquals(2, acquisitions); assertEquals(1, fresh.exchanges)
            assertSame(fresh.connection, assertIs<ForegroundAuditPeerState.Ready>(host.peers().single().state.value).connection)
        } finally { cleanup.complete(Unit); run.cancelAndJoin(); old.connection.closeAndJoin(); fresh.connection.closeAndJoin() }
    }

    @Test fun inventoryFailureStopsStreamsButPreservesEvidenceAndAllowsRecovery() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher, blockExchange = true)
        var fail = false
        val host = ForegroundAuditConnections({ if (fail) throw IOException("Synthetic inventory failure"); listOf(a.record) }, { a.connection })
        val run = launch { host.runForeground() }
        try {
            runCurrent(); fail = true; host.enrollmentsChanged(); runCurrent()
            assertIs<ForegroundAuditState.Unavailable>(host.state.value); assertEquals(1, a.joins)
            assertFalse(a.cacheClosed); assertEquals(AuditSyncPhase.CANCELLED, a.connection.state.value.phase)
            fail = false; host.enrollmentsChanged(); runCurrent(); assertEquals(2, a.exchanges)
            assertIs<ForegroundAuditState.Ready>(host.state.value)
        } finally { run.cancelAndJoin(); a.connection.closeAndJoin() }
    }

    @Test fun foregroundRestartsNeverAutomaticallyResumeABudgetPausedRound() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher, budget = 1)
        a.pauseWithSignedHistory(); val retained = a.connection.state.value.history
        val host = ForegroundAuditConnections({ listOf(a.record) }, { a.connection })
        repeat(2) {
            val run = launch { host.runForeground() }
            try {
                runCurrent(); assertIs<ForegroundAuditPeerState.Ready>(host.peers().single().state.value)
                host.enrollmentsChanged(); runCurrent()
                assertEquals(0, a.exchanges); assertEquals(AuditSyncPhase.PAUSED, a.connection.state.value.phase)
                assertSame(retained, a.connection.state.value.history); assertFalse(a.cacheClosed)
            } finally { run.cancelAndJoin() }
        }
        a.connection.closeAndJoin()
    }

    @Test fun explicitContinuationStartsOnlyOneRoundAndBusyClicksNeverQueue() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher, budget = 1)
        a.pauseWithSignedHistory(); val retained = a.connection.state.value.history
        val host = ForegroundAuditConnections({ listOf(a.record) }, { a.connection })
        val run = launch { host.runForeground() }; runCurrent()
        val peer = host.peers().single()
        try {
            assertFalse(peer.working.value); assertTrue(peer.request(true)); assertTrue(peer.working.value)
            assertFalse(peer.request(true)); assertFalse(peer.request(false)); runCurrent()
            assertEquals(1, a.exchanges); assertEquals(AuditSyncFailure.TRANSPORT, a.connection.state.value.failure)
            assertSame(retained, a.connection.state.value.history); assertFalse(peer.working.value)
            assertTrue(peer.request(false)); assertFalse(peer.request(false)); runCurrent(); assertEquals(2, a.exchanges)
        } finally { run.cancelAndJoin(); a.connection.closeAndJoin() }
        assertFalse(peer.request(false)); assertFalse(peer.request(true))
    }

    @Test fun activeRoundRejectsExplicitWorkUntilItsStreamHasJoined() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val cleanup = CompletableDeferred<Unit>()
        val a = Peer(1, dispatcher, cleanup = cleanup)
        val host = ForegroundAuditConnections({ listOf(a.record) }, { a.connection })
        val run = launch { host.runForeground() }; runCurrent()
        try {
            val peer = host.peers().single(); assertTrue(a.cleanupEntered.isCompleted)
            assertTrue(peer.working.value); assertFalse(peer.request(false)); assertFalse(peer.request(true))
            cleanup.complete(Unit); runCurrent(); assertFalse(peer.working.value)
            assertTrue(peer.request(false)); runCurrent(); assertEquals(2, a.exchanges)
        } finally { cleanup.complete(Unit); run.cancelAndJoin(); a.connection.closeAndJoin() }
    }

    @Test fun displayProjectionsKeepRootIdentityAndRetainedEvidenceSeparateFromPresence() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher, budget = 1)
        a.pauseWithSignedHistory(); val host = ForegroundAuditConnections({ listOf(a.record) }, { a.connection })
        var display: AuditSyncDisplays = AuditSyncDisplays.Loading
        val collecting = launch { host.displays().collect { display = it } }
        val run = launch { host.runForeground() }
        try {
            runCurrent(); val entries = assertIs<AuditSyncDisplays.Ready>(display).entries
            val entry = entries.single(); val e = a.record.enrollment
            assertEquals(AuditSyncScope(e.macID, e.accountID, e.authorityPublicKey), entry.scope)
            assertNotEquals(AuditSyncScope(e.macID, e.accountID, CborValue.Bytes(key().takeLast(65).toByteArray())), entry.scope)
            val progress = assertIs<AuditSyncProgress.Observed>(entry.progress)
            assertEquals(AuditSyncPhase.PAUSED, progress.phase); assertNull(progress.completedAt)
            assertNotNull(progress.responseAt); assertSame(a.connection.state.value.history, progress.history)
            assertFalse(entry.working); assertFailsWith<UnsupportedOperationException> { (entries as MutableList).clear() }
            assertTrue(entry.request(true)); runCurrent()
            assertEquals(AuditSyncPhase.FAILED, assertIs<AuditSyncProgress.Observed>(assertIs<AuditSyncDisplays.Ready>(display).entries.single().progress).phase)
        } finally { run.cancelAndJoin(); collecting.cancelAndJoin(); a.connection.closeAndJoin() }
    }

    @Test fun wrongOwnerAndRemovalCannotStartAnotherScope() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher); val wrong = Peer(2, dispatcher)
        var rows = listOf(a.record)
        val host = ForegroundAuditConnections({ rows }, { wrong.connection }); val run = launch { host.runForeground() }
        try {
            runCurrent(); assertIs<ForegroundAuditPeerState.Unavailable>(host.peers().single().state.value)
            assertEquals(0, a.exchanges); assertEquals(0, wrong.exchanges)
            rows = emptyList(); host.enrollmentsChanged(); runCurrent(); assertTrue(host.peers().isEmpty())
        } finally { run.cancelAndJoin(); a.connection.closeAndJoin(); wrong.connection.closeAndJoin() }
    }
}
