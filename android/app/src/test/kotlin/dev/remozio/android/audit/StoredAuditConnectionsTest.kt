package dev.remozio.android.audit

import dev.remozio.android.enrollment.StoredPairingHost
import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Test
import kotlin.test.*

class StoredAuditConnectionsTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun aes() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private fun enrollment(n: Int, mac: Int = n, account: Int = 100): PhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val pair = key()
            return EnrollmentKeyReference(role, id(3 * n + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(3 * n + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) pair else pair.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(mac), id(account), id(n + 110), id(n + 120), "Same host label",
            key().takeLast(65).toByteArray(), key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION),
            local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
    }
    private class EnrollmentDisk : EnrollmentStorage {
        var bytes: ByteArray? = null
        var fail = false
        override fun read(maximumBytes: Int): ByteArray? { check(!fail); return bytes?.copyOf() }
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
        override fun close() = Unit
    }
    private class CacheDisk : AuditCiphertextStorage {
        var closed = false
        override fun read(maximumBytes: Int): ByteArray? { check(!closed); return null }
        override fun replace(ciphertext: ByteArray): Nothing = error("No network evidence in registry tests")
        override fun close() { closed = true }
    }
    private inner class Fixture {
        val parent = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val access = Mutex()
        val disk = EnrollmentDisk()
        private val cipher = EnrollmentCipher(aes(), 65536)
        val created = ConcurrentHashMap<CborValue.Bytes, PhoneAuditSyncConnection>()
        val caches = ConcurrentHashMap<CborValue.Bytes, CacheDisk>()
        val gates = ConcurrentHashMap<CborValue.Bytes, AuditEnrollmentGate>()
        val bindings = ConcurrentHashMap<CborValue.Bytes, List<AuditCacheBinding>>()
        val loads = AtomicInteger()
        init { EncryptedEnrollmentStore.create(disk, cipher, 10).close() }
        fun open() = EncryptedEnrollmentStore.open(disk, cipher, 10)
        fun activate(row: PhoneEnrollment, replacing: PhoneEnrollment? = null) = open().use {
            val prepared = it.prepare(row, it.snapshot().revision)
            it.activateSyntheticEnrollment(row.recordID.copyBytes(), prepared.revision, replacing?.recordID?.copyBytes())
        }
        fun connection(row: StoredPhoneEnrollment, retained: List<AuditCacheBinding>, current: AuditEnrollmentGate): PhoneAuditSyncConnection {
            loads.incrementAndGet(); bindings[row.enrollment.recordID] = retained; gates[row.enrollment.recordID] = current
            val cacheDisk = CacheDisk().also { caches[row.enrollment.recordID] = it }
            val bound = CborLimits(65536, 8, 2048)
            val e = row.enrollment
            val cache = EncryptedAuditCache.open(cacheDisk, AuditArchiveCipher(aes(), bound.maxBytes),
                AuditCacheBinding(e.macID.copyBytes(), e.accountID.copyBytes(), e.authorityPublicKey.copyBytes()),
                AuditPageLimits(bound, bound, bound, 8, bound, bound), AuditEvidenceLimits(100, 1_000_000, 100, 20), bound)
            return PhoneAuditSyncConnection(row, AuditSyncSession(cache, 2, 1000u) { ElapsedInstant(1, 100u) },
                { _, _, _ -> error("Registry does not start network work") }, current, { AuditRoundLimits(2, 1000) }, Dispatchers.Unconfined)
                .also { created[e.recordID] = it }
        }
        fun registry(factory: (StoredPhoneEnrollment, List<AuditCacheBinding>, AuditEnrollmentGate) -> PhoneAuditSyncConnection = ::connection,
                     close: suspend (PhoneAuditSyncConnection) -> Unit = { it.closeAndJoin() }) =
            StoredAuditConnections(parent, ::open, factory, access, closeConnection = close)
        suspend fun stop() { parent.coroutineContext.job.cancelAndJoin() }
    }

    @Test fun activeInventoryDoesNotOpenCachesOrIncludePreparedAndRemovedRows() = runBlocking<Unit> {
        val f = Fixture(); val old = enrollment(1); val active = enrollment(2, mac = 1); val prepared = enrollment(3)
        f.activate(old); f.activate(active, old)
        f.open().use { it.prepare(prepared, it.snapshot().revision) }
        val registry = f.registry()
        try {
            val rows = registry.activeRecords()
            assertEquals(listOf(active.recordID), rows.map { it.enrollment.recordID })
            assertEquals(0, f.loads.get())
            assertFailsWith<UnsupportedOperationException> { (rows as MutableList).clear() }
        } finally { registry.invalidate(); f.stop() }
    }

    @Test fun retainedReadClosesBeforeReservationWithoutBlockingInventoryOrAnotherMac() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); val b = enrollment(2); f.activate(a); f.activate(b)
        val registry = f.registry(); val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val binding = AuditCacheBinding(a.macID.copyBytes(), a.accountID.copyBytes(), a.authorityPublicKey.copyBytes())
        val reading = async { registry.readSnapshot(binding) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); null } }
        var acquiring: Deferred<PhoneAuditSyncConnection>? = null
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            acquiring = async { registry.acquire(a.recordID) }
            withTimeout(1000) { registry.acquire(b.recordID) }
            withTimeout(1000) { f.access.withLock { f.open().use { assertEquals(2, it.snapshot().entries.size) } } }
            assertNull(f.created[a.recordID]); assertFalse(acquiring.isCompleted)
            release.countDown(); assertNull(reading.await()); assertNotNull(withTimeout(2000) { acquiring.await() })
            assertEquals(2, f.loads.get())
        } finally { release.countDown(); reading.cancelAndJoin(); acquiring?.cancelAndJoin(); registry.invalidate(); f.stop() }
    }

    @Test fun openingReservationBlocksFallbackForItsRootAndTheSharedLegacyPath() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val registry = f.registry(factory = { row, retained, gate ->
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.connection(row, retained, gate)
        })
        val acquiring = async { registry.acquire(a.recordID) }; var fallbackCalls = 0
        val matching = AuditCacheBinding(a.macID.copyBytes(), a.accountID.copyBytes(), a.authorityPublicKey.copyBytes())
        val former = AuditCacheBinding(a.macID.copyBytes(), a.accountID.copyBytes(), key().takeLast(65).toByteArray())
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            for (binding in listOf(matching, former)) assertFailsWith<AuditRegistryUnavailable> {
                registry.readSnapshot(binding) { fallbackCalls++; null }
            }
            assertEquals(0, fallbackCalls)
            release.countDown(); val owner = withTimeout(2000) { acquiring.await() }
            assertSame(owner.state.value.history, registry.readSnapshot(matching) { error("Owned file must not reopen") }?.history)
            assertNull(registry.readSnapshot(former) { fallbackCalls++; null }); assertEquals(1, fallbackCalls)
        } finally { release.countDown(); acquiring.cancelAndJoin(); registry.invalidate(); f.stop() }
    }

    @Test fun ownersAreLazySharedAndSeparateForAccountsWithEqualLabels() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); val b = enrollment(2, mac = 1, account = 101)
        f.activate(a); f.activate(b); val registry = f.registry()
        try {
            assertEquals(0, f.loads.get())
            val first = registry.acquire(a.recordID); assertSame(first, registry.acquire(a.recordID))
            val second = registry.acquire(b.recordID); assertNotSame(first, second); assertEquals(2, f.loads.get())
            assertEquals(a.label, b.label); assertEquals(AuditSyncPhase.IDLE, first.state.value.phase)
            assertNotNull(registry.ownedSnapshot(AuditCacheBinding(a.macID.copyBytes(), a.accountID.copyBytes(), a.authorityPublicKey.copyBytes())))
            assertNull(registry.ownedSnapshot(AuditCacheBinding(a.macID.copyBytes(), a.accountID.copyBytes(), b.authorityPublicKey.copyBytes())))
            assertFalse(f.caches.values.any { it.closed })
        } finally { registry.invalidate(); f.stop() }
        assertTrue(f.caches.values.all { it.closed })
    }

    @Test fun cacheLoadingDoesNotHoldTheEnrollmentMutexOrBlockInventory() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val registry = f.registry(factory = { row, retained, gate ->
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.connection(row, retained, gate)
        })
        val reading = async { registry.acquire(a.recordID) }
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            withTimeout(1000) { f.access.withLock { f.open().use { assertEquals(1, it.snapshot().entries.size) } } }
            release.countDown(); assertNotNull(reading.await())
        } finally { release.countDown(); reading.cancelAndJoin(); registry.invalidate(); f.stop() }
    }

    @Test fun cancellingAScreenWaiterDoesNotDiscardApplicationOwnedCacheLoading() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val registry = f.registry(factory = { row, retained, gate ->
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.connection(row, retained, gate)
        })
        val first = async { registry.acquire(a.recordID) }
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            first.cancelAndJoin(); release.countDown()
            val owner = withTimeout(2000) { registry.acquire(a.recordID) }
            assertSame(owner, registry.acquire(a.recordID)); assertEquals(1, f.loads.get())
            assertFalse(f.caches.getValue(a.recordID).closed)
        } finally { release.countDown(); first.cancelAndJoin(); registry.invalidate(); f.stop() }
    }

    @Test fun pairingRemovalWaitsForLateCacheCreationAndJoinedRetirementBeforeCommit() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a)
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val invalidating = CompletableDeferred<Unit>()
        val registry = f.registry(factory = { row, retained, gate ->
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.connection(row, retained, gate)
        })
        val host = StoredPairingHost(f::open, f::open, f.access, { ids ->
            invalidating.complete(Unit); registry.invalidateRecordsLocked(ids)
        }, {})
        val acquiring = async { runCatching { registry.acquire(a.recordID) } }
        var removing: Deferred<EnrollmentSnapshot>? = null
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            val revision = f.open().use { it.snapshot().revision }
            removing = async { host.remove(a.recordID, revision) }
            invalidating.await(); assertFalse(removing.isCompleted)
            f.open().use { assertEquals(EnrollmentPhase.ACTIVE, it.snapshot().entries.single().phase) }
            release.countDown()
            assertEquals(EnrollmentPhase.REMOVED, withTimeout(2000) { removing.await() }.entries.single().phase)
            assertTrue(acquiring.await().isFailure); assertTrue(f.caches.getValue(a.recordID).closed)
            assertEquals(AuditSyncPhase.CLOSED, f.created.getValue(a.recordID).state.value.phase)
        } finally { release.countDown(); acquiring.cancelAndJoin(); removing?.cancelAndJoin(); registry.invalidate(); f.stop() }
    }

    @Test fun migrationBindingsComeOnlyFromEstablishedRowsInTheSameMacAccount() = runBlocking<Unit> {
        val f = Fixture(); val old = enrollment(1); val active = enrollment(2, mac = 1)
        val other = enrollment(3); val prepared = enrollment(4, mac = 1)
        f.activate(old); f.activate(active, old); f.activate(other)
        f.open().use { it.prepare(prepared, it.snapshot().revision) }
        val registry = f.registry()
        try {
            registry.acquire(active.recordID)
            val retained = f.bindings.getValue(active.recordID)
            assertEquals(setOf(old.authorityPublicKey, active.authorityPublicKey), retained.map { CborValue.Bytes(it.authorityPublicKey) }.toSet())
            assertTrue(retained.all { it.macID.contentEquals(active.macID.copyBytes()) && it.accountID.contentEquals(active.accountID.copyBytes()) })
            assertFailsWith<AuditEnrollmentUnavailable> { registry.acquire(prepared.recordID) }
            assertEquals(1, f.loads.get())
        } finally { registry.invalidate(); f.stop() }
    }

    @Test fun failedCreationCanRetryWithoutReplacingAnotherMacOwner() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); val b = enrollment(2); f.activate(a); f.activate(b)
        var fail = true
        val registry = f.registry(factory = { row, retained, gate ->
            if (row.enrollment.recordID == a.recordID && fail) throw IOException("Synthetic failure")
            f.connection(row, retained, gate)
        })
        try {
            val healthy = registry.acquire(b.recordID)
            assertFailsWith<AuditRegistryUnavailable> { registry.acquire(a.recordID) }
            fail = false; assertNotNull(registry.acquire(a.recordID)); assertSame(healthy, registry.acquire(b.recordID))
            assertEquals(2, f.loads.get())
        } finally { registry.invalidate(); f.stop() }
    }

    @Test fun finalGateUsesTheWholeCurrentArchiveAndRejectsRemovedOrReplacedRecords() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); val replacement = enrollment(2, mac = 1); f.activate(a)
        val registry = f.registry()
        try {
            val old = registry.acquire(a.recordID); var calls = 0
            val gate = f.gates.getValue(a.recordID)
            assertTrue(gate { calls++; assertTrue(it.sameConnectionAs(old.record)) })
            f.activate(replacement, a)
            assertFalse(gate { calls++ }); assertEquals(1, calls)
            val current = registry.acquire(replacement.recordID)
            assertEquals(AuditSyncPhase.CLOSED, old.state.value.phase); assertNotSame(old, current)
            assertFalse(gate { calls++ }); assertEquals(1, calls)
        } finally { registry.invalidate(); f.stop() }
    }

    @Test fun archiveFailureRetiresAllOwnersAndRecoveryReopensFreshCaches() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); val b = enrollment(2); f.activate(a); f.activate(b)
        val registry = f.registry()
        try {
            val first = registry.acquire(a.recordID); val second = registry.acquire(b.recordID)
            f.disk.fail = true
            assertFalse(f.gates.getValue(a.recordID).invoke { error("No acceptance on corrupt enrollment") })
            assertFailsWith<AuditRegistryUnavailable> { registry.acquire(a.recordID) }
            assertEquals(AuditSyncPhase.CLOSED, first.state.value.phase); assertEquals(AuditSyncPhase.CLOSED, second.state.value.phase)
            f.disk.fail = false
            assertNotSame(first, registry.acquire(a.recordID)); assertNotSame(second, registry.acquire(b.recordID))
        } finally { f.disk.fail = false; registry.invalidate(); f.stop() }
    }

    @Test fun failedClosureBlocksItsMacAccountWhileAnIndependentAccountRemainsUsable() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); val b = enrollment(2, mac = 1, account = 101)
        val replacement = enrollment(3, mac = 1); f.activate(a); f.activate(b)
        var fail = true
        val registry = f.registry(close = { owner ->
            if (owner.record.enrollment.recordID == a.recordID && fail) throw IOException("Unsettled cache")
            owner.closeAndJoin()
        })
        try {
            registry.acquire(a.recordID); val healthy = registry.acquire(b.recordID)
            f.activate(replacement, a)
            assertFailsWith<AuditRegistryUnavailable> { registry.acquire(replacement.recordID) }
            assertSame(healthy, registry.acquire(b.recordID))
            assertFalse(f.gates.getValue(a.recordID).invoke { error("Retired owner cannot accept") })
            assertFalse(f.created.containsKey(replacement.recordID))
            fail = false; assertNotNull(registry.acquire(replacement.recordID))
            assertTrue(f.caches.getValue(a.recordID).closed)
        } finally { fail = false; registry.invalidate(); f.stop() }
    }

    @Test fun anInactiveApplicationCannotAdmitNewOwnersOrUseAnExistingGate() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a); val registry = f.registry()
        try {
            registry.acquire(a.recordID); f.stop()
            assertFalse(f.gates.getValue(a.recordID).invoke { error("Application has stopped") })
            assertFailsWith<AuditRegistryUnavailable> { registry.acquire(a.recordID) }
            assertEquals(1, f.loads.get())
        } finally { registry.invalidate(); f.stop() }
        assertTrue(f.caches.getValue(a.recordID).closed)
    }

    @Test fun historyReaderUsesTheApplicationSnapshotWithoutOpeningASecondFileOwner() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a); val registry = f.registry()
        var fallbackOpens = 0
        try {
            val owner = registry.acquire(a.recordID)
            val reader = StoredAuditReader(f::open, { _, _ -> fallbackOpens++; error("Cache already owned") },
                enrollmentAccess = f.access, readSnapshot = registry::readSnapshot)
            val loaded = assertIs<CachedAuditContent.Loaded>(assertIs<StoredAuditState.Ready>(reader.read()).scopes.single().archives.single().content)
            assertSame(owner.state.value.history, loaded.snapshot)
            assertEquals(0, fallbackOpens); assertFalse(f.caches.getValue(a.recordID).closed)
            assertSame(owner, registry.acquire(a.recordID))
        } finally { registry.invalidate(); f.stop() }
    }

    @Test fun aClosedOwnerIsReopenedInsteadOfBeingReturnedForever() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a); val registry = f.registry()
        try {
            val first = registry.acquire(a.recordID); val originalDisk = f.caches.getValue(a.recordID)
            first.closeAndJoin(); assertTrue(originalDisk.closed)
            val reopened = registry.acquire(a.recordID)
            assertNotSame(first, reopened); assertEquals(AuditSyncPhase.IDLE, reopened.state.value.phase)
            assertEquals(2, f.loads.get()); assertFalse(f.caches.getValue(a.recordID).closed)
        } finally { registry.invalidate(); f.stop() }
    }

    @Test fun concurrentAcquisitionSharesTheSameApplicationReservation() = runBlocking<Unit> {
        val f = Fixture(); val a = enrollment(1); f.activate(a)
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val registry = f.registry(factory = { row, retained, gate ->
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); f.connection(row, retained, gate)
        })
        val first = async { registry.acquire(a.recordID) }
        val second = async { registry.acquire(a.recordID) }
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(5, TimeUnit.SECONDS)) }
            release.countDown(); assertSame(first.await(), second.await()); assertEquals(1, f.loads.get())
        } finally { release.countDown(); first.cancelAndJoin(); second.cancelAndJoin(); registry.invalidate(); f.stop() }
    }
}
