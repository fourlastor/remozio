package dev.remozio.android.updates

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PhoneUpdateSchedulingStatus
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.protocol.CborValue
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class StoredMacUpdateSchedulingConnectionsTest {
    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var fail = false
        override fun read(maximumBytes: Int): ByteArray? { check(!fail); return bytes?.copyOf() }
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
        override fun close() = Unit
    }
    private val storage = Storage()
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65536)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun enrollment(n: Int, mac: Int = n, account: Int = 100): PhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val bytes = key()
            return EnrollmentKeyReference(role, id(3 * n + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(3 * n + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) bytes else bytes.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(mac), id(account), id(110 + n), id(120 + n), "Same host label",
            key().takeLast(65).toByteArray(), key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION),
            local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
    }
    private fun open() = EncryptedEnrollmentStore.open(storage, cipher, 10)
    private fun activate(row: PhoneEnrollment, replacement: PhoneEnrollment? = null) = open().use {
        val prepared = it.prepare(row, it.snapshot().revision)
        it.activateSyntheticEnrollment(row.recordID.copyBytes(), prepared.revision, replacement?.recordID?.copyBytes())
    }
    private fun connection(record: StoredPhoneEnrollment, current: suspend () -> StoredPhoneEnrollment) =
        MacUpdateSchedulingConnection(record, open = { _, _ -> error("No network in registry test") },
            loadSigner = { error("No decision key in registry test") }, currentEnrollment = current,
            elapsedRealtimeNanos = { 1_000_000L }, freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
    private fun registry(create: (StoredPhoneEnrollment, suspend () -> StoredPhoneEnrollment) -> MacUpdateSchedulingConnection = ::connection) =
        StoredMacUpdateSchedulingConnections(::open, create, Mutex(), Dispatchers.Unconfined)
    init { EncryptedEnrollmentStore.create(storage, cipher, 10).close() }

    @Test fun equalLabelsKeepSeparateMacAccountsAndReuseOnlyTheirOwnIncarnation() = runTest {
        val a = enrollment(1); val b = enrollment(2, mac = 1, account = 101); activate(a); activate(b)
        var creates = 0
        val registry = registry { record, current -> creates++; connection(record, current) }
        val first = registry.acquire(a.recordID); val second = registry.acquire(b.recordID)
        assertNotSame(first, second); assertEquals(first.record.enrollment.label, second.record.enrollment.label)
        assertSame(first, registry.acquire(a.recordID)); assertSame(second, registry.acquire(b.recordID)); assertEquals(2, creates)
        registry.invalidate()
    }

    @Test fun preparedRemovedAndMissingArchivesCannotCreateAnOwner() = runTest {
        val a = enrollment(1); val pending = enrollment(2); activate(a)
        open().use { it.prepare(pending, it.snapshot().revision) }
        val registry = registry(); assertFailsWith<MacUpdateSchedulingEnrollmentUnavailable> { registry.acquire(pending.recordID) }
        val old = registry.acquire(a.recordID)
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<MacUpdateSchedulingEnrollmentUnavailable> { registry.acquire(a.recordID) }
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, old.snapshot().availability)
        val empty = StoredMacUpdateSchedulingConnections({ null }, { _, _ -> error("Missing archive created an owner") }, Mutex(), Dispatchers.Unconfined)
        assertFailsWith<MacUpdateSchedulingEnrollmentUnavailable> { empty.acquire(a.recordID) }
    }

    @Test fun replacementClosesTheEarlierOwnerBeforeConstructingItsSuccessor() = runTest {
        val a = enrollment(1); val b = enrollment(2); val replacement = enrollment(3, mac = 1); activate(a); activate(b)
        lateinit var old: MacUpdateSchedulingConnection
        val registry = registry { record, current ->
            if (record.enrollment.recordID == replacement.recordID)
                assertEquals(MacUpdateSchedulingAvailability.CLOSED, old.snapshot().availability)
            connection(record, current)
        }
        old = registry.acquire(a.recordID); val independent = registry.acquire(b.recordID)
        activate(replacement, a)
        assertNotSame(old, registry.acquire(replacement.recordID)); assertSame(independent, registry.acquire(b.recordID))
        registry.invalidate()
    }

    @Test fun archiveFailureRetiresAllOwnersAndRecoveryCreatesFreshOwners() = runTest {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val registry = registry(); val first = registry.acquire(a.recordID); val second = registry.acquire(b.recordID)
        storage.fail = true; assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.acquire(a.recordID) }
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, first.snapshot().availability)
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, second.snapshot().availability)
        storage.fail = false
        assertNotSame(first, registry.acquire(a.recordID)); assertNotSame(second, registry.acquire(b.recordID)); registry.invalidate()
    }

    @Test fun failedRetirementBlocksThatMacAccountButNotAnotherAccount() = runTest {
        val a = enrollment(1); val b = enrollment(2, mac = 1, account = 101); val replacement = enrollment(3, mac = 1)
        activate(a); activate(b)
        val registry = StoredMacUpdateSchedulingConnections(::open, ::connection, Mutex(), Dispatchers.Unconfined, closeConnection = {
            if (it.record.enrollment.recordID == a.recordID) error("Unsettled cleanup")
            it.close()
        })
        val old = registry.acquire(a.recordID); val independent = registry.acquire(b.recordID); activate(replacement, a)
        assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.acquire(replacement.recordID) }
        assertSame(independent, registry.acquire(b.recordID))
        assertEquals(MacUpdateSchedulingAvailability.UNKNOWN, independent.snapshot().availability)
        assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.invalidate() }
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, independent.snapshot().availability); old.close()
    }

    @Test fun networkWorkReleasesTheArchiveMutexAndRevocationCancelsTheActiveOwner() = runTest {
        val a = enrollment(1); activate(a); val access = Mutex(); val entered = CompletableDeferred<Unit>()
        lateinit var current: suspend () -> StoredPhoneEnrollment
        var closes = 0
        val registry = StoredMacUpdateSchedulingConnections(::open, { record, read ->
            current = read
            MacUpdateSchedulingConnection(record, open = { _, _ ->
                object : MacUpdateSchedulingWire {
                    override suspend fun status(): PhoneUpdateSchedulingStatus {
                        assertTrue(access.tryLock()); access.unlock(); entered.complete(Unit); awaitCancellation()
                    }
                    override suspend fun challenge(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallenge = error("No mutation")
                    override suspend fun apply(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingStatus = error("No mutation")
                    override fun close() { closes++ }
                    override suspend fun closeAndJoin() { close() }
                }
            }, loadSigner = { error("No signer") }, currentEnrollment = read, elapsedRealtimeNanos = { 1_000_000L },
                freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
        }, access, Dispatchers.Unconfined)
        val owner = registry.acquire(a.recordID); val refresh = async { owner.refresh() }; entered.await()
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<MacUpdateSchedulingEnrollmentUnavailable> { current() }
        refresh.join(); assertTrue(refresh.isCancelled); assertTrue(closes >= 1)
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, owner.snapshot().availability); assertNull(owner.snapshot().observation)
    }

    @Test fun cancellationDuringConstructionClosesTheUnpublishedOwner() = runTest {
        val a = enrollment(1); activate(a)
        lateinit var acquiring: Deferred<MacUpdateSchedulingConnection>
        lateinit var cancelled: MacUpdateSchedulingConnection
        var cancel = true
        val registry = registry { record, current ->
            connection(record, current).also { if (cancel) { cancelled = it; acquiring.cancel() } }
        }
        acquiring = async(start = CoroutineStart.LAZY) { registry.acquire(a.recordID) }
        acquiring.start(); assertFailsWith<CancellationException> { acquiring.await() }
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, cancelled.snapshot().availability)
        cancel = false; assertNotSame(cancelled, registry.acquire(a.recordID)); registry.invalidate()
    }

    @Test fun setupRetirementAndArchiveCommitShareOneMutexBoundary() = runTest {
        val a = enrollment(1); activate(a); val access = Mutex()
        val registry = StoredMacUpdateSchedulingConnections(::open, ::connection, access, Dispatchers.Unconfined)
        val old = registry.acquire(a.recordID)
        access.lock()
        try {
            registry.invalidateRecordsLocked(setOf(a.recordID))
            assertEquals(MacUpdateSchedulingAvailability.CLOSED, old.snapshot().availability)
            val waiting = async(start = CoroutineStart.UNDISPATCHED) {
                assertFailsWith<MacUpdateSchedulingEnrollmentUnavailable> { registry.acquire(a.recordID) }
            }
            assertFalse(waiting.isCompleted)
            open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
            access.unlock(); waiting.await()
        } finally { if (access.isLocked) access.unlock() }
    }

    @Test fun constructorFailureKeepsHealthyOwnersAndCanRetryTheFailedScope() = runTest {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b); var fail = true
        val registry = registry { record, current ->
            if (record.enrollment.recordID == a.recordID && fail) error("Synthetic construction failure")
            connection(record, current)
        }
        val independent = registry.acquire(b.recordID)
        assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.acquire(a.recordID) }
        fail = false; assertNotNull(registry.acquire(a.recordID)); assertSame(independent, registry.acquire(b.recordID)); registry.invalidate()
    }

    @Test fun replacementWaitsForNonCancellableTransportCleanup() = runTest {
        verifyRetirementBoundary(failCleanup = false)
    }

    @Test fun aLateCleanupFailureCannotReleaseAReplacementOwner() = runTest {
        verifyRetirementBoundary(failCleanup = true)
    }

    private suspend fun verifyRetirementBoundary(failCleanup: Boolean) = coroutineScope {
        val a = enrollment(1); val b = enrollment(2, mac = 1, account = 101); val replacement = enrollment(3, mac = 1)
        activate(a); activate(b)
        val entered = CompletableDeferred<Unit>(); val cleaning = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        var replacements = 0
        val registry = registry { record, current ->
            if (record.enrollment.recordID != a.recordID) {
                if (record.enrollment.recordID == replacement.recordID) replacements++
                connection(record, current)
            } else MacUpdateSchedulingConnection(record, open = { _, _ ->
                object : MacUpdateSchedulingWire {
                    override suspend fun status(): PhoneUpdateSchedulingStatus { entered.complete(Unit); awaitCancellation() }
                    override suspend fun challenge(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallenge = error("No mutation")
                    override suspend fun apply(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingStatus = error("No mutation")
                    override fun close() = Unit
                    override suspend fun closeAndJoin() {
                        withContext(NonCancellable) {
                            cleaning.complete(Unit); release.await()
                            if (failCleanup) error("Late transport cleanup failure")
                        }
                    }
                }
            }, loadSigner = { error("No signer") }, currentEnrollment = current, elapsedRealtimeNanos = { 1_000_000L },
                freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
        }
        val old = registry.acquire(a.recordID); val independent = registry.acquire(b.recordID)
        val operation = async { old.refresh() }
        try {
            entered.await(); activate(replacement, a)
            assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.acquire(replacement.recordID) }
            cleaning.await()
            assertFalse(operation.isCompleted); assertFalse(old.retirementSettled()); assertEquals(0, replacements)
            assertSame(independent, registry.acquire(b.recordID))
            assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.acquire(replacement.recordID) }
            release.complete(Unit); operation.join(); assertTrue(operation.isCancelled)
            if (failCleanup) {
                assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.acquire(replacement.recordID) }
                assertEquals(0, replacements); assertFailsWith<MacUpdateSchedulingRegistryUnavailable> { registry.invalidate() }
            } else {
                assertNotSame(old, registry.acquire(replacement.recordID)); assertEquals(1, replacements); registry.invalidate()
            }
        } finally { release.complete(Unit); operation.cancelAndJoin() }
    }
}
