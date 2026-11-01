package dev.remozio.android.updates

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PhoneUpdateProgressObservation
import dev.remozio.protocol.CborValue
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class StoredMacUpdateProgressConnectionsTest {
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
        MacUpdateProgressConnection(record, open = { _, _ -> error("No network in registry test") }, currentEnrollment = current,
            freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
    private fun registry(create: (StoredPhoneEnrollment, suspend () -> StoredPhoneEnrollment) -> MacUpdateProgressConnection = ::connection) =
        StoredMacUpdateProgressConnections(::open, create, Mutex(), Dispatchers.Unconfined)
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
        val registry = registry(); assertFailsWith<MacUpdateProgressEnrollmentUnavailable> { registry.acquire(pending.recordID) }
        val old = registry.acquire(a.recordID)
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<MacUpdateProgressEnrollmentUnavailable> { registry.acquire(a.recordID) }
        assertEquals(MacUpdateProgressAvailability.CLOSED, old.snapshot().availability)
        val empty = StoredMacUpdateProgressConnections({ null }, { _, _ -> error("Missing archive created an owner") }, Mutex(), Dispatchers.Unconfined)
        assertFailsWith<MacUpdateProgressEnrollmentUnavailable> { empty.acquire(a.recordID) }
    }

    @Test fun replacementClosesTheEarlierOwnerBeforeConstructingItsSuccessor() = runTest {
        val a = enrollment(1); val b = enrollment(2); val replacement = enrollment(3, mac = 1); activate(a); activate(b)
        lateinit var old: MacUpdateProgressConnection
        val registry = registry { record, current ->
            if (record.enrollment.recordID == replacement.recordID)
                assertEquals(MacUpdateProgressAvailability.CLOSED, old.snapshot().availability)
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
        storage.fail = true; assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.acquire(a.recordID) }
        assertEquals(MacUpdateProgressAvailability.CLOSED, first.snapshot().availability)
        assertEquals(MacUpdateProgressAvailability.CLOSED, second.snapshot().availability)
        storage.fail = false
        assertNotSame(first, registry.acquire(a.recordID)); assertNotSame(second, registry.acquire(b.recordID)); registry.invalidate()
    }

    @Test fun failedRetirementBlocksThatMacAccountButNotAnotherAccount() = runTest {
        val a = enrollment(1); val b = enrollment(2, mac = 1, account = 101); val replacement = enrollment(3, mac = 1)
        activate(a); activate(b)
        val registry = StoredMacUpdateProgressConnections(::open, ::connection, Mutex(), Dispatchers.Unconfined, closeConnection = {
            if (it.record.enrollment.recordID == a.recordID) error("Unsettled cleanup")
            it.close()
        })
        val old = registry.acquire(a.recordID); val independent = registry.acquire(b.recordID); activate(replacement, a)
        assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.acquire(replacement.recordID) }
        assertSame(independent, registry.acquire(b.recordID))
        assertEquals(MacUpdateProgressAvailability.UNKNOWN, independent.snapshot().availability)
        assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.invalidate() }
        assertEquals(MacUpdateProgressAvailability.CLOSED, independent.snapshot().availability); old.close()
    }

    @Test fun networkWorkReleasesTheArchiveMutexAndRevocationCancelsTheActiveOwner() = runTest {
        val a = enrollment(1); activate(a); val access = Mutex(); val entered = CompletableDeferred<Unit>()
        lateinit var current: suspend () -> StoredPhoneEnrollment
        var closes = 0
        val registry = StoredMacUpdateProgressConnections(::open, { record, read ->
            current = read
            MacUpdateProgressConnection(record, open = { _, _ ->
                object : MacUpdateProgressWire {
                    override suspend fun read(): PhoneUpdateProgressObservation {
                        assertTrue(access.tryLock()); access.unlock(); entered.complete(Unit); awaitCancellation()
                    }
                    override fun close() { closes++ }
                    override suspend fun closeAndJoin() { close() }
                }
            }, currentEnrollment = read, freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
        }, access, Dispatchers.Unconfined)
        val owner = registry.acquire(a.recordID); val refresh = async { owner.refresh() }; entered.await()
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<MacUpdateProgressEnrollmentUnavailable> { current() }
        refresh.join(); assertTrue(refresh.isCancelled); assertTrue(closes >= 1)
        assertEquals(MacUpdateProgressAvailability.CLOSED, owner.snapshot().availability); assertNull(owner.snapshot().observation)
    }

    @Test fun cancellationDuringConstructionClosesTheUnpublishedOwner() = runTest {
        val a = enrollment(1); activate(a)
        lateinit var acquiring: Deferred<MacUpdateProgressConnection>
        lateinit var cancelled: MacUpdateProgressConnection
        var cancel = true
        val registry = registry { record, current ->
            connection(record, current).also { if (cancel) { cancelled = it; acquiring.cancel() } }
        }
        acquiring = async(start = CoroutineStart.LAZY) { registry.acquire(a.recordID) }
        acquiring.start(); assertFailsWith<CancellationException> { acquiring.await() }
        assertEquals(MacUpdateProgressAvailability.CLOSED, cancelled.snapshot().availability)
        cancel = false; assertNotSame(cancelled, registry.acquire(a.recordID)); registry.invalidate()
    }

    @Test fun setupRetirementAndArchiveCommitShareOneMutexBoundary() = runTest {
        val a = enrollment(1); activate(a); val access = Mutex()
        val registry = StoredMacUpdateProgressConnections(::open, ::connection, access, Dispatchers.Unconfined)
        val old = registry.acquire(a.recordID)
        access.lock()
        try {
            registry.invalidateRecordsLocked(setOf(a.recordID))
            assertEquals(MacUpdateProgressAvailability.CLOSED, old.snapshot().availability)
            val waiting = async(start = CoroutineStart.UNDISPATCHED) {
                assertFailsWith<MacUpdateProgressEnrollmentUnavailable> { registry.acquire(a.recordID) }
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
        assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.acquire(a.recordID) }
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
            } else MacUpdateProgressConnection(record, open = { _, _ ->
                object : MacUpdateProgressWire {
                    override suspend fun read(): PhoneUpdateProgressObservation { entered.complete(Unit); awaitCancellation() }
                    override fun close() = Unit
                    override suspend fun closeAndJoin() {
                        withContext(NonCancellable) {
                            cleaning.complete(Unit); release.await()
                            if (failCleanup) error("Late transport cleanup failure")
                        }
                    }
                }
            }, currentEnrollment = current, freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
        }
        val old = registry.acquire(a.recordID); val independent = registry.acquire(b.recordID)
        val operation = async { old.refresh() }
        try {
            entered.await(); activate(replacement, a)
            assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.acquire(replacement.recordID) }
            cleaning.await()
            assertFalse(operation.isCompleted); assertFalse(old.retirementSettled()); assertEquals(0, replacements)
            assertSame(independent, registry.acquire(b.recordID))
            assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.acquire(replacement.recordID) }
            release.complete(Unit); operation.join(); assertTrue(operation.isCancelled)
            if (failCleanup) {
                assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.acquire(replacement.recordID) }
                assertEquals(0, replacements); assertFailsWith<MacUpdateProgressRegistryUnavailable> { registry.invalidate() }
            } else {
                assertNotSame(old, registry.acquire(replacement.recordID)); assertEquals(1, replacements); registry.invalidate()
            }
        } finally { release.complete(Unit); operation.cancelAndJoin() }
    }
}
