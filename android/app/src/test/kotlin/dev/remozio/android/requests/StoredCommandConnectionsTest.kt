package dev.remozio.android.requests

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.*
import dev.remozio.protocol.CborLimits
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import org.junit.Test
import kotlin.test.*

class StoredCommandConnectionsTest {
    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var fail = false
        override fun read(maximumBytes: Int): ByteArray? { check(!fail); return bytes?.copyOf() }
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
        override fun close() = Unit
    }
    private val storage = Storage()
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65536)
    private val bounds = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bounds, bounds, bounds, bounds)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun publicKey() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun enrollment(n: Int, scope: Int = n, account: Int = 100): PhoneEnrollment {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = publicKey()
            return EnrollmentKeyReference(role, id(3 * n + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(3 * n + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(scope), id(account), id(110 + n), id(120 + n), "Synthetic Mac",
            publicKey().takeLast(65).toByteArray(), publicKey(), key(EnrollmentKeyRole.TRANSPORT),
            key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
    }
    private fun open() = EncryptedEnrollmentStore.open(storage, cipher, 10)
    private fun activate(enrollment: PhoneEnrollment, replacement: PhoneEnrollment? = null) = open().use {
        val prepared = it.prepare(enrollment, it.snapshot().revision)
        it.activateSyntheticEnrollment(enrollment.recordID.copyBytes(), prepared.revision, replacement?.recordID?.copyBytes())
    }
    private fun connection(record: StoredPhoneEnrollment) = CommandConnection(record, limits,
        open = { _, _ -> error("No network in registry test") }, clock = { ElapsedInstant(0, 0u) }, dispatcher = Dispatchers.Unconfined)
    private fun registry(create: (StoredPhoneEnrollment) -> CommandConnection = ::connection) =
        StoredCommandConnections(::open, create, Mutex(), Dispatchers.Unconfined)
    init { EncryptedEnrollmentStore.create(storage, cipher, 10).close() }

    @Test fun bulkAcquisitionReadsOneArchiveAndKeepsEqualLabelsInSeparateScopes() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        var opens = 0; var created = 0
        val registry = StoredCommandConnections({ opens++; open() }, { created++; connection(it) }, Mutex(), Dispatchers.Unconfined)
        val first = registry.acquireActive()
        assertEquals(1, opens); assertEquals(2, created)
        assertEquals(setOf(a.recordID, b.recordID), first.map { it.recordID }.toSet())
        assertEquals(1, first.map { it.label }.toSet().size)
        assertEquals(setOf(a.macID, b.macID), first.map { it.macID }.toSet())
        assertNotSame(first[0].connection, first[1].connection)
        val again = registry.acquireActive()
        assertEquals(2, opens); assertEquals(2, created)
        first.forEach { original -> assertSame(original.connection, again.single { it.recordID == original.recordID }.connection) }
        assertEquals("StoredCommandOwner(redacted)", first.first().toString())
        registry.invalidate()
    }

    @Test fun oneFailedConstructionDoesNotHideOrRecreateAnotherMac() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        var fail = true
        val registry = registry { if (it.enrollment.recordID == a.recordID && fail) error("Synthetic create failure"); connection(it) }
        val first = registry.acquireActive()
        assertNull(first.single { it.recordID == a.recordID }.connection)
        val healthy = assertNotNull(first.single { it.recordID == b.recordID }.connection)
        fail = false
        val again = registry.acquireActive()
        assertNotNull(again.single { it.recordID == a.recordID }.connection)
        assertSame(healthy, again.single { it.recordID == b.recordID }.connection)
        registry.invalidate()
    }

    @Test fun bulkReplacementRetiresOldTrustBeforeConstructingNewAndPreservesOtherMacs() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); val replacement = enrollment(3, 1)
        activate(a); activate(b)
        var old: CommandConnection? = null
        val registry = registry { record ->
            if (record.enrollment.recordID == replacement.recordID) assertEquals(CommandConnectionState.CLOSED, old!!.connectionState.value)
            connection(record)
        }
        val first = registry.acquireActive(); old = first.single { it.recordID == a.recordID }.connection
        val other = first.single { it.recordID == b.recordID }.connection
        activate(replacement, a)
        val after = registry.acquireActive()
        assertFalse(after.any { it.recordID == a.recordID })
        assertNotNull(after.single { it.recordID == replacement.recordID }.connection)
        assertSame(other, after.single { it.recordID == b.recordID }.connection)
        registry.invalidate()
    }

    @Test fun failedRetirementBlocksOnlyItsScopeAndCannotBeBypassedByBulkRetry() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        var closes = 0
        val registry = StoredCommandConnections(::open, ::connection, Mutex(), Dispatchers.Unconfined) { owner ->
            if (owner.record.enrollment.recordID == a.recordID) { closes++; error("Synthetic close failure") }
            owner.close()
        }
        val before = registry.acquireActive()
        val healthy = before.single { it.recordID == b.recordID }.connection
        // Removing retained trust forces retirement. A failed close must never permit replacement.
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        val after = registry.acquireActive()
        assertEquals(listOf(b.recordID), after.map { it.recordID }); assertSame(healthy, after.single().connection)
        registry.acquireActive(); assertEquals(1, closes)
        assertFailsWith<CommandRegistryUnavailable> { registry.acquire(a.recordID) }
        assertFailsWith<CommandRegistryUnavailable> { registry.invalidate() }
        before.single { it.recordID == a.recordID }.connection?.close()
    }

    @Test fun bulkReadFailureInvalidatesEveryOwnerAndCannotExposeStaleRows() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val registry = registry(); val owners = registry.acquireActive()
        storage.fail = true
        assertFailsWith<CommandRegistryUnavailable> { registry.acquireActive() }
        owners.forEach { assertEquals(CommandConnectionState.CLOSED, it.connection!!.connectionState.value) }
        storage.fail = false
        val after = registry.acquireActive()
        after.forEach { fresh -> assertNotSame(owners.single { it.recordID == fresh.recordID }.connection, fresh.connection) }
        registry.invalidate()
    }

    @Test fun bulkReadNeverConstructsOwnersForPreparedOrRemovedRecords() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); val c = enrollment(3)
        activate(a); activate(b)
        open().use { it.prepare(c, it.snapshot().revision); it.remove(b.recordID.copyBytes(), it.snapshot().revision) }
        val registry = registry(); val active = registry.acquireActive()
        assertEquals(listOf(a.recordID), active.map { it.recordID }); assertNotNull(active.single().connection)
        registry.invalidate()
    }

    @Test fun cancelledBulkConstructionStopsBeforeAnotherScopeAndRetainsOnlyItsValidOwner() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        var creates = 0; var cancelFirst = true
        lateinit var first: Deferred<List<StoredCommandOwner>>
        val registry = registry { record ->
            creates++
            if (cancelFirst) { cancelFirst = false; first.cancel() }
            connection(record)
        }
        first = async(start = CoroutineStart.LAZY) { registry.acquireActive() }
        first.start()
        assertFailsWith<CancellationException> { first.await() }; assertEquals(1, creates)
        val after = registry.acquireActive()
        assertEquals(2, after.size); assertEquals(2, creates)
        assertTrue(after.all { it.connection?.connectionState?.value == CommandConnectionState.DISCONNECTED })
        registry.invalidate()
    }

    @Test fun aNewRecordCannotBypassFailedRetirementForTheSameMacAccount() = runBlocking<Unit> {
        val a = enrollment(1); val otherAccount = enrollment(2, scope = 1, account = 101)
        val replacement = enrollment(3, scope = 1)
        activate(a); activate(otherAccount)
        var creates = 0
        val registry = StoredCommandConnections(::open, { creates++; connection(it) }, Mutex(), Dispatchers.Unconfined) { owner ->
            if (owner.record.enrollment.recordID == a.recordID) error("Synthetic close failure")
            owner.close()
        }
        val before = registry.acquireActive()
        val old = before.single { it.recordID == a.recordID }.connection!!
        val healthy = before.single { it.recordID == otherAccount.recordID }.connection
        try {
            activate(replacement, a)
            repeat(2) {
                val after = registry.acquireActive()
                assertNull(after.single { it.recordID == replacement.recordID }.connection)
                assertSame(healthy, after.single { it.recordID == otherAccount.recordID }.connection)
                assertFailsWith<CommandRegistryUnavailable> { registry.acquire(replacement.recordID) }
            }
            assertEquals(2, creates)
        } finally {
            old.close(); runCatching { registry.invalidate() }
        }
    }

    @Test fun repeatedAndConcurrentAcquisitionsShareOneOwnerPerMac() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        var created = 0
        val registry = registry { created++; connection(it) }
        val owners = List(20) { async { registry.acquire(a.recordID) } }.awaitAll()
        owners.forEach { assertSame(owners.first(), it) }
        val other = registry.acquire(b.recordID)
        assertNotSame(owners.first(), other); assertEquals(2, created)
        registry.invalidate()
        assertEquals(CommandConnectionState.CLOSED, owners.first().connectionState.value)
        assertEquals(CommandConnectionState.CLOSED, other.connectionState.value)
    }

    @Test fun replacementClosesOldOwnerBeforeOpeningNewWithoutClosingAnotherMac() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); val replacement = enrollment(3, 1)
        activate(a); activate(b)
        var old: CommandConnection? = null
        val registry = registry {
            if (it.enrollment.recordID == replacement.recordID) assertEquals(CommandConnectionState.CLOSED, old!!.connectionState.value)
            connection(it)
        }
        old = registry.acquire(a.recordID)
        val other = registry.acquire(b.recordID)
        activate(replacement, a)
        val fresh = registry.acquire(replacement.recordID)
        assertNotSame(old, fresh); assertSame(other, registry.acquire(b.recordID))
        assertFailsWith<CommandEnrollmentUnavailable> { registry.acquire(a.recordID) }
        registry.invalidate()
    }

    @Test fun setupInvalidatesOnlySelectedRecordsUnderTheSharedLock() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val mutex = Mutex()
        val registry = StoredCommandConnections(::open, ::connection, mutex, Dispatchers.Unconfined)
        val first = registry.acquire(a.recordID); val other = registry.acquire(b.recordID)
        mutex.lock()
        try { registry.invalidateRecordsLocked(setOf(a.recordID)) } finally { mutex.unlock() }
        assertEquals(CommandConnectionState.CLOSED, first.connectionState.value)
        assertSame(other, registry.acquire(b.recordID))
        assertNotSame(first, registry.acquire(a.recordID))
        registry.invalidate()
    }

    @Test fun failedCloseCannotBeBypassedByRetryOrAcquisition() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val mutex = Mutex()
        var attempts = 0
        val registry = StoredCommandConnections(::open, ::connection, mutex, Dispatchers.Unconfined) { owner ->
            if (owner.record.enrollment.recordID == a.recordID) { attempts++; error("Synthetic close failure") }
            owner.close()
        }
        registry.acquire(a.recordID)
        val other = registry.acquire(b.recordID)
        repeat(2) {
            mutex.lock()
            try { assertFailsWith<CommandRegistryUnavailable> { registry.invalidateRecordsLocked(setOf(a.recordID)) } }
            finally { mutex.unlock() }
        }
        assertEquals(1, attempts)
        assertFailsWith<CommandRegistryUnavailable> { registry.acquire(a.recordID) }
        assertSame(other, registry.acquire(b.recordID))
        assertFailsWith<CommandRegistryUnavailable> { registry.invalidate() }
        assertEquals(CommandConnectionState.CLOSED, other.connectionState.value)
    }

    @Test fun unreadableArchiveInvalidatesEveryOwnerAndRecoveryCreatesFreshOnes() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val registry = registry(); val first = registry.acquire(a.recordID); val second = registry.acquire(b.recordID)
        storage.fail = true
        assertFailsWith<CommandRegistryUnavailable> { registry.acquire(a.recordID) }
        assertEquals(CommandConnectionState.CLOSED, first.connectionState.value)
        assertEquals(CommandConnectionState.CLOSED, second.connectionState.value)
        storage.fail = false
        assertNotSame(first, registry.acquire(a.recordID)); registry.invalidate()
    }

    @Test fun preparedRemovedAndFailedConstructionNeverPublishAnOwner() = runBlocking {
        val a = enrollment(1)
        open().use { it.prepare(a, it.snapshot().revision) }
        var attempts = 0
        val registry = registry { attempts++; if (attempts == 1) error("Synthetic storage failure"); connection(it) }
        assertFailsWith<CommandEnrollmentUnavailable> { registry.acquire(a.recordID) }; assertEquals(0, attempts)
        open().use { it.activateSyntheticEnrollment(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<CommandRegistryUnavailable> { registry.acquire(a.recordID) }
        val owner = registry.acquire(a.recordID); assertEquals(2, attempts)
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<CommandEnrollmentUnavailable> { registry.acquire(a.recordID) }
        assertEquals(CommandConnectionState.CLOSED, owner.connectionState.value)
    }
}
