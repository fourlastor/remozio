package dev.sebastiano.remozio.android.routing

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PhoneRoutingChallenge
import dev.remozio.phone.transport.PhoneRoutingResult
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import org.junit.Test
import kotlin.test.*

class StoredRoutingConnectionsTest {
    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null; var fail = false
        override fun read(maximumBytes: Int): ByteArray? { check(!fail); return bytes?.copyOf() }
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
        override fun close() = Unit
    }
    private val storage = Storage()
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65536)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun enrollment(n: Int, scope: Int = n, account: Int = 100): PhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val pair = key()
            return EnrollmentKeyReference(role, id(3 * n + role.ordinal), "remozio.${role.aliasPart}.v1.${"%032x".format(3 * n + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) pair else pair.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(scope), id(account), id(110 + n), id(120 + n), "Same host label",
            key().takeLast(65).toByteArray(), key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION),
            local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
    }
    private fun open() = EncryptedEnrollmentStore.open(storage, cipher, 10)
    private fun activate(row: PhoneEnrollment, replacement: PhoneEnrollment? = null) = open().use {
        val prepared = it.prepare(row, it.snapshot().revision)
        it.activateSyntheticEnrollment(row.recordID.copyBytes(), prepared.revision, replacement?.recordID?.copyBytes())
    }
    private fun connection(record: StoredPhoneEnrollment, current: suspend () -> Boolean) = MacRoutingConnection(record,
        open = { _, _ -> error("No network in registry test") }, loadSigner = { error("No signer in registry test") },
        current = current, freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined)
    private fun registry(create: (StoredPhoneEnrollment, suspend () -> Boolean) -> MacRoutingConnection = ::connection) =
        StoredRoutingConnections(::open, create, Mutex(), Dispatchers.Unconfined)
    init { EncryptedEnrollmentStore.create(storage, cipher, 10).close() }

    @Test fun oneArchiveSnapshotKeepsEqualLabelsAndIndependentAccountsDistinct() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2, scope = 1, account = 101); activate(a); activate(b)
        var reads = 0; var creates = 0
        val registry = StoredRoutingConnections({ reads++; open() }, { row, current -> creates++; connection(row, current) }, Mutex(), Dispatchers.Unconfined)
        val first = registry.acquireActive(); assertEquals(1, reads); assertEquals(2, creates)
        assertEquals(setOf(a.recordID, b.recordID), first.map { it.recordID }.toSet()); assertEquals(1, first.map { it.label }.toSet().size)
        val again = registry.acquireActive(); assertEquals(2, reads); assertEquals(2, creates)
        first.forEach { assertSame(it.connection, again.single { row -> row.recordID == it.recordID }.connection) }
        assertSame(first.first().connection, registry.acquire(a.recordID)); registry.invalidate()
    }
    @Test fun constructorFailureIsIsolatedAndCanRetryWithoutReplacingHealthyOwners() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b); var fail = true
        val registry = registry { row, current -> if (row.enrollment.recordID == a.recordID && fail) error("fixture"); connection(row, current) }
        val before = registry.acquireActive(); assertNull(before.single { it.recordID == a.recordID }.connection)
        val healthy = before.single { it.recordID == b.recordID }.connection
        fail = false; val after = registry.acquireActive(); assertNotNull(after.single { it.recordID == a.recordID }.connection)
        assertSame(healthy, after.single { it.recordID == b.recordID }.connection); registry.invalidate()
    }
    @Test fun replacementRetiresOnlyTheAffectedScopeBeforeCreatingANewOwner() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2); val replacement = enrollment(3, scope = 1); activate(a); activate(b)
        lateinit var old: MacRoutingConnection
        val registry = registry { row, current ->
            if (row.enrollment.recordID == replacement.recordID) assertEquals(MacRoutingAvailability.CLOSED, old.snapshot().availability)
            connection(row, current)
        }
        val before = registry.acquireActive(); old = before.single { it.recordID == a.recordID }.connection!!
        activate(replacement, a); val after = registry.acquireActive()
        assertNotSame(old, after.single { it.recordID == replacement.recordID }.connection)
        assertSame(before.single { it.recordID == b.recordID }.connection, after.single { it.recordID == b.recordID }.connection)
        registry.invalidate()
    }
    @Test fun archiveFailureRetiresEveryOwnerAndRecoveryCreatesFreshOnes() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val registry = registry(); val before = registry.acquireActive()
        storage.fail = true; assertFailsWith<RoutingRegistryUnavailable> { registry.acquireActive() }
        before.forEach { assertEquals(MacRoutingAvailability.CLOSED, it.connection!!.snapshot().availability) }
        storage.fail = false; val after = registry.acquireActive()
        before.forEach { row -> assertNotSame(row.connection, after.single { it.recordID == row.recordID }.connection) }; registry.invalidate()
    }
    @Test fun failedRetirementCannotBeBypassedByANewRecordInTheSameMacAccount() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2, scope = 1, account = 101); val replacement = enrollment(3, scope = 1)
        activate(a); activate(b); var rejected = false
        val registry = StoredRoutingConnections(::open, ::connection, Mutex(), Dispatchers.Unconfined, closeConnection = {
            if (it.record.enrollment.recordID == a.recordID) { rejected = true; error("unsettled cleanup") }; it.close()
        })
        val before = registry.acquireActive(); activate(replacement, a); val after = registry.acquireActive()
        assertTrue(rejected); assertNull(after.single { it.recordID == replacement.recordID }.connection)
        assertSame(before.single { it.recordID == b.recordID }.connection, after.single { it.recordID == b.recordID }.connection)
        assertFailsWith<RoutingRegistryUnavailable> { registry.acquire(replacement.recordID) }
        assertFailsWith<RoutingRegistryUnavailable> { registry.invalidate() }; before.first().connection?.close()
    }
    @Test fun preparedRemovedAndScopedInvalidationNeverRetireAnotherActiveAccount() = runBlocking<Unit> {
        val a = enrollment(1); val b = enrollment(2); val c = enrollment(3); activate(a); activate(b)
        open().use { it.prepare(c, it.snapshot().revision) }
        val registry = registry(); val before = registry.acquireActive(); assertEquals(2, before.size)
        registry.invalidateRecordsLocked(setOf(a.recordID))
        assertEquals(MacRoutingAvailability.CLOSED, before.single { it.recordID == a.recordID }.connection!!.snapshot().availability)
        assertEquals(MacRoutingAvailability.UNKNOWN, before.single { it.recordID == b.recordID }.connection!!.snapshot().availability)
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertEquals(listOf(b.recordID), registry.acquireActive().map { it.recordID }); registry.invalidate()
    }
    @Test fun operationRechecksStorageAndCannotPublishAfterLocalRemoval() = runBlocking<Unit> {
        val a = enrollment(1); activate(a); var queries = 0
        val registry = registry { row, current -> MacRoutingConnection(row, open = { _, _ ->
            object : RoutingWire {
                override suspend fun status(): PhoneRoutingResult {
                    queries++; open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
                    return PhoneRoutingResult.Failure(PhoneRoutingFailure.UNAVAILABLE)
                }
                override suspend fun challenge(expectedRevision: ULong): PhoneRoutingResult = error("No mutation")
                override suspend fun apply(challenge: PhoneRoutingChallenge, signature: ByteArray): PhoneRoutingResult = error("No mutation")
                override fun close() = Unit
                override suspend fun closeAndJoin() = Unit
            }
        }, loadSigner = { error("No signer") }, current = current, freshnessMillis = { 1000 }, timeoutMillis = { 1000 }, dispatcher = Dispatchers.Unconfined) }
        val owner = registry.acquire(a.recordID)
        assertFailsWith<CancellationException> { owner.refresh() }; assertEquals(1, queries)
        assertEquals(MacRoutingAvailability.CLOSED, owner.snapshot().availability); assertNull(owner.snapshot().observation)
        assertTrue(registry.acquireActive().isEmpty())
    }
}
