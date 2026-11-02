package dev.sebastiano.remozio.android.enrollment

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.RelayAccessCredential
import dev.remozio.phone.transport.RelayEndpoint
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import org.junit.Test
import kotlin.test.*

class StoredMacInventoryTest {
    @Test fun inventoryOpeningCannotInitializeOrRepairStorage() {
        assertEquals(EnrollmentOpenMode.EMPTY, enrollmentOpenMode(false, false, false))
        assertEquals(EnrollmentOpenMode.CREATE, enrollmentOpenMode(false, false, true))
        for (create in listOf(false, true)) {
            assertEquals(EnrollmentOpenMode.OPEN, enrollmentOpenMode(true, true, create))
            assertFailsWith<EnrollmentStoreUnavailable> { enrollmentOpenMode(true, false, create) }
            assertFailsWith<EnrollmentStoreUnavailable> { enrollmentOpenMode(false, true, create) }
        }
    }

    @Test fun projectionKeepsMacsDistinctAndSeparatesIncompleteSetupFromRemovedRecords() = runBlocking {
        val storage = Storage()
        val store = create(storage)
        val first = record(1); val second = record(2); val removed = record(3)
        store.prepare(first, 0u); store.activateSyntheticEnrollment(first.recordID.copyBytes(), 1u)
        store.prepare(second, 2u)
        store.prepare(removed, 3u); store.remove(removed.recordID.copyBytes(), 4u)
        val before = storage.writes
        val result = assertIs<MacInventoryState.Ready>(StoredMacReader({ store }).read())
        assertEquals(listOf(first.recordID, second.recordID), result.macs.map { it.recordID })
        assertEquals(listOf("Same display name", "Same display name"), result.macs.map { it.label })
        assertEquals(listOf(false, true), result.macs.map { it.setupIncomplete })
        assertEquals(before, storage.writes)
        assertEquals(1, storage.closes)
        assertFailsWith<EnrollmentStoreUnavailable> { store.snapshot() }
        assertFailsWith<UnsupportedOperationException> { (result.macs as MutableList).clear() }
        assertFalse(result.toString().contains("Same display name"))
        assertFalse(result.macs.toString().contains("Same display name"))
    }

    @Test fun emptyUnavailableAndRetryAreDifferentWithoutExposingErrors() = runBlocking {
        assertTrue(assertIs<MacInventoryState.Ready>(StoredMacReader({ null }).read()).macs.isEmpty())
        val attempts = AtomicInteger()
        val reader = StoredMacReader({
            if (attempts.getAndIncrement() == 0) error("synthetic-secret")
            null
        })
        val failed = reader.read()
        assertSame(MacInventoryState.Unavailable, failed)
        assertFalse(failed.toString().contains("synthetic-secret"))
        assertIs<MacInventoryState.Ready>(reader.read())
        assertEquals(2, attempts.get())
        val storage = Storage()
        val invalidOwner = create(storage).also { it.close() }
        assertSame(MacInventoryState.Unavailable, StoredMacReader({ invalidOwner }).read())
    }

    @Test fun cancellationClosesTheOwnerBeforeTheNextReaderAndDoesNotPublishLateRows() = runBlocking {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val storage = Storage(); val store = create(storage)
        val attempts = AtomicInteger()
        val reader = StoredMacReader({
            when (attempts.incrementAndGet()) {
                1 -> { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); store }
                else -> { check(storage.closes == 1); null }
            }
        })
        var published = false
        val first = launch(Dispatchers.Default) { reader.read(); published = true }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            first.cancel()
            val second = async(Dispatchers.Default) { reader.read() }
            release.countDown()
            withTimeout(5000) {
                first.join()
                assertIs<MacInventoryState.Ready>(second.await())
            }
            assertFalse(published)
            assertEquals(1, storage.closes)
            assertEquals(2, attempts.get())
        } finally { release.countDown(); first.cancelAndJoin() }
    }

    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var writes = 0
        @Volatile var closes = 0
        override fun read(maximumBytes: Int): ByteArray? = bytes?.copyOf()?.also { require(it.size <= maximumBytes) }
        override fun replace(ciphertext: ByteArray) { writes++; bytes = ciphertext.copyOf() }
        override fun close() { closes++ }
    }
    private fun create(storage: Storage) = EncryptedEnrollmentStore.create(storage,
        EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65_536), 10)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun spki() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun record(n: Int): PhoneEnrollment {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = spki()
            return EnrollmentKeyReference(role, id(n * 3 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(n * 3 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(n), id(100), id(n + 40), id(n + 80), "Same display name",
            spki().takeLast(65).toByteArray(), spki(), key(EnrollmentKeyRole.TRANSPORT),
            key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() },
            RelayAccessCredential(RelayEndpoint("synthetic.example"), "synthetic-id", "synthetic-secret"))
    }
}
