package dev.remozio.android.push

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.push.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.PushData
import dev.remozio.protocol.CborValue
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.Test
import kotlin.test.*

class StoredWakeNotificationsTest {
    private class Archive {
        private var bytes: ByteArray? = null
        private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65_536)
        var writes = 0; var closes = 0; var unavailable = false
        fun open(): EncryptedEnrollmentStore {
            check(!unavailable)
            val storage = object : EnrollmentStorage {
                var closed = false
                override fun read(maximumBytes: Int): ByteArray? { check(!closed); return bytes?.copyOf() }
                override fun replace(ciphertext: ByteArray) { check(!closed); bytes = ciphertext.copyOf(); writes++ }
                override fun close() { if (!closed) { closed = true; closes++ } }
            }
            return if (bytes == null) EncryptedEnrollmentStore.create(storage, cipher, 10) else EncryptedEnrollmentStore.open(storage, cipher, 10)
        }
        fun prepare(record: PhoneEnrollment, active: Boolean) = open().use { store ->
            store.prepare(record, store.snapshot().revision)
            if (active) store.activateSyntheticEnrollment(record.recordID.copyBytes(), store.snapshot().revision)
        }
        fun remove(record: PhoneEnrollment) = open().use { it.remove(record.recordID.copyBytes(), it.snapshot().revision) }
    }
    private class Fixture {
        val archive = Archive()
        val client = PushClientFixture().also { it.enable() }
        val mutex = Mutex()
        val posted = mutableListOf<Pair<CborValue.Bytes, Boolean>>()
        val cancelled = mutableListOf<CborValue.Bytes>()
        var time = 100uL
        val receiver = StoredWakeNotifications(archive::open, mutex, client.owner, { ElapsedInstant(1, time) },
            { enrollment, alert -> posted += enrollment to alert; WakeNotificationResult.POSTED }, { cancelled += it }, Dispatchers.Unconfined)
        val generation get() = assertNotNull(client.owner.generation())
    }
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun spki() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun record(n: Int, mac: Int = n): PhoneEnrollment {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = spki(); val keyID = id(n * 10 + role.ordinal)
            return EnrollmentKeyReference(role, keyID, "remozio.${role.aliasPart}.v1." + keyID.joinToString("") { "%02x".format(it) },
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(mac), id(mac), id(mac), id(n), "Synthetic Mac",
            spki().takeLast(65).toByteArray(), spki(), key(EnrollmentKeyRole.TRANSPORT), key(EnrollmentKeyRole.DECISION),
            key(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
    }
    private fun wake(record: PhoneEnrollment, n: Int = 1) = PushData.Wake(ByteArray(32) { n.toByte() }, record.enrollmentTag.copyBytes()).encode()

    @Test fun activeMacsRouteIndependentlyAndDuplicateWakesDoNotAlertAgain() = runBlocking {
        val f = Fixture(); val first = record(1); val second = record(2)
        f.archive.prepare(first, true); f.archive.prepare(second, true); val writes = f.archive.writes
        assertEquals(WakeReception.ACCEPTED, f.receiver.receive(f.generation, wake(first))?.reception)
        assertEquals(WakeReception.ACCEPTED, f.receiver.receive(f.generation, wake(second))?.reception)
        assertEquals(WakeReception.DUPLICATE, f.receiver.receive(f.generation, wake(first))?.reception)
        assertEquals(listOf(first.recordID, second.recordID), f.posted.map { it.first })
        assertEquals(listOf(true, true), f.posted.map { it.second }); assertEquals(writes, f.archive.writes)
        assertEquals(WakeReception.ACCEPTED, f.receiver.receive(f.generation, wake(first, 2))?.reception)
        assertFalse(f.posted.last().second)
    }
    @Test fun preparedRemovedAndUnknownTagsCannotPostNotifications() = runBlocking {
        val f = Fixture(); val prepared = record(1); val removed = record(2); val unknown = record(3)
        f.archive.prepare(prepared, false); f.archive.prepare(removed, true); f.archive.remove(removed)
        for (r in listOf(prepared, removed, unknown)) assertEquals(WakeReception.UNKNOWN_ENROLLMENT, f.receiver.receive(f.generation, wake(r))?.reception)
        assertTrue(f.posted.isEmpty()); assertTrue(f.cancelled.isEmpty())
    }
    @Test fun removalWithdrawsTheExactIncarnationAndItsOldTagCannotReachTheReplacement() = runBlocking {
        val f = Fixture(); val first = record(1); val next = record(2, mac = 1)
        f.archive.prepare(first, true); f.receiver.receive(f.generation, wake(first))
        f.mutex.withLock { f.receiver.invalidateRecordsLocked(setOf(first.recordID)); f.archive.remove(first) }
        f.archive.prepare(next, true)
        assertEquals(WakeReception.UNKNOWN_ENROLLMENT, f.receiver.receive(f.generation, wake(first, 2))?.reception)
        assertEquals(WakeReception.ACCEPTED, f.receiver.receive(f.generation, wake(next))?.reception)
        assertEquals(1, f.cancelled.size); assertEquals(first.recordID, f.cancelled.single())
        assertEquals(next.recordID, f.posted.last().first)
    }
    @Test fun staleProviderGenerationCannotPostAndAnArchiveFailureWithdrawsCachedNotifications() = runBlocking {
        val f = Fixture(); val r = record(1); f.archive.prepare(r, true); val old = f.generation
        f.receiver.receive(old, wake(r)); assertEquals(1, f.posted.size)
        f.client.owner.setEnabled(false)
        assertNull(f.receiver.receive(old, wake(r, 2))); assertEquals(1, f.posted.size)
        f.client.owner.setEnabled(true); assertNotEquals(old, f.generation)
        assertNull(f.receiver.receive(old, wake(r, 3))); assertEquals(1, f.posted.size)
        f.archive.unavailable = true
        assertNull(f.receiver.receive(f.generation, wake(r, 4))); assertEquals(1, f.cancelled.size)
        f.archive.unavailable = false
        assertEquals(WakeReception.ACCEPTED, f.receiver.receive(f.generation, wake(r, 5))?.reception)
    }
    @Test fun absentArchiveIsReadOnlyAndCancellationWhileWaitingDoesNotPost() = runBlocking {
        val client = PushClientFixture().also { it.enable() }; val mutex = Mutex(); var opens = 0; var posts = 0
        val receiver = StoredWakeNotifications({ opens++; null }, mutex, client.owner, { ElapsedInstant(1, 100u) },
            { _, _ -> posts++; WakeNotificationResult.POSTED }, {}, Dispatchers.Unconfined)
        val r = record(1); val generation = assertNotNull(client.owner.generation())
        assertEquals(WakeReception.UNKNOWN_ENROLLMENT, receiver.receive(generation, wake(r))?.reception)
        mutex.lock()
        val waiting = async(start = CoroutineStart.UNDISPATCHED) { receiver.receive(generation, wake(r)) }
        waiting.cancel(); mutex.unlock()
        assertFailsWith<CancellationException> { waiting.await() }
        assertEquals(1, opens); assertEquals(0, posts)
    }
    @Test fun coldProcessRetirementCancelsTheStableLocalRecordWithoutLoadingItsArchive() {
        val client = PushClientFixture().also { it.enable() }; val cancelled = mutableListOf<CborValue.Bytes>(); val r = record(1)
        val receiver = StoredWakeNotifications({ error("retirement must not reopen storage") }, Mutex(), client.owner,
            { ElapsedInstant(1, 100u) }, { _, _ -> error("retirement must not post") }, { cancelled += it }, Dispatchers.Unconfined)
        receiver.invalidateRecordsLocked(setOf(r.recordID))
        assertEquals(listOf(r.recordID), cancelled)
    }
    @Test fun tokenChallengesAndExtraPayloadFieldsCannotCreateApprovalNotifications() = runBlocking {
        val f = Fixture(); val r = record(1); f.archive.prepare(r, true)
        val challenge = PushData.TokenChallenge(id(5), ByteArray(32) { 6 }, r.enrollmentTag.copyBytes()).encode()
        assertEquals(WakeReception.TOKEN_CHALLENGE, f.receiver.receive(f.generation, challenge)?.reception)
        assertEquals(WakeReception.MALFORMED, f.receiver.receive(f.generation, wake(r) + ("endpoint" to "https://synthetic.invalid"))?.reception)
        assertTrue(f.posted.isEmpty())
    }
}
