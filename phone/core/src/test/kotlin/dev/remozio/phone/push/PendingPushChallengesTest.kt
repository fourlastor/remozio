package dev.remozio.phone.push

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyGenerator
import org.junit.Test
import kotlin.test.*

class PendingPushChallengesTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun record(recordID: Int = 1, phone: Int = 3, phase: EnrollmentPhase = EnrollmentPhase.ACTIVE): StoredPhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val bytes = key()
            return EnrollmentKeyReference(role, id(role.ordinal + 10),
                "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
                if (role == EnrollmentKeyRole.TRANSPORT) bytes else bytes.takeLast(65).toByteArray())
        }
        return StoredPhoneEnrollment(PhoneEnrollment(id(recordID), id(20), id(21), id(phone), id(4), "Synthetic host", key().takeLast(65).toByteArray(),
            key(), local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { 5 }, null), phase)
    }
    private val offer = PhonePushTokenOffer("synthetic-token", "project", "123", "dev.remozio.android")
    private fun metadata(record: StoredPhoneEnrollment, candidate: Int = 6, revision: ULong = 1u, owner: Int = 9,
                         token: String = offer.token, tag: ByteArray = record.enrollment.enrollmentTag.copyBytes()): PhonePushRegistrationMetadata {
        val e = record.enrollment
        val binding = GatewayTokenBinding(id(owner), e.macID.copyBytes(), e.accountID.copyBytes(), id(7), id(8),
            e.phoneID.copyBytes(), e.epoch.copyBytes(), id(candidate), MessageDigest.getInstance("SHA-256").digest(token.toByteArray()),
            ByteArray(32) { 42 }, tag)
        return PhonePushRegistrationMetadata(GatewayTokenCandidate(binding, revision, id(10), 1000u, 2000u))
    }
    private class Storage : PushChallengeStorage {
        var bytes: ByteArray? = null
        var writes = 0
        var fails = false
        override fun read(maximumBytes: Int) = bytes?.copyOf()
        override fun replace(ciphertext: ByteArray) {
            bytes = ciphertext.copyOf(); writes++
            if (fails) error("synthetic-storage-secret")
        }
    }
    private class Fixture(val maximum: Int = 8, val lifetime: ULong = 100u) {
        val storage = Storage()
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val cipher = PushChallengeCipher(key)
        val generation = UUID.randomUUID()
        var revision = 1
        fun open() = PendingPushChallenges(storage, cipher, maximum, lifetime) { ByteArray(16) { (revision++).toByte() } }
    }
    private fun challenge(metadata: PhonePushRegistrationMetadata, value: Byte = 42) =
        PushData.TokenChallenge(metadata.candidateID, ByteArray(32) { value }, metadata.enrollmentTag)
    @Test fun providerChallengeArrivesBeforeMetadataAndSurvivesReopening() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open()
        journal.selectGeneration(f.generation, 1u, 100u)
        val ticket = assertNotNull(journal.admit(f.generation, challenge(m), 1u, 101u))
        val reopened = f.open(); val matched = assertNotNull(reopened.match(f.generation, m, 1u, 102u))
        assertContentEquals(ByteArray(32) { 42 }, matched.challenge)
        assertEquals(ticket.revision, reopened.pending(f.generation, 1u, 102u).single().revision)
        assertFalse(String(assertNotNull(f.storage.bytes), Charsets.ISO_8859_1).contains("*".repeat(32)))
        assertEquals("PendingPushChallenges(redacted)", journal.toString())
        assertEquals("PendingPushChallengeTicket(redacted)", ticket.toString())
    }
    @Test fun duplicatesNeverExtendTheOriginalDeadline() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        val first = assertNotNull(journal.admit(f.generation, challenge(m), 1u, 101u)); val writes = f.storage.writes
        val duplicate = assertNotNull(journal.admit(f.generation, challenge(m), 1u, 150u))
        assertEquals(first.revision, duplicate.revision); assertEquals(writes, f.storage.writes)
        assertNotNull(journal.match(f.generation, m, 1u, 200u)); assertNull(journal.match(f.generation, m, 1u, 201u))
        assertTrue(f.open().pending(f.generation, 1u, 202u).isEmpty())
    }
    @Test fun matchingRequiresTheExactCandidateAndEnrollmentTag() {
        val f = Fixture(); val record = record(); val m = metadata(record); val journal = f.open()
        journal.selectGeneration(f.generation, 1u, 100u); journal.admit(f.generation, challenge(m), 1u, 101u)
        assertNull(journal.match(f.generation, metadata(record, candidate = 99), 1u, 102u))
        assertNull(journal.match(f.generation, metadata(record, tag = ByteArray(32)), 1u, 103u))
        val matched = assertNotNull(journal.match(f.generation, m, 1u, 104u)); matched.challenge.fill(0)
        assertContentEquals(ByteArray(32) { 42 }, assertNotNull(journal.match(f.generation, m, 1u, 105u)).challenge)
    }
    @Test fun conflictingChallengeCannotReplaceAnExistingDelivery() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        journal.admit(f.generation, challenge(m), 1u, 101u); val writes = f.storage.writes
        assertFailsWith<IllegalArgumentException> { journal.admit(f.generation, challenge(m, 99), 1u, 102u) }
        assertContentEquals(ByteArray(32) { 42 }, assertNotNull(journal.match(f.generation, m, 1u, 103u)).challenge)
        assertEquals(writes, f.storage.writes)
    }
    @Test fun capacityPreservesAnExistingDeliveryAndExpiryReleasesItsSlot() {
        val f = Fixture(maximum = 1); val record = record(); val first = metadata(record); val next = metadata(record, candidate = 99)
        val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u); journal.admit(f.generation, challenge(first), 1u, 101u)
        assertNull(journal.admit(f.generation, challenge(next), 1u, 102u)); assertNotNull(journal.match(f.generation, first, 1u, 103u))
        assertNotNull(journal.admit(f.generation, challenge(next), 1u, 201u)); assertNull(journal.match(f.generation, first, 1u, 201u))
    }
    @Test fun oldTicketsCannotDiscardANewerDeliveryForTheSameCandidate() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        val first = assertNotNull(journal.admit(f.generation, challenge(m), 1u, 101u))
        val next = assertNotNull(journal.admit(f.generation, challenge(m), 1u, 201u))
        assertNotEquals(first.revision, next.revision); assertFalse(journal.discard(first, 1u, 202u))
        assertNotNull(journal.match(f.generation, m, 1u, 203u)); assertTrue(journal.discard(next, 1u, 204u))
        assertNull(f.open().match(f.generation, m, 1u, 205u))
    }
    @Test fun providerOrBootChangesRetireBuffersAndOldWorkersCannotSelectTheirGeneration() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        val first = assertNotNull(journal.admit(f.generation, challenge(m), 1u, 101u)); val next = UUID.randomUUID()
        journal.selectGeneration(next, 1u, 102u)
        assertNull(journal.match(f.generation, m, 1u, 103u)); assertNull(journal.admit(f.generation, challenge(m), 1u, 103u))
        assertFalse(journal.discard(first, 1u, 103u)); assertNotNull(journal.admit(next, challenge(m), 1u, 104u))
        journal.selectGeneration(next, 2u, 5u); assertNull(journal.match(next, m, 2u, 6u))
        assertNotNull(journal.admit(next, challenge(m), 2u, 7u))
    }
    @Test fun clockRollbackAndDeadlineOverflowCannotWriteOrResetState() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        journal.admit(f.generation, challenge(m), 1u, 101u); val retained = assertNotNull(f.storage.bytes).copyOf()
        assertFailsWith<IllegalArgumentException> { journal.pending(f.generation, 1u, 99u) }
        assertFailsWith<IllegalArgumentException> { journal.pending(f.generation, 2u, 102u) }
        assertContentEquals(retained, f.storage.bytes); assertNotNull(journal.match(f.generation, m, 1u, 103u))
        journal.selectGeneration(f.generation, 2u, ULong.MAX_VALUE)
        val writes = f.storage.writes
        assertFailsWith<IllegalArgumentException> { journal.admit(f.generation, challenge(m), 2u, ULong.MAX_VALUE) }
        assertEquals(writes, f.storage.writes)
    }
    @Test fun uncertainCommitRetiresTheOwnerAndReopeningRecoversTheAdmittedDelivery() {
        val f = Fixture(); val m = metadata(record()); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        f.storage.fails = true
        val error = assertFailsWith<PushChallengeStoreUnavailable> { journal.admit(f.generation, challenge(m), 1u, 101u) }
        assertFalse(error.toString().contains("storage-secret")); f.storage.fails = false
        assertFailsWith<PushChallengeStoreUnavailable> { journal.pending(f.generation, 1u, 102u) }
        assertNotNull(f.open().match(f.generation, m, 1u, 102u))
    }
    @Test fun corruptionWrongKeyAndUnsupportedArchivesNeverResetStorage() {
        val f = Fixture(); val journal = f.open(); journal.selectGeneration(f.generation, 1u, 100u)
        journal.admit(f.generation, challenge(metadata(record())), 1u, 101u)
        val original = assertNotNull(f.storage.bytes).copyOf(); val writes = f.storage.writes
        val bad = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        for (bytes in listOf(bad, ByteArray(PushChallengeCipher.MAXIMUM_CIPHERTEXT_BYTES + 1), f.cipher.encrypt(byteArrayOf(1)))) {
            f.storage.bytes = bytes; assertFailsWith<PushChallengeStoreUnavailable> { f.open() }
            assertContentEquals(bytes, f.storage.bytes); assertEquals(writes, f.storage.writes)
        }
        f.storage.bytes = original
        val other = PushChallengeCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey())
        assertFailsWith<PushChallengeStoreUnavailable> { PendingPushChallenges(f.storage, other, 8, 100u) }
        assertContentEquals(original, f.storage.bytes)
    }
    @Test fun cipherUsesIndependentRandomizedEnvelopesAndRejectsAnotherPurpose() {
        val f = Fixture(); val plaintext = "synthetic-provider-only-challenge".encodeToByteArray()
        val first = f.cipher.encrypt(plaintext); val second = f.cipher.encrypt(plaintext)
        assertFalse(first.contentEquals(second)); assertContentEquals(plaintext, f.cipher.decrypt(first))
        first[0] = 0; assertFailsWith<IllegalArgumentException> { f.cipher.decrypt(first) }
        assertEquals("PushChallengeCipher(redacted)", f.cipher.toString())
    }
}
