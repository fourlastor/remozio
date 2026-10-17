package dev.remozio.android.push

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.push.*
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyGenerator
import org.junit.Test
import kotlin.test.*

class ApplicationPushChallengesTest {
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
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf(); writes++; if (fails) error("synthetic-storage-secret") }
    }
    private class Factory(val storage: Storage) {
        val cipher = PushChallengeCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey())
        var opens = 0
        var closes = 0
        fun open(): PushChallengeOwner {
            opens++; val journal = PendingPushChallenges(storage, cipher, 8, 1000u)
            return object : PushChallengeOwner {
                override fun selectGeneration(generation: UUID, moment: PushChallengeMoment) =
                    journal.selectGeneration(generation, moment.bootEpoch, moment.milliseconds)
                override fun admit(generation: UUID, challenge: PushData.TokenChallenge, moment: PushChallengeMoment) =
                    journal.admit(generation, challenge, moment.bootEpoch, moment.milliseconds)
                override fun pending(generation: UUID, moment: PushChallengeMoment) = journal.pending(generation, moment.bootEpoch, moment.milliseconds)
                override fun match(generation: UUID, metadata: PhonePushRegistrationMetadata, moment: PushChallengeMoment) =
                    journal.match(generation, metadata, moment.bootEpoch, moment.milliseconds)
                override fun discard(ticket: PendingPushChallengeTicket, moment: PushChallengeMoment) =
                    journal.discard(ticket, moment.bootEpoch, moment.milliseconds)
                override fun close() { closes++ }
            }
        }
    }
    private fun challenge(metadata: PhonePushRegistrationMetadata) = PushData.TokenChallenge(metadata.candidateID, ByteArray(32) { 42 }, metadata.enrollmentTag)
    @Test fun durableAdmissionPrecedesTheReturnedSchedulingTicketAndSurvivesReopening() {
        val f = PushClientFixture(); f.enable(); val generation = assertNotNull(f.owner.generation()); val m = metadata(record())
        val storage = Storage(); val factory = Factory(storage)
        val app = ApplicationPushChallenges(f.owner, { PushChallengeMoment(1u, 100u) }, factory::open)
        val ticket = assertNotNull(app.admit(generation, challenge(m))); assertEquals(2, storage.writes)
        app.close(); val reopened = ApplicationPushChallenges(f.owner, { PushChallengeMoment(1u, 101u) }, factory::open)
        assertEquals(ticket.revision, reopened.pending(generation).single().revision)
        assertContentEquals(ByteArray(32) { 42 }, assertNotNull(reopened.match(generation, m)).challenge)
        assertFalse(String(assertNotNull(storage.bytes), Charsets.ISO_8859_1).contains("*".repeat(32))); reopened.close()
    }
    @Test fun disabledProviderCannotOpenStorageAdmitOrPublishAMatch() {
        val f = PushClientFixture(); f.enable(); val generation = assertNotNull(f.owner.generation()); val m = metadata(record())
        val storage = Storage(); val factory = Factory(storage); f.owner.setEnabled(false)
        val app = ApplicationPushChallenges(f.owner, { error("Disabled work read the clock") }, factory::open)
        assertNull(app.admit(generation, challenge(m))); assertNull(app.match(generation, m)); assertTrue(app.pending(generation).isEmpty())
        assertEquals(0, factory.opens); assertEquals(0, storage.writes); app.close()
    }
    @Test fun oldWorkersCannotRestoreTheirProviderGenerationOrDiscardNewDelivery() {
        val f = PushClientFixture(); f.enable(); val old = assertNotNull(f.owner.generation()); val m = metadata(record())
        val storage = Storage(); val factory = Factory(storage); var now = 100uL
        val app = ApplicationPushChallenges(f.owner, { PushChallengeMoment(1u, now++) }, factory::open)
        val ticket = assertNotNull(app.admit(old, challenge(m)))
        assertTrue(f.owner.setEnabled(false)); assertTrue(f.owner.setEnabled(true)); val current = assertNotNull(f.owner.generation())
        val next = assertNotNull(app.admit(current, challenge(m))); val writes = storage.writes
        assertNull(app.admit(old, challenge(m))); assertTrue(app.pending(old).isEmpty()); assertFalse(app.discard(ticket))
        assertEquals(writes, storage.writes); assertEquals(next.revision, app.pending(current).single().revision); app.close()
    }
    @Test fun uncertainAdmissionClosesItsOwnerAndRestoredWorkRemainsPending() {
        val f = PushClientFixture(); f.enable(); val generation = assertNotNull(f.owner.generation()); val m = metadata(record())
        val storage = Storage(); val factory = Factory(storage); val app = ApplicationPushChallenges(f.owner, { PushChallengeMoment(1u, 100u) }, factory::open)
        assertTrue(app.pending(generation).isEmpty()); storage.fails = true
        assertFailsWith<PushChallengeStoreUnavailable> { app.admit(generation, challenge(m)) }
        assertEquals(1, factory.closes); storage.fails = false
        assertEquals(1, app.pending(generation).size); assertEquals(2, factory.opens); app.close()
    }
    @Test fun bootChangeExpiresBuffersWithoutSelectingAnOldClockEpoch() {
        val f = PushClientFixture(); f.enable(); val generation = assertNotNull(f.owner.generation()); val m = metadata(record())
        val storage = Storage(); val factory = Factory(storage); var moment = PushChallengeMoment(1u, 100u)
        val app = ApplicationPushChallenges(f.owner, { moment }, factory::open)
        app.admit(generation, challenge(m)); moment = PushChallengeMoment(2u, 1u)
        assertNull(app.match(generation, m)); assertTrue(app.pending(generation).isEmpty()); app.close()
    }
}
