package dev.remozio.android.push

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.push.PhonePushProofLedger
import dev.remozio.phone.push.PhonePushProofStorage
import dev.remozio.phone.push.PhonePushProofUnavailable
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import org.junit.Test
import kotlin.test.*

class ApplicationPushProofsTest {
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
    private class Storage : PhonePushProofStorage {
        var bytes: ByteArray? = null
        var writes = 0
        var fails = false
        override fun read(maximumBytes: Int) = bytes?.copyOf()
        override fun replace(bytes: ByteArray) {
            this.bytes = bytes.copyOf(); writes++
            if (fails) error("synthetic-storage-secret")
        }
    }
    private class Factory(val storage: Storage) {
        var opens = 0
        var closes = 0
        fun open(): PushProofOwner {
            opens++; val ledger = PhonePushProofLedger(storage, 8)
            return object : PushProofOwner {
                override fun retainActiveRecords(recordIDs: Set<CborValue.Bytes>) = ledger.retainActiveRecords(recordIDs)
                override fun claim(record: StoredPhoneEnrollment, metadata: PhonePushRegistrationMetadata, offer: PhonePushTokenOffer) =
                    ledger.claim(record, metadata, offer)
                override fun close() { closes++ }
            }
        }
    }
    @Test fun retryAndApplicationRestartDoNotClearAClaimForTheSameRootCandidate() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().token(offer.token)
        val candidate = assertNotNull(f.owner.tokenCandidate()); val record = record(); val metadata = metadata(record)
        val storage = Storage(); val factory = Factory(storage); val app = ApplicationPushProofs(f.owner, factory::open)
        assertEquals(PushProofClaim.CLAIMED, app.claim(candidate, record, metadata, listOf(record)))
        f.owner.retry(); f.driver.attempts.last().token(offer.token); val retried = assertNotNull(f.owner.tokenCandidate())
        assertNotEquals(candidate.revision, retried.revision)
        assertEquals(PushProofClaim.RECOVERY_REQUIRED, app.claim(retried, record, metadata, listOf(record)))
        app.close(); val reopened = ApplicationPushProofs(f.owner, factory::open)
        assertEquals(PushProofClaim.RECOVERY_REQUIRED, reopened.claim(retried, record, metadata, listOf(record)))
        assertEquals(1, storage.writes); reopened.close()
    }
    @Test fun staleProviderRevisionCannotOpenOrMutateProofHistory() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().token(offer.token)
        val candidate = assertNotNull(f.owner.tokenCandidate()); val record = record(); val storage = Storage(); val factory = Factory(storage)
        val app = ApplicationPushProofs(f.owner, factory::open)
        f.driver.attempts.single().token("replacement-token")
        assertEquals(PushProofClaim.OBSOLETE, app.claim(candidate, record, metadata(record), listOf(record)))
        assertEquals(0, factory.opens); assertEquals(0, storage.writes)
        val current = assertNotNull(f.owner.tokenCandidate())
        assertEquals(PushProofClaim.CLAIMED, app.claim(current, record, metadata(record, token = current.token), listOf(record)))
        assertEquals(1, storage.writes); app.close()
    }
    @Test fun replacedRemovedOrPreparedEnrollmentCannotClearOrClaimHistory() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().token(offer.token)
        val candidate = assertNotNull(f.owner.tokenCandidate()); val record = record(); val storage = Storage(); val factory = Factory(storage)
        val app = ApplicationPushProofs(f.owner, factory::open)
        for (active in listOf(emptyList(), listOf(record()), listOf(StoredPhoneEnrollment(record.enrollment, EnrollmentPhase.PREPARED)))) {
            assertEquals(PushProofClaim.OBSOLETE, app.claim(candidate, record, metadata(record), active))
        }
        assertEquals(0, factory.opens); assertEquals(0, storage.writes); app.close()
    }
    @Test fun uncertainCommitRetiresItsOwnerAndReopeningCannotAuthorizeAnotherProof() {
        val f = PushClientFixture(); f.enable(); f.driver.attempts.single().token(offer.token)
        val candidate = assertNotNull(f.owner.tokenCandidate()); val record = record(); val storage = Storage(); val factory = Factory(storage)
        val app = ApplicationPushProofs(f.owner, factory::open); storage.fails = true
        assertFailsWith<PhonePushProofUnavailable> { app.claim(candidate, record, metadata(record), listOf(record)) }
        assertEquals(1, factory.closes); storage.fails = false
        assertEquals(PushProofClaim.RECOVERY_REQUIRED, app.claim(candidate, record, metadata(record), listOf(record)))
        assertEquals(2, factory.opens); assertEquals(1, storage.writes); app.close()
    }
}
