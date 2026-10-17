package dev.remozio.phone.push

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import org.junit.Test
import kotlin.test.*

class PhonePushProofLedgerTest {
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
        var commitThenFail = false
        override fun read(maximumBytes: Int) = bytes?.copyOf()
        override fun replace(bytes: ByteArray) {
            if (fails && !commitThenFail) error("synthetic-storage-secret")
            this.bytes = bytes.copyOf(); writes++
            if (fails) error("synthetic-storage-secret")
        }
    }
    @Test fun claimCommitsBeforeItReturnsAndRestartCannotRepeatIt() {
        val record = record(); val metadata = metadata(record); val storage = Storage()
        val ledger = PhonePushProofLedger(storage, 8)
        assertTrue(ledger.claim(record, metadata, offer)); assertEquals(1, storage.writes)
        assertFalse(ledger.claim(record, metadata, offer)); assertEquals(1, storage.writes)
        val reopened = PhonePushProofLedger(storage, 8)
        assertFalse(reopened.claim(record, metadata, offer)); assertEquals(1, storage.writes)
        val encoded = String(assertNotNull(storage.bytes), Charsets.ISO_8859_1)
        assertFalse(encoded.contains(offer.token)); assertFalse(encoded.contains("*".repeat(32)))
        assertEquals("PhonePushProofLedger(redacted)", reopened.toString())
    }
    @Test fun newerCandidatesAdvanceTheFloorAndStaleRepliesCannotReviveClaims() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        val first = metadata(record); val next = metadata(record, candidate = 7, revision = 3u)
        assertTrue(ledger.claim(record, first, offer)); assertTrue(ledger.claim(record, next, offer))
        assertFalse(ledger.claim(record, first, offer))
        assertFalse(ledger.claim(record, metadata(record, candidate = 8, revision = 2u), offer))
        assertEquals(2, storage.writes)
        assertFalse(PhonePushProofLedger(storage, 8).claim(record, first, offer))
    }
    @Test fun theSameCandidateCannotBeTransmittedAgainUnderANewerRevision() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        assertTrue(ledger.claim(record, metadata(record), offer))
        assertFalse(ledger.claim(record, metadata(record, revision = 3u), offer))
        assertFalse(ledger.claim(record, metadata(record, candidate = 8, revision = 2u), offer))
        assertFalse(PhonePushProofLedger(storage, 8).claim(record, metadata(record, revision = 3u), offer))
        assertEquals(2, storage.writes)
    }
    @Test fun conflictingMetadataAtOneRevisionIsRejectedWithoutResettingHistory() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        val first = metadata(record); assertTrue(ledger.claim(record, first, offer))
        assertFailsWith<IllegalArgumentException> { ledger.claim(record, metadata(record, candidate = 99), offer) }
        assertFalse(ledger.claim(record, first, offer)); assertEquals(1, storage.writes)
    }
    @Test fun scopeTagTokenAndEnrollmentPhaseMustMatchBeforeAnyWrite() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        for (bad in listOf(metadata(record(phone = 99)), metadata(record, tag = ByteArray(32)), metadata(record, token = "other-token"))) {
            assertFailsWith<IllegalArgumentException> { ledger.claim(record, bad, offer) }
        }
        assertFailsWith<IllegalArgumentException> {
            ledger.claim(StoredPhoneEnrollment(record.enrollment, EnrollmentPhase.PREPARED), metadata(record), offer)
        }
        assertEquals(0, storage.writes)
    }
    @Test fun registrationNamespacesRetainIndependentClaimsAcrossProviderChanges() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        val first = metadata(record); val another = metadata(record, owner = 99)
        assertTrue(ledger.claim(record, first, offer)); assertTrue(ledger.claim(record, another, offer))
        val reopened = PhonePushProofLedger(storage, 8)
        assertFalse(reopened.claim(record, first, offer)); assertFalse(reopened.claim(record, another, offer))
        assertEquals(2, storage.writes)
    }
    @Test fun capacityDoesNotEvictAnActiveClaimAndTrustedRemovalCanReleaseIt() {
        val first = record(); val second = record(recordID = 40, phone = 41); val storage = Storage()
        val ledger = PhonePushProofLedger(storage, 1)
        assertTrue(ledger.claim(first, metadata(first), offer))
        assertFailsWith<IllegalStateException> { ledger.claim(second, metadata(second), offer) }
        assertFalse(ledger.claim(first, metadata(first), offer)); assertEquals(1, storage.writes)
        ledger.retainActiveRecords(setOf(second.enrollment.recordID))
        assertTrue(ledger.claim(second, metadata(second), offer)); assertEquals(3, storage.writes)
    }
    @Test fun uncertainStorageCommitWithholdsPermissionAndReopeningRetainsItsClaim() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        storage.fails = true; storage.commitThenFail = true
        val error = assertFailsWith<PhonePushProofUnavailable> { ledger.claim(record, metadata(record), offer) }
        assertFalse(error.toString().contains("storage-secret"))
        storage.fails = false
        assertFailsWith<PhonePushProofUnavailable> { ledger.claim(record, metadata(record), offer) }
        assertFalse(PhonePushProofLedger(storage, 8).claim(record, metadata(record), offer))
        assertEquals(1, storage.writes)
    }
    @Test fun failedWriteBeforeCommitAuthorizesNothingAndDoesNotResetOtherClaims() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        assertTrue(ledger.claim(record, metadata(record), offer)); val retained = assertNotNull(storage.bytes).copyOf()
        storage.fails = true
        assertFailsWith<PhonePushProofUnavailable> { ledger.claim(record, metadata(record, candidate = 7, revision = 3u), offer) }
        assertContentEquals(retained, storage.bytes); storage.fails = false
        val reopened = PhonePushProofLedger(storage, 8)
        assertFalse(reopened.claim(record, metadata(record), offer))
        assertTrue(reopened.claim(record, metadata(record, candidate = 7, revision = 3u), offer))
    }
    @Test fun malformedAndConflictingArchivesAreRejectedWithoutWrites() {
        val record = record(); val storage = Storage(); val ledger = PhonePushProofLedger(storage, 8)
        assertTrue(ledger.claim(record, metadata(record), offer))
        val original = assertNotNull(storage.bytes); val limits = CborLimits(1_048_576, 4, 128)
        val fields = (DeterministicCbor.decode(original, limits) as CborValue.Fields).values
        val rows = (fields[2u] as CborValue.ArrayValue).values
        val duplicate = DeterministicCbor.encode(CborValue.Fields(fields + (2uL to CborValue.ArrayValue(rows + rows))), limits)
        val unknown = DeterministicCbor.encode(CborValue.Fields(fields + (3uL to CborValue.Null)), limits)
        for (bad in listOf(original.copyOf(original.size - 1), byteArrayOf(1), ByteArray(1_048_577), duplicate, unknown)) {
            storage.bytes = bad
            assertFailsWith<PhonePushProofUnavailable> { PhonePushProofLedger(storage, 8) }
            assertEquals(1, storage.writes); assertContentEquals(bad, storage.bytes)
        }
    }
}
