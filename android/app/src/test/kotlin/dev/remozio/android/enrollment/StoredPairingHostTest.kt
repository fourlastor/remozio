package dev.remozio.android.enrollment

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import org.junit.Test
import kotlin.test.*

class StoredPairingHostTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = key()
    private val biometric = key()
    private fun record(n: Int): PhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val point = (if (role == EnrollmentKeyRole.BIOMETRIC) biometric else key()).public.encoded
            return EnrollmentKeyReference(role, id(n * 3 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(n * 3 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) point else point.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(20), id(21), id(n + 30), id(n + 40), "Synthetic Mac",
            authority.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC),
            ByteArray(32) { n.toByte() }, null)
    }
    private fun transcript(e: PhoneEnrollment, old: PhoneEnrollment? = null): PairingTranscript {
        val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
        fun offer(role: ChannelRole, nonce: Int) = ChannelOffer(role, scope, ByteArray(32) { nonce.toByte() }, setOf(1uL), emptyList(), emptySet())
        fun claim(k: EnrollmentKeyReference) = PairingKey(k.keyID.copyBytes(), k.publicKey.copyBytes().takeLast(65).toByteArray())
        return PairingTranscript(id(70), ByteArray(32) { 71 }, offer(ChannelRole.PHONE, 72), offer(ChannelRole.MAC, 73),
            1u, 1u, e.authorityPublicKey.copyBytes(), e.transportPublicKey.copyBytes().takeLast(65).toByteArray(),
            claim(e.transportKey), claim(e.decisionKey), claim(e.biometricKey), e.enrollmentTag.copyBytes(),
            old?.let { PairingReplacement(it.phoneID.copyBytes(), it.epoch.copyBytes()) }, id(74), 1000u, 2000u)
    }

    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var fail = false
        override fun read(maximumBytes: Int) = bytes?.copyOf()
        override fun replace(ciphertext: ByteArray) { check(!fail); bytes = ciphertext.copyOf() }
        override fun close() = Unit
    }
    private val storage = Storage()
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65536)
    private val mutex = Mutex()
    private var custodyAvailable = true
    private var custodyChecks = 0
    private val invalidated = mutableListOf<Set<CborValue.Bytes>>()
    private fun open() = EncryptedEnrollmentStore.open(storage, cipher, 10)
    private fun host(invalidate: (Set<CborValue.Bytes>) -> Unit = { invalidated.add(it) }) = StoredPairingHost(
        ::open, ::open, mutex, { assertTrue(mutex.isLocked); invalidate(it) }, { custodyChecks++; check(custodyAvailable) }, Dispatchers.Unconfined)
    private fun receipt(t: PairingTranscript) = CborValue.Bytes(P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
        initSign(authority.private); update(t.signingInput(PairingProofPurpose.MAC_COMMIT)); sign()
    }))
    init { EncryptedEnrollmentStore.create(storage, cipher, 10).close() }

    @Test fun activationReopensRetainedAttemptAndInvalidatesBeforeCommit() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e)
        host().prepare(e, t, 0u, 1u)
        assertTrue(invalidated.isEmpty())
        val result = host { ids ->
            assertEquals(setOf(e.recordID), ids)
            open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        }.activate(e.recordID, receipt(t))
        assertEquals(EnrollmentPhase.ACTIVE, result.entries.single().phase)
        assertFails { host().activate(e.recordID, receipt(t)) }
    }

    @Test fun replacementClosesBothIncarnationsBeforeChangingTrust() = runBlocking<Unit> {
        val old = record(1); val original = transcript(old)
        host().prepare(old, original, 0u, 1u)
        val active = host().activate(old.recordID, receipt(original))
        val next = record(2); val replacement = transcript(next, old)
        host().prepare(next, replacement, active.revision, 1u, old.recordID)
        val result = host { ids ->
            assertEquals(setOf(old.recordID, next.recordID), ids)
            open().use { store ->
                assertEquals(EnrollmentPhase.ACTIVE, store.snapshot().entries.single { it.enrollment.recordID == old.recordID }.phase)
                assertEquals(EnrollmentPhase.PREPARED, store.snapshot().entries.single { it.enrollment.recordID == next.recordID }.phase)
            }
        }.activate(next.recordID, receipt(replacement))
        assertEquals(EnrollmentPhase.REMOVED, result.entries.single { it.enrollment.recordID == old.recordID }.phase)
        assertEquals(EnrollmentPhase.ACTIVE, result.entries.single { it.enrollment.recordID == next.recordID }.phase)
    }

    @Test fun custodyFailurePreventsPreparationAndActivationWithoutClosingConnections() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e)
        custodyAvailable = false
        assertFails { host().prepare(e, t, 0u, 1u) }
        open().use { assertTrue(it.snapshot().entries.isEmpty()) }
        custodyAvailable = true
        host().prepare(e, t, 0u, 1u)
        custodyAvailable = false
        assertFails { host().activate(e.recordID, receipt(t)) }
        assertTrue(invalidated.isEmpty())
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
        assertEquals(3, custodyChecks)
        host().remove(e.recordID, 1u)
        assertEquals(3, custodyChecks)
    }

    @Test fun invalidReceiptDoesNotInterruptConnections() = runBlocking<Unit> {
        val e = record(1); host().prepare(e, transcript(e), 0u, 1u)
        assertFails { host().activate(e.recordID, CborValue.Bytes(ByteArray(64))) }
        assertTrue(invalidated.isEmpty())
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
    }

    @Test fun invalidationFailurePreventsActivationAndRemoval() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e); host().prepare(e, t, 0u, 1u)
        val broken = host { error("Synthetic close failure") }
        assertFails { broken.activate(e.recordID, receipt(t)) }
        assertFails { broken.remove(e.recordID, 1u) }
        open().use { assertEquals(EnrollmentPhase.PREPARED, it.snapshot().entries.single().phase) }
    }

    @Test fun removalRejectsStaleRevisionAndLateReceipt() = runBlocking<Unit> {
        val e = record(1); val t = transcript(e); host().prepare(e, t, 0u, 1u)
        assertFails { host().remove(e.recordID, 0u) }
        assertTrue(invalidated.isEmpty())
        host().remove(e.recordID, 1u)
        assertEquals(listOf(setOf(e.recordID)), invalidated)
        assertFails { host().activate(e.recordID, receipt(t)) }
        open().use { assertEquals(EnrollmentPhase.REMOVED, it.snapshot().entries.single().phase) }
    }
    @Test fun preparedLeaseRetiresBeforeRemovalAndCannotLoadAnAlteredTranscript() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val access = h.prepared(e.recordID, t)
        assertTrue(access.lease.isCurrent())
        assertFails { h.prepared(e.recordID, transcript(record(2))) }
        h.remove(e.recordID, 1u)
        assertFalse(access.lease.isCurrent())
        assertFails { h.prepared(e.recordID, t) }
    }

    @Test fun verifiedActivationRetiresItsPreparedBiometricLease() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val access = h.prepared(e.recordID, t)
        h.activate(e.recordID, receipt(t))
        assertFalse(access.lease.isCurrent())
        assertFails { h.prepared(e.recordID, t) }
    }

    @Test fun releasingOnePreparedLeaseDoesNotRetireAnother() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val first = h.prepared(e.recordID, t); val second = h.prepared(e.recordID, t)
        h.release(e.recordID, first.lease)
        assertFalse(first.lease.isCurrent()); assertTrue(second.lease.isCurrent())
        h.release(e.recordID, second.lease)
        assertFalse(second.lease.isCurrent())
    }

    @Test fun preparedLeasesAreBoundedAndReleasedCapacityCanBeReused() = runBlocking<Unit> {
        val h = host(); val e = record(1); val t = transcript(e)
        h.prepare(e, t, 0u, 1u)
        val leases = (1..32).map { h.prepared(e.recordID, t).lease }
        assertFails { h.prepared(e.recordID, t) }
        h.release(e.recordID, leases.first())
        assertTrue(h.prepared(e.recordID, t).lease.isCurrent())
        h.remove(e.recordID, 1u)
        assertTrue(leases.none { it.isCurrent() })
    }
}
