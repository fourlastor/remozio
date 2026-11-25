package dev.sebastiano.remozio.android.biometrics

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.sebastiano.remozio.android.enrollment.PairingDeadline

import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import org.junit.Test
import kotlin.test.*

class AndroidPairingBiometricsTest {
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
            old?.let { PairingReplacement(it.phoneID.copyBytes(), it.epoch.copyBytes()) }, id(74), 1_000_000u, 1_001_000u)
    }
    private val enrollment = record(1)
    private val transcript = transcript(enrollment)
    private val prepared = StoredPhoneEnrollment(enrollment, EnrollmentPhase.PREPARED, PreparedPairing(transcript, null, 1u))
    private var time = ElapsedInstant(1, 100u)
    private var current = true
    private fun newDeadline(wall: ULong = 1_000_000u, remaining: Long = 300_000) =
        PairingDeadline(transcript, ElapsedInstant(1, 100u), remaining, wall)

    private fun owner(deadline: PairingDeadline = newDeadline()) =
        AndroidPairingBiometrics(prepared, biometric.private, biometric.public, deadline, { time }, { current })

    @Test fun proofUsesOnlyTheExactTranscriptAndBiometricPurpose() {
        val owner = owner(); val operation = owner.prepare(owner.beginAttempt())
        val proof = operation.complete(operation.signature)
        assertTrue(transcript.verify(proof, enrollment.biometricKey.publicKey.copyBytes(), PairingProofPurpose.PHONE_BIOMETRIC))
        assertFalse(transcript.verify(proof, enrollment.biometricKey.publicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
        assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
        owner.close()
        assertFalse(owner.available())
    }

    @Test fun expiryClockChangesAndCancellationPreventLateSigning() {
        for (changed in listOf(ElapsedInstant(1, 1100u), ElapsedInstant(1, 99u), ElapsedInstant(2, 101u))) {
            time = ElapsedInstant(1, 100u)
            val owner = owner(); val operation = owner.prepare(owner.beginAttempt())
            time = changed
            assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
            owner.close()
        }
        time = ElapsedInstant(1, 100u)
        val owner = owner(); val operation = owner.prepare(owner.beginAttempt())
        operation.close()
        assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
        owner.close()
    }

    @Test fun localInvalidationOrCryptoObjectSubstitutionCannotSign() {
        val owner = owner(); val operation = owner.prepare(owner.beginAttempt())
        val substituted = Signature.getInstance("SHA256withECDSA").apply { initSign(biometric.private) }
        assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(substituted) }
        val next = owner.prepare(owner.beginAttempt()); current = false
        assertFailsWith<BiometricAuthorizationUnavailable> { next.complete(next.signature) }
        assertFalse(owner.available())
        owner.close()
    }

    @Test fun wallClockSkewOnlyControlsTheAdvisory() {
        for ((wall, advisory) in listOf(970_000uL to false, 1_030_000uL to false, 939_999uL to true, 1_061_001uL to true)) {
            time = ElapsedInstant(1, 100u)
            val deadline = newDeadline(wall)
            assertEquals(advisory, deadline.clockSkewAdvisory)
            assertEquals(1100L, deadline.expiresElapsedMillis)
            owner(deadline).use { signer ->
                val operation = signer.prepare(signer.beginAttempt())
                assertTrue(transcript.verify(operation.complete(operation.signature),
                    enrollment.biometricKey.publicKey.copyBytes(), PairingProofPurpose.PHONE_BIOMETRIC))
            }
        }
    }

    @Test fun loadingAgainAfterCancellationKeepsTheOriginalChannelDeadline() {
        val deadline = newDeadline(remaining = 50)
        assertEquals(150L, deadline.expiresElapsedMillis)
        time = ElapsedInstant(1, 140u)
        owner(deadline).use { signer -> signer.prepare(signer.beginAttempt()).close() }
        owner(deadline).use { signer ->
            val operation = signer.prepare(signer.beginAttempt())
            time = ElapsedInstant(1, 150u)
            assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
            assertFailsWith<IllegalStateException> { signer.beginAttempt() }
        }
    }

    @Test fun aConsumedChannelBudgetCannotStartAPrompt() {
        owner(newDeadline(remaining = 0)).use { signer ->
            assertFalse(signer.available())
            assertFailsWith<IllegalStateException> { signer.beginAttempt() }
        }
    }

    @Test fun aDeadlineFromAnotherTranscriptCannotLoadASigner() {
        val other = PairingDeadline(transcript(record(2)), ElapsedInstant(1, 100u), 1_000, 1_000_000u)
        assertFailsWith<IllegalArgumentException> { owner(other) }
    }
}
