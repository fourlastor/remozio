package dev.remozio.phone.updates

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.Test
import kotlin.test.*

class PhoneUpdateSchedulingTooLateObservationTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private val signingLimits = CborLimits(8192, 2, 32)
    private val controlLimits = CborLimits(1024, 2, 32)

    private inner class Fixture {
        val root = key()
        val decision = key()
        var nanos = 1_000_000L
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(3), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, decision),
            local(EnrollmentKeyRole.BIOMETRIC, key()), ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        val scope = ChannelScope(id(20), id(21), id(3), id(4))
        val update = ByteArray(32) { 8 }
        fun query(clock: () -> Long = { nanos }) = PhoneUpdateSchedulingQuery.begin(record, update, 1u, 0u,
            UpdateSchedulingAction.CANCEL_DRAIN, clock, 1000) { ByteArray(32) { 31 } }
        fun progress(request: PhoneUpdateSchedulingFrame, scope: ChannelScope = this.scope,
                     update: ByteArray = this.update, generation: ULong = 1u,
                     revision: ULong = 1u) = UpdateSchedulingProgressResponse(
            UpdateSchedulingStatusResponse(scope, request.queryNonce.copyBytes(), update, generation, revision,
                UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES),
            UpdateSchedulingProgressPhase.CHECKING_RESTART, UpdateSchedulingDesignation.THIS_ACCOUNT,
            UpdateSchedulingSecurityStatus.UNKNOWN, 100u, 0u, emptyList(), UpdateSchedulingAdmissionState.CLOSED)
        fun reply(request: PhoneUpdateSchedulingFrame, signer: KeyPair = root,
                  progress: UpdateSchedulingProgressResponse = progress(request)): Pair<ByteArray, ByteArray> {
            val body = UpdateSchedulingTooLateResponse(request, progress).encode()
            return body to sign(signer, UpdateSchedulingTooLateSigningInput.make(1u, body, signingLimits))
        }
        fun apply(): PhoneUpdateSchedulingFrame.Apply {
            val control = UpdateSchedulingControl(id(20), id(21), id(3), id(4), id(6), ByteArray(32) { 7 },
                record.enrollment.decisionKey.keyID.copyBytes(), update, 1u, 0u, 1000u, 31_000u,
                UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES).encode(controlLimits)
            val signature = sign(decision, UpdateSchedulingSigningInput.make(1u, control, controlLimits, signingLimits))
            return PhoneUpdateSchedulingFrame.Apply(ByteArray(32) { 41 }, control, signature)
        }
    }

    @Test fun originalChallengeAcceptsOnlyItsRootVerifiedTooLateObservation() {
        val f = Fixture(); val query = f.query(); val request = query.requestFrame(f.record)
        val (body, signature) = f.reply(request)
        f.nanos += 40_000_000
        val result = query.verifyTooLate(f.record, body, signature)
        query.close()
        assertEquals(40L, result.ageMilliseconds()); assertEquals(140uL, result.readyAgeUpperBoundMilliseconds())
        assertTrue(result.matchesEnrollment(f.record)); assertTrue(result.isFresh(41))
        assertNull(result.response.progress.status.controlDigest)
        assertEquals(0uL, result.response.progress.availableActions)
        assertEquals("PhoneUpdateSchedulingTooLateObservation(redacted)", result.toString())
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, body, signature) }
        assertEquals(40L, result.ageMilliseconds())
    }

    @Test fun anotherRootCannotEstablishTooLateOrRestoreTheQuery() {
        val f = Fixture(); val query = f.query(); val request = query.requestFrame(f.record)
        val (body, signature) = f.reply(request, signer = key())
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, body, signature) }
        val valid = f.reply(request)
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, valid.first, valid.second) }
    }

    @Test fun aValidRootSignatureCannotSubstituteAnyChannelScopeMember() {
        for (part in 0..3) {
            val f = Fixture(); val query = f.query(); val request = query.requestFrame(f.record)
            val ids = listOf(id(20), id(21), id(3), id(4)).toMutableList(); ids[part] = id(99)
            val other = ChannelScope(ids[0], ids[1], ids[2], ids[3])
            val reply = f.reply(request, progress = f.progress(request, scope = other))
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
        }
    }

    @Test fun anotherNonceActionOrRevisionCannotReuseAValidReply() {
        for (part in 0..2) {
            val f = Fixture(); val query = f.query(); val request = query.requestFrame(f.record)
            val other = PhoneUpdateSchedulingFrame.Challenge(
                if (part == 0) ByteArray(32) { 99 } else request.queryNonce.copyBytes(), request.updateID.copyBytes(),
                request.generation, if (part == 2) 1u else request.revision,
                if (part == 1) UpdateSchedulingAction.DEFER_UPDATE else request.action)
            val reply = f.reply(other)
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
        }
    }

    @Test fun changedCandidateOrGenerationCannotReuseAValidReply() {
        for (changeCandidate in listOf(false, true)) {
            val f = Fixture(); val query = f.query(); val request = query.requestFrame(f.record)
            val other = PhoneUpdateSchedulingFrame.Challenge(request.queryNonce.copyBytes(),
                if (changeCandidate) ByteArray(32) { 99 } else f.update,
                if (changeCandidate) 1u else 2u, 0u, request.action)
            val reply = f.reply(other, progress = f.progress(other,
                update = other.updateID.copyBytes(), generation = other.generation))
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
        }
    }

    @Test fun anApplyReplyPreservesUnknownConsumptionEvenWhenTheCurrentRevisionAdvanced() {
        val f = Fixture(); val request = f.apply(); val age = UpdateSchedulingAge(f.nanos) { f.nanos }
        val reply = f.reply(request)
        val result = verifyPhoneUpdateSchedulingTooLate(f.record, f.record, request, reply.first, reply.second, age, 1000)
        assertEquals(1uL, result.response.progress.status.revision)
        assertEquals(UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, result.response.progress.status.requestedAction)
        assertNull(result.response.progress.status.controlDigest)
        assertTrue(result.response.matches(request, f.scope))
        val altered = request.signature.copyBytes(); altered[0] = (altered[0].toInt() xor 1).toByte()
        val other = PhoneUpdateSchedulingFrame.Apply(request.queryNonce.copyBytes(), request.canonicalControl.copyBytes(), altered)
        assertFails { verifyPhoneUpdateSchedulingTooLate(f.record, f.record, other, reply.first, reply.second, age, 1000) }
    }

    @Test fun originalDeadlineIncludesTimeBeforeTheReplyAndCannotBeRenewed() {
        val f = Fixture(); val query = f.query(); val reply = f.reply(query.requestFrame(f.record))
        f.nanos += 1_000_000_000
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
        f.nanos = 1_000_000
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
        val oldAge = UpdateSchedulingAge(f.nanos) { f.nanos }; val apply = f.apply(); val applied = f.reply(apply)
        f.nanos += 1_000_000_000
        assertFails { verifyPhoneUpdateSchedulingTooLate(f.record, f.record, apply, applied.first, applied.second, oldAge, 1000) }
    }

    @Test fun closingTheQueryBeforeVerificationCannotTransferAResult() {
        val f = Fixture(); val query = f.query(); val reply = f.reply(query.requestFrame(f.record))
        query.close()
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
    }

    @Test fun closingDuringTheFinalClockReadCannotPublishTheObservation() {
        val f = Fixture(); var armed = false; var reads = 0; lateinit var query: PhoneUpdateSchedulingQuery
        query = f.query {
            if (armed && ++reads == 3) query.close()
            f.nanos
        }
        val reply = f.reply(query.requestFrame(f.record)); armed = true
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(f.record, reply.first, reply.second) }
        assertEquals(3, reads)
    }

    @Test fun clockRegressionPermanentlyRetiresTheTransferredObservation() {
        val f = Fixture(); val query = f.query(); val reply = f.reply(query.requestFrame(f.record))
        val result = query.verifyTooLate(f.record, reply.first, reply.second)
        f.nanos += 10_000_000; assertEquals(10L, result.ageMilliseconds())
        f.nanos -= 1; assertNull(result.ageMilliseconds())
        f.nanos += 20_000_000; assertFalse(result.isFresh(1000)); assertNull(result.readyAgeUpperBoundMilliseconds())
    }

    @Test fun payloadCopiesAndExplicitClosureCannotMutateOrRenewTheObservation() {
        val f = Fixture(); val query = f.query(); val reply = f.reply(query.requestFrame(f.record))
        val result = query.verifyTooLate(f.record, reply.first, reply.second)
        reply.first.fill(0); reply.second.fill(0)
        assertEquals(UpdateSchedulingProgressPhase.CHECKING_RESTART, result.response.progress.phase)
        assertTrue(result.isFresh(1000)); result.close(); assertNull(result.ageMilliseconds())
        assertFalse(result.isFresh(1000)); assertNull(result.readyAgeUpperBoundMilliseconds())
    }

    @Test fun aChallengeAndTooLateCannotBothTransferFromOneQuery() {
        val f = Fixture(); val query = f.query(); val request = query.requestFrame(f.record)
        val late = f.reply(request)
        val control = f.apply().canonicalControl.copyBytes()
        val envelope = RootUpdateSchedulingChallenge(request.queryNonce.copyBytes(), control, controlLimits).encode(controlLimits)
        val signed = sign(f.root, RootUpdateSchedulingChallengeSigningInput.make(1u, envelope, controlLimits, signingLimits))
        val observation = query.verifyTooLate(f.record, late.first, late.second)
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verify(f.record, envelope, signed) }
        assertTrue(observation.isFresh(1000))
        val second = f.query(); val secondRequest = second.requestFrame(f.record)
        val matchingControl = UpdateSchedulingControl(id(20), id(21), id(3), id(4), id(6), ByteArray(32) { 7 },
            f.record.enrollment.decisionKey.keyID.copyBytes(), f.update, 1u, 0u, 1000u, 31_000u,
            secondRequest.action).encode(controlLimits)
        val challengePayload = RootUpdateSchedulingChallenge(secondRequest.queryNonce.copyBytes(), matchingControl, controlLimits)
            .encode(controlLimits)
        val challengeSignature = sign(f.root, RootUpdateSchedulingChallengeSigningInput.make(1u, challengePayload, controlLimits, signingLimits))
        val challenge = second.verify(f.record, challengePayload, challengeSignature)
        val secondLate = f.reply(secondRequest)
        assertFailsWith<PhoneUpdateSchedulingUnavailable> { second.verifyTooLate(f.record, secondLate.first, secondLate.second) }
        assertEquals(64, challenge.sign(f.record) { sign(f.decision, it) }.size)
    }

    @Test fun malformedOversizedOrChangedEnrollmentRepliesCannotTransfer() {
        for (invalid in 0..4) {
            val f = Fixture(); val query = f.query(); val reply = f.reply(query.requestFrame(f.record))
            val current = if (invalid == 0) Fixture().record else f.record
            val body = when (invalid) { 1 -> byteArrayOf(1); 2 -> ByteArray(8193); else -> reply.first }
            val signature = when (invalid) { 3 -> ByteArray(63); 4 -> ByteArray(65); else -> reply.second }
            assertFailsWith<PhoneUpdateSchedulingUnavailable> { query.verifyTooLate(current, body, signature) }
        }
    }
}
