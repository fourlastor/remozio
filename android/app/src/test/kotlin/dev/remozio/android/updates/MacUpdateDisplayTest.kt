package dev.remozio.android.updates

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.*
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.phone.updates.PhoneUpdateSchedulingTooLateObservation
import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.*
import kotlinx.coroutines.test.runTest
import org.junit.Test

class MacUpdateDisplayTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private inner class Fixture {
        val root = key()
        var nanos = 1_000_000L
        val update = ByteArray(32) { 8 }
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio." + role.aliasPart + ".v1." + "%032x".format(role.ordinal + 10),
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(3), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, key()),
            local(EnrollmentKeyRole.BIOMETRIC, key()), ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        val scope = ChannelScope(id(20), id(21), id(3), id(4))
        suspend fun progress(
            phase: UpdateSchedulingProgressPhase = UpdateSchedulingProgressPhase.READY,
            designation: UpdateSchedulingDesignation = UpdateSchedulingDesignation.THIS_ACCOUNT,
            actions: ULong = 3u,
            generation: ULong = 1u,
            revision: ULong = 0u,
            action: UpdateSchedulingAction? = null,
            readyAge: ULong? = 100u,
            blockers: List<UpdateSchedulingBlocker> = emptyList(),
            delayNanos: Long = 0,
        ): PhoneUpdateProgressObservation = syntheticUpdateProgressChannel(record, { nanos }, { record }) { query ->
            nanos += delayNanos
            val status = UpdateSchedulingStatusResponse(scope, query.queryNonce.copyBytes(), update, generation, revision, action)
            val body = UpdateSchedulingProgressResponse(status, phase, designation, UpdateSchedulingSecurityStatus.SECURITY,
                readyAge, actions, blockers, if (phase == UpdateSchedulingProgressPhase.DRAINING || phase.irreversible)
                    UpdateSchedulingAdmissionState.CLOSED else UpdateSchedulingAdmissionState.OPEN).encode()
            PhoneUpdateProgressFrame.Response(query.queryNonce.copyBytes(), body,
                sign(root, UpdateSchedulingProgressSigningInput.make(1u, body, CborLimits(8192, 2, 32)))).encode()
        }.read()
        suspend fun status(generation: ULong = 1u, revision: ULong = 0u, action: UpdateSchedulingAction? = null): PhoneUpdateSchedulingStatus =
            syntheticUpdateSchedulingChannel(record, { nanos }, { record }) { query ->
                val body = UpdateSchedulingStatusResponse(scope, query.queryNonce.copyBytes(), update, generation, revision, action).encode()
                PhoneUpdateSchedulingFrame.StateResponse(query.queryNonce.copyBytes(), body,
                    sign(root, UpdateSchedulingStatusSigningInput.make(1u, body, CborLimits(8192, 2, 32)))).encode()
            }.status()
        suspend fun late(revision: ULong = 1u): PhoneUpdateSchedulingTooLateObservation {
            val query = PhoneUpdateSchedulingQuery.begin(record, update, 1u, 0u,
                UpdateSchedulingAction.CANCEL_DRAIN, { nanos }, 5000)
            try {
                val channel = syntheticUpdateSchedulingV2Channel(record, { nanos }, { record }) { request ->
                    val status = UpdateSchedulingStatusResponse(scope, request.queryNonce.copyBytes(), update, 1u, revision,
                        UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES)
                    val progress = UpdateSchedulingProgressResponse(status, UpdateSchedulingProgressPhase.ACTIVATING,
                        UpdateSchedulingDesignation.THIS_ACCOUNT, UpdateSchedulingSecurityStatus.SECURITY, 100u, 0u,
                        emptyList(), UpdateSchedulingAdmissionState.CLOSED)
                    val body = UpdateSchedulingTooLateResponse(request, progress).encode()
                    PhoneUpdateSchedulingFrameV2.TooLate(request.queryNonce.copyBytes(), body,
                        sign(root, UpdateSchedulingTooLateSigningInput.make(1u, body, CborLimits(8192, 2, 32)))).encode()
                }
                return (channel.challengeResult(query) as PhoneUpdateSchedulingChallengeResult.TooLate).observation
            } finally { query.close() }
        }
        fun display(progress: PhoneUpdateProgressObservation? = null, status: PhoneUpdateSchedulingStatus? = null,
            progressAvailable: MacUpdateProgressAvailability = MacUpdateProgressAvailability.ONLINE,
            schedulingAvailable: MacUpdateSchedulingAvailability = MacUpdateSchedulingAvailability.ONLINE,
            attempt: MacUpdateSchedulingAttempt? = null, late: PhoneUpdateSchedulingTooLateObservation? = null,
            canSchedule: Boolean = true, canOffer: Boolean = true) =
            macUpdateDisplay(record, MacUpdateProgressState(progressAvailable, progress),
                MacUpdateSchedulingState(schedulingAvailable, status, attempt, late), 1000, canSchedule) { canOffer }
        fun attempt(outcome: MacUpdateSchedulingOutcome) = MacUpdateSchedulingAttempt(CborValue.Bytes(update), 1u, 0u,
            UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, outcome)
    }
    private fun assertNoActions(display: MacUpdateDisplay) {
        assertFalse(display.canInstall); assertFalse(display.canDefer); assertFalse(display.canCancelDrain)
    }

    @Test fun absentObservationsCannotClaimCurrentStatusOrActions() {
        val model = Fixture().display()
        assertNull(model.current); assertNull(model.lastKnown); assertNull(model.sampleAgeMilliseconds)
        assertNoActions(model)
    }
    @Test fun coherentFreshObservationsOfferOnlyTheRootActions() = runTest {
        val f = Fixture(); val progress = f.progress(); val model = f.display(progress, f.status())
        assertSame(progress.response, model.current); assertNull(model.lastKnown)
        assertTrue(model.canInstall); assertTrue(model.canDefer); assertFalse(model.canCancelDrain)
    }
    @Test fun otherUnassignedAndUnknownOwnersCannotDefer() = runTest {
        val f = Fixture()
        for (designation in listOf(UpdateSchedulingDesignation.OTHER_ACCOUNT, UpdateSchedulingDesignation.UNASSIGNED,
            UpdateSchedulingDesignation.UNKNOWN)) {
            val model = f.display(f.progress(designation = designation, actions = 1u), f.status())
            assertTrue(model.canInstall); assertFalse(model.canDefer)
        }
    }
    @Test fun neitherDisplayNorOwnerPermissionCanCreateAnAbsentRootAction() = runTest {
        val f = Fixture(); assertNoActions(f.display(f.progress(actions = 0u), f.status()))
    }
    @Test fun displayNeverBroadensEitherConnectionOwnersEligibility() = runTest {
        val f = Fixture(); val progress = f.progress(); val status = f.status()
        assertNoActions(f.display(progress, status, canSchedule = false))
        assertNoActions(f.display(progress, status, canOffer = false))
    }
    @Test fun exactFreshnessBoundaryMovesAllProgressToLastKnown() = runTest {
        val f = Fixture(); val progress = f.progress(); val status = f.status()
        f.nanos += 1_000_000_000
        val model = f.display(progress, status)
        assertNull(model.current); assertSame(progress.response, model.lastKnown); assertNoActions(model)
    }
    @Test fun unavailableProgressOwnersDoNotPromoteRecentSamplesToCurrentFacts() = runTest {
        val f = Fixture(); val progress = f.progress(); val status = f.status()
        for (availability in listOf(MacUpdateProgressAvailability.UNKNOWN, MacUpdateProgressAvailability.OFFLINE,
            MacUpdateProgressAvailability.CLOSED)) {
            val model = f.display(progress, status, progressAvailable = availability)
            assertNull(model.current); assertSame(progress.response, model.lastKnown); assertNoActions(model)
        }
    }
    @Test fun aFreshProgressReadCannotRefreshAnOlderSchedulingObservation() = runTest {
        val f = Fixture(); val status = f.status(); f.nanos += 1_000_000_000
        val model = f.display(f.progress(), status)
        assertNotNull(model.current); assertNoActions(model)
    }
    @Test fun freshRevisionGenerationAndActionMismatchesDisableEveryControl() = runTest {
        val f = Fixture(); val progress = f.progress()
        assertNoActions(f.display(progress, f.status(generation = 2u)))
        assertNoActions(f.display(progress, f.status(revision = 1u, action = UpdateSchedulingAction.DEFER_UPDATE)))
    }
    @Test fun anotherEnrollmentCannotSupplyCurrentOrCachedProgress() = runTest {
        val f = Fixture(); val foreign = Fixture()
        val model = f.display(foreign.progress(), foreign.status())
        assertNull(model.current); assertNull(model.lastKnown); assertNoActions(model)
    }
    @Test fun aNewSignedStatusNeverAcknowledgesAnEarlierUnknownControl() = runTest {
        val f = Fixture(); val attempt = f.attempt(MacUpdateSchedulingOutcome.UNCERTAIN)
        val model = f.display(f.progress(), f.status(), attempt = attempt)
        assertNotNull(model.current); assertSame(attempt, model.attempt)
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, model.attempt?.outcome)
    }
    @Test fun aSubmittingControlDisablesEveryOtherChoice() = runTest {
        val f = Fixture(); assertNoActions(f.display(f.progress(), f.status(), attempt = f.attempt(MacUpdateSchedulingOutcome.SUBMITTING)))
    }
    @Test fun aFailedClockCannotRecoverTheSameSampleAsFresh() = runTest {
        val f = Fixture(); val progress = f.progress(); val status = f.status(); f.nanos = 0
        val invalid = f.display(progress, status)
        assertNull(invalid.current); assertNull(invalid.sampleAgeMilliseconds); assertNoActions(invalid)
        f.nanos = 2_000_000
        val later = f.display(progress, status)
        assertNull(later.current); assertNull(later.sampleAgeMilliseconds); assertNoActions(later)
    }
    @Test fun readyAndBlockerAgesIncludeTheOriginalQueryLifetime() = runTest {
        val f = Fixture(); val progress = f.progress(delayNanos = 250_000_000,
            blockers = listOf(UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.ACTIVE_COMMANDS, 2u, 50u)))
        val model = f.display(progress, f.status())
        assertEquals(250L, model.sampleAgeMilliseconds); assertEquals(350uL, model.readyAgeMilliseconds)
        assertEquals(300uL, model.blockers.single().oldestAgeMilliseconds)
    }
    @Test fun overflowingAgesRemainUnknownInsteadOfWrappingToYoungWork() = runTest {
        val f = Fixture(); val model = f.display(f.progress(readyAge = ULong.MAX_VALUE, delayNanos = 1_000_000,
            blockers = listOf(UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.ACTIVE_COMMANDS, 1u, ULong.MAX_VALUE))), f.status())
        assertNull(model.readyAgeMilliseconds); assertNull(model.blockers.single().oldestAgeMilliseconds)
    }
    @Test fun otherAccountBlockersNeverGainAnInventedCountOrAge() = runTest {
        val f = Fixture(); val model = f.display(f.progress(blockers = listOf(
            UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.OTHER_ACCOUNTS, null, null))), f.status())
        assertNull(model.blockers.single().count); assertNull(model.blockers.single().oldestAgeMilliseconds)
    }
    @Test fun tooLateDominatesAnEarlierNonIrreversibleProgressFrame() = runTest {
        val f = Fixture(); val progress = f.progress(revision = 2u, action = UpdateSchedulingAction.DEFER_UPDATE)
        val model = f.display(progress, f.status(), late = f.late(revision = 1u))
        assertEquals(UpdateSchedulingProgressPhase.ACTIVATING, model.current?.phase)
        assertTrue(model.tooLate); assertNoActions(model)
    }
    @Test fun progressForANewCandidateDoesNotInheritOldTooLateOrResolveTheOldAttempt() = runTest {
        val f = Fixture(); val late = f.late(); val attempt = f.attempt(MacUpdateSchedulingOutcome.UNCERTAIN)
        val model = f.display(f.progress(generation = 2u), f.status(generation = 2u), attempt = attempt, late = late)
        assertEquals(2uL, model.current?.status?.generation); assertFalse(model.tooLate)
        assertSame(attempt, model.attempt); assertNoActions(model)
    }
    @Test fun laterIrreversibleProgressCanAdvanceWithoutRevivingControls() = runTest {
        val f = Fixture(); val late = f.late()
        val model = f.display(f.progress(phase = UpdateSchedulingProgressPhase.COMPLETED, actions = 0u,
            revision = 2u, action = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES), late = late)
        assertEquals(UpdateSchedulingProgressPhase.COMPLETED, model.current?.phase)
        assertTrue(model.tooLate); assertNoActions(model)
    }
    @Test fun expiredTooLateRemainsLastKnownAndCannotAcknowledgeTheEarlierRequest() = runTest {
        val f = Fixture(); val late = f.late(); val attempt = f.attempt(MacUpdateSchedulingOutcome.UNCERTAIN)
        f.nanos += 1_000_000_000
        val model = f.display(late = late, attempt = attempt)
        assertNull(model.current); assertEquals(UpdateSchedulingProgressPhase.ACTIVATING, model.lastKnown?.phase)
        assertTrue(model.tooLate); assertSame(attempt, model.attempt); assertNoActions(model)
    }
    @Test fun aLiveDrainOffersCancelOnlyWhenRootAllowsAndTheStatusMatches() = runTest {
        val f = Fixture(); val action = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES
        val model = f.display(f.progress(phase = UpdateSchedulingProgressPhase.DRAINING, actions = 4u,
            revision = 1u, action = action), f.status(revision = 1u, action = action))
        assertTrue(model.canCancelDrain); assertFalse(model.canInstall); assertFalse(model.canDefer)
    }
    @Test fun cancelledDrainDoesNotMeanTheUpdateWasInstalled() = runTest {
        val f = Fixture(); val model = f.display(f.progress(phase = UpdateSchedulingProgressPhase.CANCELLED, actions = 1u), f.status())
        assertEquals(UpdateSchedulingProgressPhase.CANCELLED, model.current?.phase)
        assertTrue(model.canInstall); assertFalse(model.canDefer); assertFalse(model.canCancelDrain)
    }
    @Test fun descriptionsNeverExposeSignedProgressOrRequestIdentifiers() = runTest {
        val f = Fixture(); val model = f.display(f.progress(), f.status())
        assertEquals("MacUpdateDisplay(redacted)", model.toString())
    }
}
