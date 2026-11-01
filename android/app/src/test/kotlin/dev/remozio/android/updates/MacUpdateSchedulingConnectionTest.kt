package dev.remozio.android.updates

import dev.remozio.android.decisions.AndroidDecisionIdentity
import dev.remozio.android.decisions.DecisionKeySecurity
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.*
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class MacUpdateSchedulingConnectionTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private val controls = CborLimits(1024, 2, 32)
    private val replies = CborLimits(2048, 2, 32)
    private val signing = CborLimits(4096, 2, 32)

    private inner class Fixture(private val phone: Int = 3) {
        val root = key(); val decision = key(); val biometric = key()
        var nanos = 1_000_000L
        var opens = 0; var loads = 0; var signs = 0; var signerCloses = 0
        var applicationFrames = 0
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val enrollment = PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded, local(EnrollmentKeyRole.TRANSPORT, key()),
            local(EnrollmentKeyRole.DECISION, decision), local(EnrollmentKeyRole.BIOMETRIC, biometric), ByteArray(32) { 5 }, null)
        val record = StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE)
        var current = record
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        val updateID = ByteArray(32) { 8 }
        val wires = ArrayDeque<Wire>()
        var afterSign: () -> Unit = {}

        fun state(query: PhoneUpdateSchedulingFrame, revision: ULong = 0u, action: UpdateSchedulingAction? = null,
                  digest: ByteArray? = null, update: ByteArray = updateID): ByteArray {
            val payload = UpdateSchedulingStatusResponse(scope, query.queryNonce.copyBytes(), update, 1u,
                revision, action, digest).encode()
            return PhoneUpdateSchedulingFrame.StateResponse(query.queryNonce.copyBytes(), payload,
                sign(root, UpdateSchedulingStatusSigningInput.make(1u, payload, signing))).encode()
        }
        fun challenge(query: PhoneUpdateSchedulingFrame): ByteArray {
            val q = assertIs<PhoneUpdateSchedulingFrame.Challenge>(query)
            val control = UpdateSchedulingControl(id(20), id(21), id(phone), id(4), id(6), ByteArray(32) { 7 },
                enrollment.decisionKey.keyID.copyBytes(), q.updateID.copyBytes(), q.generation, q.revision,
                1000u, 31_000u, q.action).encode(controls)
            val payload = RootUpdateSchedulingChallenge(q.queryNonce.copyBytes(), control, replies).encode(replies)
            return PhoneUpdateSchedulingFrame.ChallengeResponse(q.queryNonce.copyBytes(), payload,
                sign(root, RootUpdateSchedulingChallengeSigningInput.make(1u, payload, replies, signing))).encode()
        }
        fun applied(query: PhoneUpdateSchedulingFrame): ByteArray {
            val q = assertIs<PhoneUpdateSchedulingFrame.Apply>(query)
            val bytes = q.canonicalControl.copyBytes()
            val control = UpdateSchedulingControl.decode(bytes, controls)
            assertTrue(UpdateSchedulingSignature.verify(q.signature.copyBytes(), enrollment.decisionKey.publicKey.copyBytes(),
                1u, bytes, controls, signing))
            return state(query, control.expectedRevision + 1u, control.action, MessageDigest.getInstance("SHA-256").digest(bytes))
        }
        suspend fun channel(reply: (PhoneUpdateSchedulingFrame) -> ByteArray): PhoneUpdateSchedulingChannel =
            syntheticUpdateSchedulingChannel(record, { nanos }, { current }) { query -> applicationFrames++; reply(query) }
        suspend fun status(): PhoneUpdateSchedulingStatus = channel { state(it) }.status()
        fun late(query: PhoneUpdateSchedulingFrame): ByteArray {
            val state = UpdateSchedulingStatusResponse(scope, query.queryNonce.copyBytes(), updateID, 1u, 1u,
                UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES)
            val progress = UpdateSchedulingProgressResponse(state, UpdateSchedulingProgressPhase.CHECKING_RESTART,
                UpdateSchedulingDesignation.THIS_ACCOUNT, UpdateSchedulingSecurityStatus.UNKNOWN, 100u, 0u,
                emptyList(), UpdateSchedulingAdmissionState.CLOSED)
            val body = UpdateSchedulingTooLateResponse(query, progress).encode()
            val signature = sign(root, UpdateSchedulingTooLateSigningInput.make(1u, body, CborLimits(8192, 2, 32)))
            return PhoneUpdateSchedulingFrameV2.TooLate(query.queryNonce.copyBytes(), body, signature).encode()
        }
        suspend fun lateChannel(reply: (PhoneUpdateSchedulingFrame) -> ByteArray = ::late) =
            syntheticUpdateSchedulingV2Channel(record, { nanos }, { current }) { applicationFrames++; reply(it) }
        fun lateChallengeWire(cleanup: suspend () -> Unit = {}) = Wire(
            challengeResult = { lateChannel().challengeResult(it) }, cleanup = cleanup)
        fun lateApplyWire(cleanup: suspend () -> Unit = {}) = Wire(
            applyResult = { challenge, signature -> lateChannel().applyResult(challenge, signature) }, cleanup = cleanup)
        fun owner() = MacUpdateSchedulingConnection(record, open = { _, _ -> opens++; wires.removeFirst() },
            loadSigner = {
                loads++
                val identity = AndroidDecisionIdentity(enrollment, decision.private, DecisionKeySecurity.TRUSTED_ENVIRONMENT)
                object : UpdateSchedulingDecisionSigner {
                    override fun sign(challenge: PhoneUpdateSchedulingChallenge, current: StoredPhoneEnrollment): ByteArray {
                        signs++
                        return identity.signUpdateScheduling(challenge, current).also { afterSign() }
                    }
                    override fun close() { signerCloses++; identity.close() }
                }
            }, currentEnrollment = { current }, elapsedRealtimeNanos = { nanos }, freshnessMillis = { 1000 },
            timeoutMillis = { 5000 }, dispatcher = Dispatchers.Unconfined)
        fun statusWire() = Wire(status = { status() })
        fun challengeWire(cleanup: suspend () -> Unit = {}) = Wire(challenge = { channel(::challenge).challenge(it) }, cleanup = cleanup)
        fun applyWire(cleanup: suspend () -> Unit = {}) = Wire(apply = { challenge, signature ->
            channel(::applied).apply(challenge, signature)
        }, cleanup = cleanup)
    }

    private class Wire(
        private val status: suspend () -> PhoneUpdateSchedulingStatus = { error("Unexpected status") },
        private val challenge: suspend (PhoneUpdateSchedulingQuery) -> PhoneUpdateSchedulingChallenge = { error("Unexpected challenge") },
        private val apply: suspend (PhoneUpdateSchedulingChallenge, ByteArray) -> PhoneUpdateSchedulingStatus = { _, _ -> error("Unexpected apply") },
        private val challengeResult: (suspend (PhoneUpdateSchedulingQuery) -> PhoneUpdateSchedulingChallengeResult)? = null,
        private val applyResult: (suspend (PhoneUpdateSchedulingChallenge, ByteArray) -> PhoneUpdateSchedulingApplyResult)? = null,
        private val cleanup: suspend () -> Unit = {},
    ) : MacUpdateSchedulingWire {
        var closes = 0; var challenges = 0; var applies = 0
        override suspend fun status() = status.invoke()
        override suspend fun challenge(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallenge { challenges++; return challenge.invoke(query) }
        override suspend fun apply(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingStatus {
            applies++; return apply.invoke(challenge, signature)
        }
        override suspend fun challengeResult(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallengeResult {
            val body = challengeResult ?: return super.challengeResult(query)
            challenges++; return body(query)
        }
        override suspend fun applyResult(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingApplyResult {
            val body = applyResult ?: return super.applyResult(challenge, signature)
            applies++; return body(challenge, signature)
        }
        override fun close() { closes++ }
        override suspend fun closeAndJoin() { close(); cleanup() }
    }

    @Test fun signedStatusNeedsNoDecisionKeyAndSleepMakesItLastKnown() = runTest {
        val f = Fixture(); val owner = f.owner(); f.wires.add(f.statusWire())
        assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        assertTrue(owner.canSchedule(observed)); assertEquals(0, f.loads)
        f.nanos += 1_000_000_000
        assertFalse(owner.canSchedule(observed)); assertEquals(MacUpdateSchedulingAvailability.OFFLINE, owner.snapshot().availability)
        assertSame(observed, owner.snapshot().observation); owner.close()
    }

    @Test fun eachExplicitActionUsesOneOriginalChoiceOneSignatureAndOneApply() = runTest {
        for (action in UpdateSchedulingAction.entries) {
            val f = Fixture(); val owner = f.owner(); val prepare = f.challengeWire(); val apply = f.applyWire()
            f.wires.addAll(listOf(f.statusWire(), prepare, apply)); assertTrue(owner.refresh())
            val observed = assertNotNull(owner.snapshot().observation)
            assertTrue(owner.schedule(observed, action))
            assertEquals(action, owner.snapshot().attempt?.action)
            assertEquals(MacUpdateSchedulingOutcome.ACKNOWLEDGED, owner.snapshot().attempt?.outcome)
            assertEquals(1uL, owner.snapshot().observation?.response?.revision)
            assertEquals(0uL, owner.snapshot().attempt?.revision)
            assertEquals(1, prepare.challenges); assertEquals(1, apply.applies)
            assertEquals(1, f.loads); assertEquals(1, f.signs); assertEquals(1, f.signerCloses); assertEquals(3, f.opens)
            assertFalse(observed.isFresh(1000)); owner.close()
        }
    }

    @Test fun anOldDisplayedObservationCannotSelectANewerUpdateOrRetryAChoice() = runTest {
        val f = Fixture(); val owner = f.owner(); f.wires.add(f.statusWire()); assertTrue(owner.refresh())
        val old = assertNotNull(owner.snapshot().observation)
        f.wires.add(f.statusWire()); assertTrue(owner.refresh())
        assertFalse(owner.schedule(old, UpdateSchedulingAction.CANCEL_DRAIN)); assertEquals(2, f.opens)
        val current = assertNotNull(owner.snapshot().observation)
        val refused = Wire(challenge = { error("Root refused the control") }); f.wires.add(refused)
        assertFalse(owner.schedule(current, UpdateSchedulingAction.DEFER_UPDATE))
        assertEquals(MacUpdateSchedulingOutcome.FAILED, owner.snapshot().attempt?.outcome)
        assertFalse(owner.canSchedule(current)); assertFalse(owner.schedule(current, UpdateSchedulingAction.DEFER_UPDATE))
        assertEquals(1, refused.challenges); assertEquals(0, f.loads); owner.close()
    }

    @Test fun lostAcknowledgmentStaysUncertainAndAStatusReadNeverReplaysTheControl() = runTest {
        val f = Fixture(); val owner = f.owner(); val lost = Wire(apply = { _, _ -> error("Lost acknowledgment") })
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), lost)); assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        assertFalse(owner.schedule(observed, UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES))
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, owner.snapshot().attempt?.outcome)
        assertFalse(owner.canSchedule(observed)); assertFalse(owner.schedule(observed, UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES))
        f.wires.add(f.statusWire()); assertTrue(owner.refresh())
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, owner.snapshot().attempt?.outcome)
        assertEquals(1, lost.applies); assertEquals(1, f.signs); owner.close()
    }

    @Test fun enrollmentChangeAfterSigningCannotOpenTheApplyWire() = runTest {
        val f = Fixture(); val owner = f.owner(); f.wires.addAll(listOf(f.statusWire(), f.challengeWire()))
        assertTrue(owner.refresh()); val observed = assertNotNull(owner.snapshot().observation)
        f.afterSign = { f.current = StoredPhoneEnrollment(f.enrollment, EnrollmentPhase.PREPARED) }
        assertFalse(owner.schedule(observed, UpdateSchedulingAction.CANCEL_DRAIN))
        assertEquals(2, f.opens); assertEquals(1, f.signs); assertEquals(1, f.signerCloses)
        assertEquals(MacUpdateSchedulingOutcome.FAILED, owner.snapshot().attempt?.outcome); owner.close()
    }

    @Test fun aForeignOrRevokedStatusCannotBePublished() = runTest {
        for (foreign in listOf(false, true)) {
            val f = Fixture(); val owner = f.owner(); val value = if (foreign) Fixture(99).status() else f.status()
            val wire = Wire(status = {
                if (!foreign) f.current = StoredPhoneEnrollment(f.enrollment, EnrollmentPhase.PREPARED)
                value
            }); f.wires.add(wire)
            assertFalse(owner.refresh()); assertNull(owner.snapshot().observation); assertFalse(value.isFresh(1000))
            assertEquals(1, wire.closes); assertEquals(0, f.loads); owner.close()
        }
    }

    @Test fun anExpiredSignedChallengeCannotSendAControl() = runTest {
        val f = Fixture(); val owner = f.owner(); f.wires.addAll(listOf(f.statusWire(), f.challengeWire()))
        assertTrue(owner.refresh()); val observed = assertNotNull(owner.snapshot().observation)
        f.afterSign = { f.nanos += 30_000_000_000 }
        val apply = f.applyWire(); f.wires.add(apply)
        assertFalse(owner.schedule(observed, UpdateSchedulingAction.DEFER_UPDATE))
        assertEquals(1, apply.applies); assertEquals(1, f.signs)
        assertEquals(2, f.applicationFrames)
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, owner.snapshot().attempt?.outcome); owner.close()
    }

    @Test fun cancellationRetainsUncertaintyAndConcurrentWorkNeverQueues() = runTest {
        val f = Fixture(); val owner = f.owner(); val entered = CompletableDeferred<Unit>()
        val blocked = Wire(apply = { _, _ -> entered.complete(Unit); awaitCancellation() })
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), blocked)); assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        val action = async { owner.schedule(observed, UpdateSchedulingAction.CANCEL_DRAIN) }; entered.await()
        assertFalse(owner.refresh()); assertFalse(owner.schedule(observed, UpdateSchedulingAction.CANCEL_DRAIN))
        action.cancelAndJoin()
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, owner.snapshot().attempt?.outcome)
        assertEquals(1, blocked.applies); assertEquals(1, f.signerCloses); owner.close()
    }

    @Test fun retirementCancelsTheOwnedWireAndWithholdsALateStatus() = runTest {
        val f = Fixture(); val owner = f.owner(); val entered = CompletableDeferred<Unit>()
        val blocked = Wire(status = { entered.complete(Unit); awaitCancellation() }); f.wires.add(blocked)
        val refresh = async { owner.refresh() }; entered.await(); owner.close(); refresh.join()
        assertTrue(refresh.isCancelled); assertTrue(blocked.closes >= 1)
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, owner.snapshot().availability)
        assertNull(owner.snapshot().observation); assertFails { owner.refresh() }
    }

    @Test fun aChallengeCleanupFailureRetiresTheChallengeBeforeDecisionCustodyLoads() = runTest {
        val f = Fixture(); val owner = f.owner(); var captured: PhoneUpdateSchedulingChallenge? = null
        val broken = Wire(challenge = { query -> f.channel(f::challenge).challenge(query).also { captured = it } },
            cleanup = { error("Cleanup failed") })
        f.wires.addAll(listOf(f.statusWire(), broken)); assertTrue(owner.refresh())
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.DEFER_UPDATE))
        assertEquals(0, f.loads)
        assertFails { assertNotNull(captured).sign(f.record) { sign(f.decision, it) } }
        assertFails { owner.refresh() }; assertFails { owner.close() }
    }

    @Test fun cleanupFailureCannotEraseAnAuthenticatedAcknowledgment() = runTest {
        val f = Fixture(); val owner = f.owner()
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), f.applyWire { error("Cleanup failed") }))
        assertTrue(owner.refresh())
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.CANCEL_DRAIN))
        assertEquals(MacUpdateSchedulingOutcome.ACKNOWLEDGED, owner.snapshot().attempt?.outcome)
        assertEquals(1uL, owner.snapshot().observation?.response?.revision)
        assertEquals(MacUpdateSchedulingAvailability.OFFLINE, owner.snapshot().availability)
        assertEquals(1, f.signerCloses); assertFails { owner.refresh() }; assertFails { owner.close() }
    }

    @Test fun revocationBeforeAnotherChoiceCannotRelabelTheEarlierAcknowledgment() = runTest {
        val f = Fixture(); val owner = f.owner()
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), f.applyWire())); assertTrue(owner.refresh())
        assertTrue(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.DEFER_UPDATE))
        val acknowledged = assertNotNull(owner.snapshot().attempt)
        f.current = StoredPhoneEnrollment(f.enrollment, EnrollmentPhase.PREPARED)
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.CANCEL_DRAIN))
        assertSame(acknowledged, owner.snapshot().attempt); assertEquals(3, f.opens); owner.close()
    }

    @Test fun cancellingAScreenWaiterDoesNotCancelTheApplicationOwnedControl() = runTest {
        val f = Fixture(); val owner = f.owner(); val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val apply = Wire(apply = { challenge, signature -> entered.complete(Unit); release.await(); f.channel(f::applied).apply(challenge, signature) })
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), apply)); assertTrue(owner.refresh())
        val operation = applicationMacUpdateScheduling(backgroundScope, owner, assertNotNull(owner.snapshot().observation),
            UpdateSchedulingAction.DEFER_UPDATE)
        val waiter = launch(start = CoroutineStart.UNDISPATCHED) { operation.await() }
        entered.await(); waiter.cancelAndJoin(); assertTrue(operation.isActive)
        release.complete(Unit); assertTrue(operation.await())
        assertEquals(MacUpdateSchedulingOutcome.ACKNOWLEDGED, owner.snapshot().attempt?.outcome)
        assertEquals(1, apply.applies); assertEquals(1, f.signs); owner.close()
    }

    @Test fun tooLateBeforeTheChallengePublishesProgressWithoutLoadingDecisionCustody() = runTest {
        val f = Fixture(); val owner = f.owner(); val late = f.lateChallengeWire()
        f.wires.addAll(listOf(f.statusWire(), late)); assertTrue(owner.refresh())
        val displayed = assertNotNull(owner.snapshot().observation)
        assertFalse(owner.schedule(displayed, UpdateSchedulingAction.CANCEL_DRAIN))
        val state = owner.snapshot(); assertNull(state.observation)
        val progress = assertNotNull(state.tooLate)
        assertTrue(progress.isFresh(1000)); assertFalse(displayed.isFresh(1000))
        assertEquals(MacUpdateSchedulingOutcome.FAILED, state.attempt?.outcome)
        assertEquals(MacUpdateSchedulingAvailability.ONLINE, state.availability)
        assertEquals(0, f.loads); assertEquals(0, f.signs); assertEquals(0, late.applies)
        assertFalse(owner.canSchedule(displayed)); assertFalse(owner.schedule(displayed, UpdateSchedulingAction.CANCEL_DRAIN))
        assertEquals(2, f.opens); assertEquals(1, late.closes); owner.close(); assertFalse(progress.isFresh(1000))
    }

    @Test fun applyTooLateCannotTurnMatchingCurrentProgressIntoAnAcknowledgment() = runTest {
        val f = Fixture(); val owner = f.owner(); val late = f.lateApplyWire()
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), late)); assertTrue(owner.refresh())
        val displayed = assertNotNull(owner.snapshot().observation)
        assertFalse(owner.schedule(displayed, UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES))
        val state = owner.snapshot(); val progress = assertNotNull(state.tooLate)
        assertEquals(1uL, progress.response.progress.status.revision)
        assertEquals(state.attempt?.action, progress.response.progress.status.requestedAction)
        assertNull(progress.response.progress.status.controlDigest)
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, state.attempt?.outcome)
        assertNull(state.observation); assertEquals(1, late.applies); assertEquals(1, f.signs); assertEquals(1, f.signerCloses)
        assertFalse(owner.canSchedule(displayed)); owner.close()
    }

    @Test fun ordinaryStatusCannotEraseIrreversibilityOrRefreshItsOriginalAge() = runTest {
        val f = Fixture(); val owner = f.owner()
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), f.lateApplyWire())); assertTrue(owner.refresh())
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES))
        val progress = assertNotNull(owner.snapshot().tooLate); f.nanos += 200_000_000
        f.wires.add(f.statusWire()); assertTrue(owner.refresh())
        val state = owner.snapshot(); assertSame(progress, state.tooLate); assertEquals(200L, progress.ageMilliseconds())
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, state.attempt?.outcome)
        assertFalse(owner.canSchedule(assertNotNull(state.observation)))
        f.nanos += 800_000_000
        assertEquals(MacUpdateSchedulingAvailability.OFFLINE, owner.snapshot().availability)
        owner.close()
    }

    @Test fun aNewSignedCandidateRetiresOldProgressAndKeepsTheEarlierUnknownOutcome() = runTest {
        val f = Fixture(); val owner = f.owner()
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), f.lateApplyWire())); assertTrue(owner.refresh())
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.DEFER_UPDATE))
        val old = assertNotNull(owner.snapshot().tooLate)
        f.wires.add(Wire(status = { f.channel { f.state(it, update = ByteArray(32) { 99 }) }.status() }))
        assertTrue(owner.refresh()); val state = owner.snapshot()
        assertNull(state.tooLate); assertFalse(old.isFresh(1000))
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, state.attempt?.outcome)
        assertTrue(owner.canSchedule(assertNotNull(state.observation))); owner.close()
    }

    @Test fun challengeTooLateCleanupFailureCannotPublishOrLoadDecisionCustody() = runTest {
        val f = Fixture(); val owner = f.owner(); val late = f.lateChallengeWire { error("Cleanup failed") }
        f.wires.addAll(listOf(f.statusWire(), late)); assertTrue(owner.refresh())
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.CANCEL_DRAIN))
        assertNull(owner.snapshot().tooLate); assertEquals(MacUpdateSchedulingOutcome.FAILED, owner.snapshot().attempt?.outcome)
        assertEquals(0, f.loads); assertEquals(1, late.closes); assertFails { owner.refresh() }; assertFails { owner.close() }
    }

    @Test fun applyTooLateCleanupFailurePreservesUncertaintyAndDisablesFurtherWork() = runTest {
        val f = Fixture(); val owner = f.owner()
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), f.lateApplyWire { error("Cleanup failed") }))
        assertTrue(owner.refresh()); assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.DEFER_UPDATE))
        val state = owner.snapshot(); assertNotNull(state.tooLate)
        assertEquals(MacUpdateSchedulingOutcome.UNCERTAIN, state.attempt?.outcome)
        assertEquals(MacUpdateSchedulingAvailability.OFFLINE, state.availability)
        assertEquals(1, f.signerCloses); assertFails { owner.refresh() }; assertFails { owner.close() }
    }

    @Test fun revokedEnrollmentCannotPublishAValidTooLateReply() = runTest {
        val f = Fixture(); val owner = f.owner()
        val late = Wire(challengeResult = { query -> f.lateChannel {
            f.current = StoredPhoneEnrollment(f.enrollment, EnrollmentPhase.PREPARED); f.late(it)
        }.challengeResult(query) })
        f.wires.addAll(listOf(f.statusWire(), late)); assertTrue(owner.refresh())
        assertFalse(owner.schedule(assertNotNull(owner.snapshot().observation), UpdateSchedulingAction.CANCEL_DRAIN))
        assertNull(owner.snapshot().tooLate); assertEquals(0, f.loads); assertEquals(1, late.challenges); owner.close()
    }

    @Test fun retirementDuringTooLateCleanupClosesTheObservationAndWaitsForTheOwnedOperation() = runTest {
        val f = Fixture(); val owner = f.owner(); val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val late = f.lateApplyWire { entered.complete(Unit); release.await() }
        f.wires.addAll(listOf(f.statusWire(), f.challengeWire(), late)); assertTrue(owner.refresh())
        val displayed = assertNotNull(owner.snapshot().observation)
        val operation = async { owner.schedule(displayed, UpdateSchedulingAction.DEFER_UPDATE) }; entered.await()
        val progress = assertNotNull(owner.snapshot().tooLate); owner.close()
        assertFalse(owner.retirementSettled()); assertFalse(progress.isFresh(1000))
        release.complete(Unit); operation.join(); assertTrue(owner.retirementSettled())
        assertEquals(MacUpdateSchedulingAvailability.CLOSED, owner.snapshot().availability)
        assertNull(owner.snapshot().tooLate); assertEquals(1, late.applies); assertEquals(1, f.signs)
    }
}
