package dev.sebastiano.remozio.android.routing

import dev.sebastiano.remozio.android.decisions.AndroidDecisionIdentity
import dev.sebastiano.remozio.android.decisions.DecisionIdentityUnavailable
import dev.sebastiano.remozio.android.decisions.DecisionKeySecurity
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.*
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

class MacRoutingConnectionTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(pair: KeyPair, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(pair.private); update(bytes); sign()
    }
    private inner class Fixture(private val phone: Int = 3) {
        val root = key(); val decision = key(); val biometric = key()
        var nanos = 1_000_000L; var current = true; var opens = 0; var loads = 0; var signs = 0; var signerCloses = 0
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val enrollment = PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, decision), local(EnrollmentKeyRole.BIOMETRIC, biometric),
            ByteArray(32) { 5 }, null)
        val record = StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE)
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        val wires = ArrayDeque<Wire>()
        var prepared: PhoneRoutingResult.Verified? = null
        val inputLimits = CborLimits(3200, 2, 16)
        fun control(): ByteArray = RoutingAwayControl(id(20), id(21), id(phone), id(4), id(6), ByteArray(32) { 7 },
            enrollment.decisionKey.keyID.copyBytes(), 0u, 1000u, 31_000u).encode(CborLimits(1024, 2, 32))
        suspend fun result(outcome: RoutingStatusOutcome = RoutingStatusOutcome.STATUS,
                           mode: RoutingStatusMode = RoutingStatusMode.PRESENT, revision: ULong = 0u): PhoneRoutingResult.Verified {
            val nonce = ByteArray(32) { 31 }
            val control = if (outcome == RoutingStatusOutcome.CHALLENGE) control() else null
            val digest = if (outcome == RoutingStatusOutcome.APPLIED) MessageDigest.getInstance("SHA-256").digest(control()) else null
            val body = RoutingStatusResponse(scope, nonce, outcome, id(30), 100u,
                RoutingStatusState(mode, revision, if (mode == RoutingStatusMode.AWAY) RoutingStatusDestination.PHONES else RoutingStatusDestination.LOCAL_MAC,
                    if (mode == RoutingStatusMode.AWAY) RoutingStatusReason.MANUAL_AWAY else RoutingStatusReason.MANUAL_PRESENT, false),
                control, digest, if (outcome == RoutingStatusOutcome.APPLIED) 1u else null)
            val query = when (outcome) {
                RoutingStatusOutcome.CHALLENGE, RoutingStatusOutcome.CONFLICT -> PhoneRoutingFrame.Challenge(nonce, 0u)
                RoutingStatusOutcome.APPLIED -> PhoneRoutingFrame.Apply(nonce, control(), sign(decision,
                    RoutingAwaySigningInput.make(1u, control(), CborLimits(1024, 2, 32), inputLimits)))
                else -> PhoneRoutingFrame.Status(nonce)
            }
            return verifiedSyntheticRouting(record, root.private, body, { nanos }, query, prepared?.challenge)
                .also { if (outcome == RoutingStatusOutcome.CHALLENGE) prepared = it }
        }
        fun identity(pair: KeyPair = decision) = AndroidDecisionIdentity(enrollment, pair.private, DecisionKeySecurity.TRUSTED_ENVIRONMENT)
        fun owner(afterSign: () -> Unit = {}): MacRoutingConnection = MacRoutingConnection(record,
            open = { _, _ -> opens++; wires.removeFirst() }, loadSigner = {
                loads++; val identity = identity()
                object : RoutingDecisionSigner {
                    override fun sign(challenge: PhoneRoutingChallenge): ByteArray {
                        signs++; return identity.signRoutingAway(challenge).also { afterSign() }
                    }
                    override fun close() { signerCloses++; identity.close() }
                }
            }, current = { current }, freshnessMillis = { 1000 }, timeoutMillis = { 5000 }, dispatcher = Dispatchers.Unconfined)
    }
    private class Wire(
        private val status: suspend () -> PhoneRoutingResult = { error("Unexpected status") },
        private val challenge: suspend (ULong) -> PhoneRoutingResult = { error("Unexpected challenge") },
        private val apply: suspend (PhoneRoutingChallenge, ByteArray) -> PhoneRoutingResult = { _, _ -> error("Unexpected apply") },
        private val cleanup: suspend () -> Unit = {},
    ) : RoutingWire {
        var closes = 0; var statuses = 0; var challenges = 0; var applies = 0
        override suspend fun status(): PhoneRoutingResult { statuses++; return status.invoke() }
        override suspend fun challenge(expectedRevision: ULong): PhoneRoutingResult { challenges++; return challenge.invoke(expectedRevision) }
        override suspend fun apply(challenge: PhoneRoutingChallenge, signature: ByteArray): PhoneRoutingResult { applies++; return apply.invoke(challenge, signature) }
        override fun close() { closes++ }
        override suspend fun closeAndJoin() { close(); cleanup() }
    }
    @Test fun refreshNeedsNoDecisionKeyAndStaleOrFailedSamplesRemainLastKnown() = runTest {
        val f = Fixture(); val first = f.result(); val wire = Wire(status = { first }); f.wires.add(wire)
        val owner = f.owner(); assertTrue(owner.refresh()); assertTrue(owner.canSetAway())
        assertSame(first, owner.snapshot().observation); assertEquals(MacRoutingAvailability.ONLINE, owner.snapshot().availability)
        assertEquals(0, f.loads); assertEquals(1, wire.closes)
        f.nanos += 1_000_000_000; assertEquals(MacRoutingAvailability.OFFLINE, owner.snapshot().availability); assertFalse(owner.canSetAway())
        assertSame(first, owner.snapshot().observation)
        f.wires.add(Wire(status = { error("offline") })); assertFalse(owner.refresh())
        assertSame(first, owner.snapshot().observation); assertEquals(MacRoutingAvailability.OFFLINE, owner.snapshot().availability)
        owner.close()
    }
    @Test fun explicitAwayUsesOneChallengeOneDecisionSignatureAndOneApply() = runTest {
        val f = Fixture(); val initial = f.result(); val prepared = f.result(RoutingStatusOutcome.CHALLENGE)
        val applied = f.result(RoutingStatusOutcome.APPLIED, revision = 5u)
        val status = Wire(status = { initial }); val challenge = Wire(challenge = { assertEquals(0uL, it); prepared })
        val apply = Wire(apply = { received, signature ->
            assertSame(prepared.challenge, received)
            assertTrue(RoutingAwaySignature.verify(signature, f.enrollment.decisionKey.publicKey.copyBytes(), 1u,
                f.control(), CborLimits(1024, 2, 32), f.inputLimits)); applied
        })
        f.wires.addAll(listOf(status, challenge, apply)); val owner = f.owner()
        assertTrue(owner.refresh()); assertTrue(owner.setAway())
        assertEquals(1, f.loads); assertEquals(1, f.signs); assertEquals(1, f.signerCloses)
        assertEquals(1, challenge.challenges); assertEquals(1, apply.applies); assertEquals(3, f.opens)
        assertEquals(MacRoutingAction.ACKNOWLEDGED, owner.snapshot().action)
        assertEquals(RoutingStatusMode.PRESENT, owner.snapshot().observation!!.response.state.mode)
        assertEquals(5uL, owner.snapshot().observation!!.response.state.revision); owner.close()
    }
    @Test fun conflictPublishesCurrentStateAndNeverSignsOrReissuesAChallenge() = runTest {
        val f = Fixture(); f.wires.add(Wire(status = { f.result() })); val conflict = f.result(RoutingStatusOutcome.CONFLICT, revision = 2u)
        val wire = Wire(challenge = { conflict }); f.wires.add(wire); val owner = f.owner()
        owner.refresh(); assertTrue(owner.setAway()); assertEquals(MacRoutingAction.CONFLICT, owner.snapshot().action)
        assertSame(conflict, owner.snapshot().observation); assertEquals(0, f.loads); assertEquals(2, f.opens); assertEquals(1, wire.challenges)
        owner.close()
    }
    @Test fun unavailableAndAlreadyAwayStatesCannotQueueAnAwayChoice() = runTest {
        val f = Fixture(); val owner = f.owner()
        assertFalse(owner.setAway()); assertEquals(0, f.opens); assertEquals(MacRoutingAvailability.UNKNOWN, owner.snapshot().availability)
        f.wires.add(Wire(status = { f.result(mode = RoutingStatusMode.AWAY, revision = 1u) })); assertTrue(owner.refresh())
        assertFalse(owner.setAway()); assertEquals(1, f.opens); assertEquals(0, f.loads); owner.close()
    }
    @Test fun signerChecksEnrollmentKeyRoleClosureAndPostSignExpiry() = runTest {
        val f = Fixture(); val challenge = f.result(RoutingStatusOutcome.CHALLENGE).challenge!!
        f.identity().use { assertEquals(64, it.signRoutingAway(challenge).size) }
        f.identity(f.biometric).use { assertFailsWith<DecisionIdentityUnavailable> { it.signRoutingAway(challenge) } }
        Fixture(99).identity().use { assertFailsWith<DecisionIdentityUnavailable> { it.signRoutingAway(challenge) } }
        val closed = f.identity(); closed.close(); assertFailsWith<DecisionIdentityUnavailable> { closed.signRoutingAway(challenge) }
        assertFails { challenge.sign(f.enrollment) { input -> sign(f.decision, input).also { f.nanos += 30_000_000_000 } } }
    }
    @Test fun enrollmentChangeAfterSigningCannotOpenTheApplyWire() = runTest {
        val f = Fixture(); val initial = f.result(); val challenge = f.result(RoutingStatusOutcome.CHALLENGE)
        f.wires.addAll(listOf(Wire(status = { initial }), Wire(challenge = { challenge })))
        val owner = f.owner { f.current = false }; owner.refresh(); assertFalse(owner.setAway())
        assertEquals(2, f.opens); assertEquals(1, f.signs); assertEquals(1, f.signerCloses)
        assertEquals(MacRoutingAction.FAILED, owner.snapshot().action); owner.close()
    }
    @Test fun lostApplyAcknowledgmentNeverReplaysAndStatusCanReconcileCurrentState() = runTest {
        val f = Fixture(); val initial = f.result(); val challenge = f.result(RoutingStatusOutcome.CHALLENGE)
        val apply = Wire(apply = { _, _ -> error("Lost Root reply") })
        f.wires.addAll(listOf(Wire(status = { initial }), Wire(challenge = { challenge }), apply)); val owner = f.owner()
        owner.refresh(); assertFalse(owner.setAway()); assertEquals(MacRoutingAction.UNCERTAIN, owner.snapshot().action)
        assertEquals(MacRoutingAvailability.OFFLINE, owner.snapshot().availability); assertEquals(1, apply.applies)
        val reconciled = f.result(mode = RoutingStatusMode.AWAY, revision = 1u); f.wires.add(Wire(status = { reconciled }))
        assertTrue(owner.refresh()); assertSame(reconciled, owner.snapshot().observation)
        assertEquals(1, apply.applies); assertEquals(1, f.signs); assertFalse(owner.canSetAway()); owner.close()
    }
    @Test fun cleanupFailureCannotEraseAVerifiedAcknowledgmentOrItsCurrentState() = runTest {
        val f = Fixture(); val initial = f.result(); val challenge = f.result(RoutingStatusOutcome.CHALLENGE)
        val acknowledged = f.result(RoutingStatusOutcome.APPLIED, revision = 5u)
        f.wires.addAll(listOf(Wire(status = { initial }), Wire(challenge = { challenge }),
            Wire(apply = { _, _ -> acknowledged }, cleanup = { error("cleanup failed") })))
        val owner = f.owner(); owner.refresh(); assertFalse(owner.setAway())
        assertEquals(MacRoutingAction.ACKNOWLEDGED, owner.snapshot().action); assertSame(acknowledged, owner.snapshot().observation)
        assertEquals(MacRoutingAvailability.OFFLINE, owner.snapshot().availability); assertEquals(1, f.signerCloses)
        assertFails { owner.refresh() }; assertFails { owner.close() }
    }
    @Test fun retirementClosesTheOwnedWireAndWithholdsLatePublication() = runTest {
        val f = Fixture(); val entered = CompletableDeferred<Unit>(); val wire = Wire(status = { entered.complete(Unit); awaitCancellation() })
        f.wires.add(wire); val owner = f.owner(); val operation = async { owner.refresh() }; entered.await()
        owner.close(); operation.join(); assertTrue(operation.isCancelled); assertTrue(wire.closes >= 1)
        assertEquals(MacRoutingAvailability.CLOSED, owner.snapshot().availability); assertNull(owner.snapshot().observation)
        assertFails { owner.refresh() }
    }
    @Test fun cancellingApplyKeepsUncertaintyAndAConcurrentPollCannotQueueOrReplay() = runTest {
        val f = Fixture(); val initial = f.result(); val challenge = f.result(RoutingStatusOutcome.CHALLENGE)
        val entered = CompletableDeferred<Unit>(); val apply = Wire(apply = { _, _ -> entered.complete(Unit); awaitCancellation() })
        f.wires.addAll(listOf(Wire(status = { initial }), Wire(challenge = { challenge }), apply)); val owner = f.owner()
        owner.refresh(); val operation = async { owner.setAway() }; entered.await()
        assertFalse(owner.refresh()); assertFalse(owner.setAway()); operation.cancelAndJoin()
        assertEquals(1, apply.applies); assertEquals(3, f.opens); assertEquals(MacRoutingAction.UNCERTAIN, owner.snapshot().action)
        assertEquals(1, f.signerCloses); owner.close()
    }
    @Test fun timeoutKeepsTheOwnerAvailableForStatusButNeverRetriesAnApply() = runTest {
        val f = Fixture(); val blocked = Wire(status = { awaitCancellation() }); f.wires.add(blocked); val owner = f.owner()
        assertFalse(owner.refresh()); assertEquals(MacRoutingAvailability.OFFLINE, owner.snapshot().availability)
        f.wires.add(Wire(status = { f.result() })); assertTrue(owner.refresh())
        val prepared = f.result(RoutingStatusOutcome.CHALLENGE); val apply = Wire(apply = { _, _ -> awaitCancellation() })
        f.wires.addAll(listOf(Wire(challenge = { prepared }), apply))
        assertFalse(owner.setAway()); assertEquals(MacRoutingAction.UNCERTAIN, owner.snapshot().action)
        assertEquals(1, apply.applies); assertEquals(1, f.signs); assertEquals(1, f.signerCloses)
        f.wires.add(Wire(status = { f.result(mode = RoutingStatusMode.AWAY, revision = 1u) }))
        assertTrue(owner.refresh()); assertEquals(1, apply.applies); assertFalse(owner.canSetAway()); owner.close()
    }
    @Test fun incompatibleRootCannotEstablishPresenceOrLoadDecisionCustody() = runTest {
        val f = Fixture(); f.wires.add(Wire(status = { PhoneRoutingResult.Failure(PhoneRoutingFailure.INCOMPATIBLE) })); val owner = f.owner()
        assertTrue(owner.refresh()); assertEquals(MacRoutingAvailability.INCOMPATIBLE, owner.snapshot().availability)
        assertNull(owner.snapshot().observation); assertFalse(owner.canSetAway()); assertEquals(0, f.loads); owner.close()
    }
    @Test fun cancellingTheScreenWaiterDoesNotCancelTheApplicationOwnedAwayOperation() = runTest {
        val f = Fixture(); val initial = f.result(); val prepared = f.result(RoutingStatusOutcome.CHALLENGE)
        val applied = f.result(RoutingStatusOutcome.APPLIED, RoutingStatusMode.AWAY, 1u)
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        f.wires.add(Wire(status = { initial }))
        val owner = f.owner()
        try {
            assertTrue(owner.refresh())
            val prepare = Wire(challenge = { prepared })
            val apply = Wire(apply = { _, _ -> entered.complete(Unit); release.await(); applied })
            f.wires.add(prepare); f.wires.add(apply)
            val operation = applicationRoutingAway(backgroundScope, owner)
            val screenWaiter = launch(start = CoroutineStart.UNDISPATCHED) { operation.await() }
            entered.await()
            screenWaiter.cancelAndJoin()
            assertTrue(operation.isActive); assertTrue(backgroundScope.isActive)
            assertEquals(MacRoutingAction.SETTING_AWAY, owner.snapshot().action)
            release.complete(Unit)
            assertTrue(operation.await())
            assertEquals(MacRoutingAction.ACKNOWLEDGED, owner.snapshot().action)
            assertEquals(RoutingStatusMode.AWAY, owner.snapshot().observation?.response?.state?.mode)
            assertEquals(1, prepare.challenges); assertEquals(1, apply.applies); assertEquals(1, f.signs)
        } finally { release.complete(Unit); owner.close() }
    }

}
