package dev.sebastiano.remozio.android.updates

import dev.remozio.phone.enrollment.EnrollmentKeyReference
import dev.remozio.phone.enrollment.EnrollmentKeyRole
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.PhoneEnrollment
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.PhoneUpdateProgressObservation
import dev.remozio.phone.transport.PhoneUpdateSchedulingStatus
import dev.remozio.phone.transport.syntheticUpdateProgressChannel
import dev.remozio.phone.transport.syntheticUpdateSchedulingChannel
import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PhoneUpdateProgressFrame
import dev.remozio.protocol.PhoneUpdateSchedulingFrame
import dev.remozio.protocol.UpdateSchedulingAction
import dev.remozio.protocol.UpdateSchedulingAdmissionState
import dev.remozio.protocol.UpdateSchedulingDesignation
import dev.remozio.protocol.UpdateSchedulingProgressPhase
import dev.remozio.protocol.UpdateSchedulingProgressResponse
import dev.remozio.protocol.UpdateSchedulingProgressSigningInput
import dev.remozio.protocol.UpdateSchedulingSecurityStatus
import dev.remozio.protocol.UpdateSchedulingStatusResponse
import dev.remozio.protocol.UpdateSchedulingStatusSigningInput
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class MacUpdateProgressConnectionTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray) = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private)
        update(bytes)
        sign()
    }

    private inner class Fixture(phone: Int = 3) {
        val root = key()
        var nanos = 1_000_000L
        var opens = 0
        var applicationFrames = 0
        var freshness = 1000L
        var freshnessUnavailable = false
        var timeout = 5000L
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio." + role.aliasPart + ".v1." + "%032x".format(role.ordinal + 10),
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val enrollment = PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, key()),
            local(EnrollmentKeyRole.BIOMETRIC, key()), ByteArray(32) { 5 }, null)
        val record = StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE)
        var current = record
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        val updateID = ByteArray(32) { 8 }
        val wires = ArrayDeque<Wire>()
        var beforeCurrent: suspend () -> Unit = {}
        var beforeOpen: suspend () -> Unit = {}

        fun owner(dispatcher: CoroutineDispatcher = Dispatchers.Unconfined) = MacUpdateProgressConnection(
            record, open = { _, _ -> beforeOpen(); opens++; wires.removeFirst() },
            currentEnrollment = { beforeCurrent(); current }, freshnessMillis = {
                check(!freshnessUnavailable) { "Synthetic settings unavailable" }
                freshness
            },
            timeoutMillis = { timeout }, dispatcher = dispatcher)

        suspend fun progress(
            designation: UpdateSchedulingDesignation = UpdateSchedulingDesignation.THIS_ACCOUNT,
            actions: ULong = 3u,
            revision: ULong = 0u,
            action: UpdateSchedulingAction? = null,
            phase: UpdateSchedulingProgressPhase = UpdateSchedulingProgressPhase.READY,
            admission: UpdateSchedulingAdmissionState = UpdateSchedulingAdmissionState.OPEN,
        ): PhoneUpdateProgressObservation = syntheticUpdateProgressChannel(record, { nanos }, { current }) { query ->
            applicationFrames++
            val status = UpdateSchedulingStatusResponse(scope, query.queryNonce.copyBytes(), updateID, 1u, revision, action)
            val payload = UpdateSchedulingProgressResponse(status, phase, designation, UpdateSchedulingSecurityStatus.SECURITY,
                100u, actions, emptyList(), admission).encode()
            PhoneUpdateProgressFrame.Response(query.queryNonce.copyBytes(), payload,
                sign(root, UpdateSchedulingProgressSigningInput.make(1u, payload, CborLimits(8192, 2, 32)))).encode()
        }.read()

        suspend fun scheduling(
            update: ByteArray = updateID,
            generation: ULong = 1u,
            revision: ULong = 0u,
            action: UpdateSchedulingAction? = null,
        ): PhoneUpdateSchedulingStatus = syntheticUpdateSchedulingChannel(record, { nanos }, { current }) { query ->
            val payload = UpdateSchedulingStatusResponse(scope, query.queryNonce.copyBytes(), update,
                generation, revision, action).encode()
            PhoneUpdateSchedulingFrame.StateResponse(query.queryNonce.copyBytes(), payload,
                sign(root, UpdateSchedulingStatusSigningInput.make(1u, payload, CborLimits(4096, 2, 32)))).encode()
        }.status()
    }

    private class Wire(
        private val body: suspend () -> PhoneUpdateProgressObservation,
        private val cleanup: suspend () -> Unit = {},
        private val failClose: Boolean = false,
    ) : MacUpdateProgressWire {
        private val closed = AtomicBoolean(false)
        var reads = 0
        var closes = 0
        var joins = 0
        override suspend fun read(): PhoneUpdateProgressObservation { reads++; return body() }
        override fun close() {
            if (closed.compareAndSet(false, true)) {
                closes++
                check(!failClose) { "Synthetic close failure" }
            }
        }
        override suspend fun closeAndJoin() { try { close() } finally { joins++; cleanup() } }
    }

    @Test fun verifiedProgressIsPublishedAfterTransportCleanupAndRetainsRootFields() = runTest {
        val f = Fixture()
        val owner = f.owner()
        var cleaned = false
        val wire = Wire({ f.progress() }, cleanup = { cleaned = true; assertNull(owner.snapshot().observation) })
        f.wires.add(wire)
        assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        assertTrue(cleaned)
        assertEquals(MacUpdateProgressAvailability.ONLINE, owner.snapshot().availability)
        assertEquals(UpdateSchedulingSecurityStatus.SECURITY, observed.response.security)
        assertEquals(100uL, observed.readyAgeUpperBoundMilliseconds())
        assertNull(observed.response.status.controlDigest)
        assertEquals(1, wire.reads)
        assertEquals(1, wire.closes)
        assertEquals(1, wire.joins)
        assertEquals(1, f.applicationFrames)
        owner.close()
        assertFalse(observed.isFresh(1000))
    }

    @Test fun eligibilityUsesRootFlagsAndOnlyTheExplicitDesignatedAccountCanDefer() = runTest {
        for (designation in UpdateSchedulingDesignation.entries) {
            val f = Fixture()
            val owner = f.owner()
            val flags = if (designation == UpdateSchedulingDesignation.THIS_ACCOUNT) 3uL else 1uL
            f.wires.add(Wire({ f.progress(designation, flags) }))
            assertTrue(owner.refresh())
            val observed = assertNotNull(owner.snapshot().observation)
            val status = f.scheduling()
            assertTrue(owner.canOffer(observed, status, UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES))
            assertEquals(designation == UpdateSchedulingDesignation.THIS_ACCOUNT,
                owner.canOffer(observed, status, UpdateSchedulingAction.DEFER_UPDATE))
            assertFalse(owner.canOffer(observed, status, UpdateSchedulingAction.CANCEL_DRAIN))
            status.close()
            owner.close()
        }
    }

    @Test fun absentEligibilityAndIrreversibleProgressCannotOfferAnyAction() = runTest {
        for (phase in listOf(UpdateSchedulingProgressPhase.UNKNOWN, UpdateSchedulingProgressPhase.ACTIVATING,
            UpdateSchedulingProgressPhase.CHECKING_RESTART, UpdateSchedulingProgressPhase.FINISHING,
            UpdateSchedulingProgressPhase.COMPLETED)) {
            val f = Fixture()
            val owner = f.owner()
            f.wires.add(Wire({ f.progress(actions = 0u, phase = phase) }))
            assertTrue(owner.refresh())
            val observed = assertNotNull(owner.snapshot().observation)
            val status = f.scheduling()
            for (action in UpdateSchedulingAction.entries) assertFalse(owner.canOffer(observed, status, action))
            status.close()
            owner.close()
        }
    }

    @Test fun updateGenerationRevisionAndRequestedActionMustMatchTheSchedulingObservation() = runTest {
        val f = Fixture()
        val owner = f.owner()
        f.wires.add(Wire({ f.progress(actions = 4u, revision = 1u,
            action = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES,
            phase = UpdateSchedulingProgressPhase.DRAINING, admission = UpdateSchedulingAdmissionState.CLOSED) }))
        assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        val changed = listOf(
            f.scheduling(update = ByteArray(32) { 99 }),
            f.scheduling(generation = 2u),
            f.scheduling(),
            f.scheduling(revision = 1u, action = UpdateSchedulingAction.DEFER_UPDATE),
        )
        for (status in changed) {
            assertFalse(owner.canOffer(observed, status, UpdateSchedulingAction.CANCEL_DRAIN))
            status.close()
        }
        val current = f.scheduling(revision = 1u, action = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES)
        assertTrue(owner.canOffer(observed, current, UpdateSchedulingAction.CANCEL_DRAIN))
        current.close()
        owner.close()
    }

    @Test fun aForeignSchedulingScopeCannotBorrowCurrentEligibility() = runTest {
        val f = Fixture()
        val owner = f.owner()
        f.wires.add(Wire({ f.progress() }))
        assertTrue(owner.refresh())
        val status = Fixture(99).scheduling()
        assertFalse(owner.canOffer(assertNotNull(owner.snapshot().observation), status, UpdateSchedulingAction.DEFER_UPDATE))
        status.close()
        owner.close()
    }

    @Test fun sleepAndReplacementRetireTheDisplayedObservation() = runTest {
        val f = Fixture()
        val owner = f.owner()
        f.wires.add(Wire({ f.progress() }))
        assertTrue(owner.refresh())
        val old = assertNotNull(owner.snapshot().observation)
        val status = f.scheduling()
        f.nanos += 1_000_000_000
        assertEquals(MacUpdateProgressAvailability.OFFLINE, owner.snapshot().availability)
        assertFalse(owner.canOffer(old, status, UpdateSchedulingAction.DEFER_UPDATE))
        assertSame(old, owner.snapshot().observation)
        f.wires.add(Wire({ f.progress() }))
        assertTrue(owner.refresh())
        assertFalse(old.isFresh(1000))
        assertFalse(owner.canOffer(old, status, UpdateSchedulingAction.DEFER_UPDATE))
        status.close()
        owner.close()
    }

    @Test fun aForeignOrRevokedReplyCannotPublishProgress() = runTest {
        for (foreign in listOf(false, true)) {
            val f = Fixture()
            val owner = f.owner()
            val value = if (foreign) Fixture(99).progress() else f.progress()
            val wire = Wire({
                if (!foreign) f.current = StoredPhoneEnrollment(f.enrollment, EnrollmentPhase.PREPARED)
                value
            })
            f.wires.add(wire)
            assertFalse(owner.refresh())
            assertNull(owner.snapshot().observation)
            assertFalse(value.isFresh(1000))
            assertEquals(1, wire.closes)
            owner.close()
        }
    }

    @Test fun delayedCleanupCountsTowardFreshnessAndWithholdsTheReply() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val value = f.progress()
        f.wires.add(Wire({ value }, cleanup = { f.nanos += 1_000_000_000 }))
        assertFalse(owner.refresh())
        assertNull(owner.snapshot().observation)
        assertFalse(value.isFresh(1000))
        owner.close()
    }

    @Test fun cleanupFailureBlocksPublicationAndFutureRefreshes() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val value = f.progress()
        f.wires.add(Wire({ value }, cleanup = { error("Synthetic cleanup failure") }))
        assertFalse(owner.refresh())
        assertNull(owner.snapshot().observation)
        assertFalse(value.isFresh(1000))
        assertFails { owner.refresh() }
        assertFails { owner.close() }
        assertFails { owner.retirementSettled() }
    }

    @Test fun cancellationDoesNotQueueAnotherReadOrPublishALateReply() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val entered = CompletableDeferred<Unit>()
        val wire = Wire({ entered.complete(Unit); awaitCancellation() })
        f.wires.add(wire)
        val refresh = async { owner.refresh() }
        entered.await()
        assertFalse(owner.refresh())
        refresh.cancelAndJoin()
        assertEquals(1, f.opens)
        assertEquals(1, wire.reads)
        assertEquals(1, wire.closes)
        assertNull(owner.snapshot().observation)
        owner.close()
        assertTrue(owner.retirementSettled())
    }

    @Test fun retirementWaitsForNonCancellableCleanupAndRetiresTheUnpublishedObservation() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val value = f.progress()
        f.wires.add(Wire({ value }, cleanup = { entered.complete(Unit); release.await() }))
        val refresh = async { owner.refresh() }
        entered.await()
        owner.close()
        assertFalse(owner.retirementSettled())
        assertNull(owner.snapshot().observation)
        release.complete(Unit)
        refresh.join()
        assertTrue(owner.retirementSettled())
        assertFalse(value.isFresh(1000))
        assertEquals(MacUpdateProgressAvailability.CLOSED, owner.snapshot().availability)
    }

    @Test fun revocationDuringCleanupWithholdsTheVerifiedObservation() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val value = f.progress()
        f.wires.add(Wire({ value }, cleanup = {
            f.current = StoredPhoneEnrollment(f.enrollment, EnrollmentPhase.PREPARED)
        }))
        assertFalse(owner.refresh())
        assertNull(owner.snapshot().observation)
        assertFalse(value.isFresh(1000))
        owner.close()
    }

    @Test fun retirementDuringOpenClosesTheReturnedWireBeforeAnyRead() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val wire = Wire({ error("Unexpected progress read") })
        f.wires.add(wire)
        f.beforeOpen = { entered.complete(Unit); withContext(NonCancellable) { release.await() } }
        val refresh = async { owner.refresh() }
        entered.await()
        owner.close()
        assertFalse(owner.retirementSettled())
        release.complete(Unit)
        refresh.join()
        assertTrue(owner.retirementSettled())
        assertEquals(0, wire.reads)
        assertEquals(1, wire.closes)
        assertEquals(1, wire.joins)
        assertNull(owner.snapshot().observation)
    }

    @Test fun closeFailureRemainsVisibleAfterTheOperationStops() = runTest {
        val f = Fixture()
        val owner = f.owner()
        val entered = CompletableDeferred<Unit>()
        val wire = Wire({ entered.complete(Unit); awaitCancellation() }, failClose = true)
        f.wires.add(wire)
        val refresh = async { owner.refresh() }
        entered.await()
        assertFails { owner.close() }
        refresh.join()
        assertFails { owner.retirementSettled() }
        assertFails { owner.close() }
        assertEquals(MacUpdateProgressAvailability.CLOSED, owner.snapshot().availability)
        assertNull(owner.snapshot().observation)
        assertEquals(1, wire.joins)
    }

    @Test fun aClosedOwnerDoesNotReadSettingsOrReuseEligibility() = runTest {
        val f = Fixture()
        val owner = f.owner()
        f.wires.add(Wire({ f.progress() }))
        assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        val status = f.scheduling()
        owner.close()
        f.freshnessUnavailable = true
        assertEquals(MacUpdateProgressAvailability.CLOSED, owner.snapshot().availability)
        assertFalse(owner.canOffer(observed, status, UpdateSchedulingAction.DEFER_UPDATE))
        assertTrue(owner.retirementSettled())
        status.close()
    }

    @Test fun aReadTimeoutClosesTheWireAndRequiresANewExplicitRefresh() = runTest {
        val f = Fixture()
        val owner = f.owner(StandardTestDispatcher(testScheduler))
        val entered = CompletableDeferred<Unit>()
        val wire = Wire({ entered.complete(Unit); awaitCancellation() })
        f.wires.add(wire)
        val refresh = async { owner.refresh() }
        runCurrent()
        entered.await()
        advanceTimeBy(5001)
        runCurrent()
        assertFalse(refresh.await())
        assertEquals(1, wire.reads)
        assertEquals(1, wire.closes)
        assertEquals(1, f.opens)
        assertEquals(MacUpdateProgressAvailability.OFFLINE, owner.snapshot().availability)
        owner.close()
    }

    @Test fun invalidFreshnessFailsClosedAndDescriptionsContainNoPayload() = runTest {
        val f = Fixture()
        val owner = f.owner()
        f.wires.add(Wire({ f.progress() }))
        assertTrue(owner.refresh())
        val observed = assertNotNull(owner.snapshot().observation)
        val status = f.scheduling()
        f.freshness = 0
        assertEquals(MacUpdateProgressAvailability.OFFLINE, owner.snapshot().availability)
        assertFalse(owner.canOffer(observed, status, UpdateSchedulingAction.DEFER_UPDATE))
        assertEquals("MacUpdateProgressConnection(redacted)", owner.toString())
        assertEquals("MacUpdateProgressState(redacted)", owner.snapshot().toString())
        status.close()
        owner.close()
    }
}
