package dev.remozio.android.requests

import dev.remozio.android.decisions.decisionPublicPoint
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.*
import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import org.junit.Test
import kotlin.test.*

class CommandConnectionTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private fun id(n: Int, size: Int = 16) = ByteArray(size) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = pair()
    private val decision = pair()
    private val biometric = pair()
    private fun point(pair: KeyPair) = decisionPublicPoint(pair.public as ECPublicKey)
    private fun reference(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(10 + role.ordinal),
        "remozio.${role.aliasPart}.v1.${"%032x".format(10 + role.ordinal)}", if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else point(pair))
    private val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(2), id(3), id(4), id(5), "Synthetic Mac",
        point(authority), pair().public.encoded, reference(EnrollmentKeyRole.TRANSPORT, pair()),
        reference(EnrollmentKeyRole.DECISION, decision), reference(EnrollmentKeyRole.BIOMETRIC, biometric), id(6, 32), null), EnrollmentPhase.ACTIVE)
    private val decline = CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest)
    private val execute = CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)
    private val request = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 1u), id(2), id(3), id(7), id(8, 32), emptySet(),
        1u, 60001u, File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes(), listOf(decline, execute), bound, bound)
    private var time = ElapsedInstant(0, 100u)
    private fun sign(body: ByteArray, key: KeyPair, type: ApprovalMessageType, purpose: SigningPurpose) =
        P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private); update(SigningInput.make(1u, type, purpose, body, bound, bound)); sign()
        })
    private fun issued(enrollment: CommandRequestEnrollment): CommandRequestSession {
        val body = request.encode(bound)
        return enrollment.accept(body, sign(body, authority, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST)).also {
            val status = RequestStatusPayload(id(2), id(3), id(7), request.requestDigest(bound, bound), request.challenge,
                1u, RequestPhase.PRESENTED, RequestStatusReason.NONE, id(20), 1000u, 59000u, null, false, null, null).encode(bound)
            it.observe(status, sign(status, authority, ApprovalMessageType.STATUS, SigningPurpose.STATUS), time)
        }
    }
    private fun message(session: CommandRequestSession, execute: Boolean = false, signingKey: KeyPair = if (execute) biometric else decision): ApprovalMessage {
        val e = record.enrollment
        val key = if (execute) e.biometricKey else e.decisionKey
        val body = session.withPendingDecision(time, e.phoneID.copyBytes(), key.keyID.copyBytes(), if (execute) this.execute else decline) { it.encode(bound) }
        val purpose = if (execute) SigningPurpose.BIOMETRIC_AUTHORIZATION else SigningPurpose.CANCELLATION
        return ApprovalMessage(1u, ApprovalMessageType.DECISION, purpose, body, sign(body, signingKey, ApprovalMessageType.DECISION, purpose))
    }
    private class Wire : CommandConnectionWire {
        val end = CompletableDeferred<Unit>()
        val sent = mutableListOf<ByteArray>()
        var closed = false
        var write: suspend () -> Unit = {}
        override suspend fun receive() { end.await() }
        override suspend fun send(bytes: ByteArray) { check(!closed); sent += bytes.copyOf(); write() }
        override fun close() { closed = true; end.complete(Unit) }
    }
    private fun owner(snapshot: (suspend (CoroutineScope, CommandRequestEnrollment) -> CommandConnectionWire)? = null,
                      open: suspend (CoroutineScope, CommandRequestEnrollment) -> CommandConnectionWire) =
        CommandConnection(record, limits, open, { time }, dispatcher = Dispatchers.Unconfined, openSnapshot = snapshot)

    @Test fun sendsExactEnrolledDecisionWithoutInventingAcceptance() = runBlocking<Unit> {
        val wire = Wire(); lateinit var session: CommandRequestSession
        val owner = owner { _, enrollment -> wire.also { session = issued(enrollment) } }
        val running = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertEquals(CommandConnectionState.CONNECTED, owner.connectionState.value)
        for (execute in listOf(false, true)) {
            val message = message(session, execute)
            owner.approval(session).send(message)
            assertContentEquals(message.encode(bound.maxBytes), wire.sent.last())
        }
        assertEquals(RequestPhase.PRESENTED, session.snapshot(time).status!!.status.phase)
        owner.close(); running.cancelAndJoin()
        assertTrue(session.closed.value); assertTrue(wire.closed)
        assertEquals(CommandConnectionState.CLOSED, owner.connectionState.value)
    }

    @Test fun rejectsWrongKeyUnownedSessionAndExpiredRequestBeforeWriting() = runBlocking<Unit> {
        val wire = Wire(); lateinit var session: CommandRequestSession
        val owner = owner { _, enrollment -> wire.also { session = issued(enrollment) } }
        val running = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        val otherInbox = CommandRequestInbox(1, 2)
        val other = issued(otherInbox.add(id(2), id(3), point(authority), limits))
        assertFails { owner.approval(other).send(message(other)) }
        assertFails { owner.approval(session).send(message(session, signingKey = biometric)) }
        val pending = message(session)
        time = ElapsedInstant(0, 60100u)
        assertFails { owner.approval(session).send(pending) }
        assertTrue(wire.sent.isEmpty())
        owner.close(); running.cancelAndJoin(); otherInbox.close()
    }

    @Test fun disconnectAndReconnectPreserveRequestAndRetryBytes() = runBlocking<Unit> {
        val wires = mutableListOf<Wire>(); lateinit var session: CommandRequestSession
        val owner = owner { _, enrollment -> Wire().also { wires += it; session = issued(enrollment) } }
        val firstRun = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        val retained = session; val message = message(session)
        wires.single().write = { throw java.io.IOException("Synthetic uncertain write") }
        assertFails { owner.approval(session).send(message) }
        wires.single().end.complete(Unit); firstRun.await()
        assertEquals(CommandConnectionState.DISCONNECTED, owner.connectionState.value)
        assertFalse(retained.closed.value)
        assertFails { owner.approval(session).send(message) }
        val secondRun = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertSame(retained, session)
        assertTrue(wires.last().sent.isEmpty())
        owner.approval(session).send(message)
        assertContentEquals(wires.first().sent.single(), wires.last().sent.single())
        owner.close(); secondRun.cancelAndJoin()
    }

    @Test fun lateOpenAfterCloseIsReleasedWithoutPublishingConnected() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); val wire = Wire()
        val owner = owner { _, _ -> withContext(NonCancellable) { entered.complete(Unit); release.await() }; wire }
        val running = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        entered.await(); owner.close(); release.complete(Unit); running.cancelAndJoin()
        assertTrue(wire.closed)
        assertEquals(CommandConnectionState.CLOSED, owner.connectionState.value)
        assertFails { owner.run() }
    }

    @Test fun reconnectWaitsForPreviousRunToReleaseItsWire() = runBlocking<Unit> {
        val wires = mutableListOf<Wire>()
        val owner = owner { _, _ -> Wire().also { wires += it } }
        val first = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        val second = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertEquals(1, wires.size)
        first.cancelAndJoin()
        yield()
        assertEquals(2, wires.size)
        assertTrue(wires.first().closed)
        assertEquals(CommandConnectionState.CONNECTED, owner.connectionState.value)
        owner.close(); second.cancelAndJoin()
    }

    @Test fun concurrentWritesSerializeAndClosureDoesNotReportSuccess() = runBlocking<Unit> {
        val wire = Wire(); lateinit var session: CommandRequestSession
        val owner = owner { _, enrollment -> wire.also { session = issued(enrollment) } }
        val running = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        wire.write = { entered.complete(Unit); release.await() }
        val first = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.approval(session).send(message(session)) } }
        entered.await()
        val second = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.approval(session).send(message(session)) } }
        assertEquals(1, wire.sent.size)
        owner.close(); release.complete(Unit)
        assertTrue(first.await().isFailure); assertTrue(second.await().isFailure)
        assertEquals(1, wire.sent.size); running.cancelAndJoin()
    }
    @Test fun snapshotDoesNotPublishADecisionWireAndForegroundKeepsItsRequests() = runBlocking<Unit> {
        val background = Wire(); val foreground = Wire()
        lateinit var captured: CommandRequestSession
        lateinit var retained: CommandRequestSession
        val owner = owner(snapshot = { _, enrollment -> background.also { captured = issued(enrollment) } }) { _, enrollment ->
            foreground.also { retained = issued(enrollment) }
        }
        val fetch = async(start = CoroutineStart.UNDISPATCHED) { owner.fetchSnapshot() }
        assertEquals(CommandConnectionState.DISCONNECTED, owner.connectionState.value)
        assertFails { owner.approval(captured).send(message(captured)) }
        assertTrue(background.sent.isEmpty())
        background.end.complete(Unit)
        assertTrue(fetch.await()); assertTrue(background.closed)
        assertFalse(captured.closed.value)
        val run = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertSame(captured, retained)
        owner.approval(retained).send(message(retained))
        assertEquals(1, foreground.sent.size)
        owner.close(); run.cancelAndJoin()
    }

    @Test fun snapshotRefusesAnActiveOrQueuedForegroundOwnerWithoutOpening() = runBlocking<Unit> {
        var snapshotOpens = 0
        val wires = mutableListOf<Wire>()
        val owner = owner(snapshot = { _, _ -> snapshotOpens++; Wire() }) { _, _ -> Wire().also { wires += it } }
        val first = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        val queued = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertFalse(owner.fetchSnapshot()); assertEquals(0, snapshotOpens)
        wires.first().end.complete(Unit); first.await()
        assertEquals(2, wires.size)
        assertFalse(owner.fetchSnapshot()); assertEquals(0, snapshotOpens)
        owner.close(); queued.cancelAndJoin()
    }

    @Test fun foregroundPreemptsSnapshotReceiveAndKeepsTheRequestOwner() = runBlocking<Unit> {
        val background = Wire(); val foreground = Wire()
        lateinit var captured: CommandRequestSession
        lateinit var retained: CommandRequestSession
        val owner = owner(snapshot = { _, enrollment -> background.also { captured = issued(enrollment) } }) { _, enrollment ->
            foreground.also { retained = issued(enrollment) }
        }
        val fetch = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.fetchSnapshot() } }
        val run = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertTrue(fetch.await().exceptionOrNull() is CancellationException)
        assertTrue(background.closed); assertFalse(foreground.closed)
        assertSame(captured, retained); assertFalse(retained.closed.value)
        assertEquals(CommandConnectionState.CONNECTED, owner.connectionState.value)
        assertFalse(owner.fetchSnapshot())
        owner.close(); run.cancelAndJoin()
    }

    @Test fun foregroundIntentBeforeSnapshotDispatchPreventsTheBackgroundOpen() = kotlinx.coroutines.test.runTest {
        val dispatcher = kotlinx.coroutines.test.StandardTestDispatcher(testScheduler)
        var snapshotOpens = 0; var foregroundOpens = 0
        val wire = Wire()
        val owner = CommandConnection(record, limits, open = { _, _ -> foregroundOpens++; wire }, clock = { time },
            dispatcher = dispatcher, openSnapshot = { _, _ -> snapshotOpens++; Wire() })
        val fetch = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.fetchSnapshot() } }
        val foreground = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        testScheduler.runCurrent()
        assertTrue(fetch.await().isFailure); assertEquals(0, snapshotOpens); assertEquals(1, foregroundOpens)
        assertEquals(CommandConnectionState.CONNECTED, owner.connectionState.value)
        owner.close(); foreground.cancelAndJoin()
    }

    @Test fun foregroundWaitsForCancelledSnapshotOpenToReleaseItsLateWire() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val late = Wire(); val foreground = Wire(); var foregroundOpens = 0
        val owner = owner(snapshot = { _, _ ->
            withContext(NonCancellable) { entered.complete(Unit); release.await() }; late
        }) { _, _ -> foregroundOpens++; assertTrue(late.closed); foreground }
        val fetch = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.fetchSnapshot() } }
        entered.await()
        val run = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        assertEquals(0, foregroundOpens); assertFalse(late.closed)
        assertFalse(owner.fetchSnapshot())
        release.complete(Unit)
        assertTrue(fetch.await().exceptionOrNull() is CancellationException)
        yield()
        assertTrue(late.closed); assertEquals(1, foregroundOpens)
        assertEquals(CommandConnectionState.CONNECTED, owner.connectionState.value)
        owner.close(); run.cancelAndJoin()
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun snapshotTimeoutClosesItsWireAndLeavesForegroundAvailable() = kotlinx.coroutines.test.runTest {
        val background = Wire(); val foreground = Wire()
        val owner = CommandConnection(record, limits, { _, _ -> foreground }, { time },
            dispatcher = kotlinx.coroutines.test.StandardTestDispatcher(testScheduler), openSnapshot = { _, _ -> background })
        val fetch = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.fetchSnapshot(100) } }
        testScheduler.runCurrent(); testScheduler.advanceTimeBy(101); testScheduler.runCurrent()
        assertTrue(fetch.await().exceptionOrNull() is TimeoutCancellationException)
        assertTrue(background.closed); assertEquals(CommandConnectionState.DISCONNECTED, owner.connectionState.value)
        val run = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        testScheduler.runCurrent(); assertEquals(CommandConnectionState.CONNECTED, owner.connectionState.value)
        owner.close(); run.cancelAndJoin()
    }

    @Test fun closedOwnerCannotCompleteAnActiveSnapshotOrOpenAnotherConnection() = runBlocking<Unit> {
        val wire = Wire()
        val owner = owner(snapshot = { _, _ -> wire }) { _, _ -> error("No foreground open expected") }
        val fetch = async(start = CoroutineStart.UNDISPATCHED) { runCatching { owner.fetchSnapshot() } }
        owner.close()
        assertTrue(fetch.await().isFailure); assertTrue(wire.closed)
        assertEquals(CommandConnectionState.CLOSED, owner.connectionState.value)
        assertFails { owner.fetchSnapshot() }; assertFails { owner.run() }
    }

    @Test fun cancellingAQueuedForegroundAttemptReleasesItsPriorityReservation() = runBlocking<Unit> {
        val foreground = Wire(); val background = Wire().also { it.end.complete(Unit) }
        val owner = owner(snapshot = { _, _ -> background }) { _, _ -> foreground }
        val first = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        val queued = async(start = CoroutineStart.UNDISPATCHED) { owner.run() }
        queued.cancelAndJoin(); foreground.end.complete(Unit); first.await()
        assertTrue(owner.fetchSnapshot()); assertTrue(background.closed)
        owner.close()
    }

}
