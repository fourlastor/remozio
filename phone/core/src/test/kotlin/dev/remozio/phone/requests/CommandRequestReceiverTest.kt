package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.io.File
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class CommandRequestReceiverTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private fun id(value: Int, count: Int = 16) = ByteArray(count) { value.toByte() }
    private fun scope(mac: Int = 1) = ChannelScope(id(mac), id(2), id(3), id(4))
    private class Wire(override val scope: ChannelScope, supportsCommands: Boolean = true,
                       override val maximumPayloadBytes: Int = 65536,
                       override val commandSchemas: Set<ULong> = if (supportsCommands) setOf(1u) else emptySet()) : RequestMessageChannel {
        val queue = Channel<ByteArray>(8)
        var closed = false
        val sent = Channel<ByteArray>(16)
        var onSend: suspend (ByteArray) -> Unit = {}
        var onClose: () -> Unit = {}
        override suspend fun receive() = queue.receiveCatching().getOrNull()
        override suspend fun send(bytes: ByteArray) { onSend(bytes); sent.send(bytes.copyOf()) }
        override fun close() { closed = true; queue.cancel(); onClose() }
    }
    private inner class Mac(val identity: Int = 1) {
        private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val publicKey: ByteArray get() = (key.public as ECPublicKey).w.let { point ->
            fun scalar(n: java.math.BigInteger) = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        var requestID = 5
        var challengeValue = 6
        var schema: ULong = 1u
        var captureBytes = capture
        val request get() = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, schema), id(identity), id(2), id(requestID), id(challengeValue, 32),
            emptySet(), 1000u, 61000u, captureBytes, listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), bound, bound)
        fun envelope(body: ByteArray, type: ApprovalMessageType, purpose: SigningPurpose): ByteArray {
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private); update(SigningInput.make(1u, type, purpose, body, bound, bound)); sign()
            })
            return ApprovalMessage(1u, type, purpose, body, signature).encode(bound.maxBytes)
        }
        fun issued() = envelope(request.encode(bound), ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST)
        fun status(terminal: Boolean = false) = envelope(RequestStatusPayload(id(identity), id(2), id(requestID), request.requestDigest(bound, bound),
            request.challenge, if (terminal) 2u else 1u, if (terminal) RequestPhase.EXPIRED else RequestPhase.PRESENTED,
            if (terminal) RequestStatusReason.AUTHORIZATION_EXPIRED else RequestStatusReason.NONE, id(7),
            if (terminal) 60000u else 10u, if (terminal) null else 60000u, null, false, if (terminal) 60000u else null, null).encode(bound),
            ApprovalMessageType.STATUS, SigningPurpose.STATUS)
        fun enroll(inbox: CommandRequestInbox = CommandRequestInbox(2, 4), retired: RetiredCommandRequests? = null) =
            inbox.add(id(identity), id(2), publicKey, limits, retired)
    }
    private fun bind(enrollment: CommandRequestEnrollment, wire: RequestMessageChannel, time: ULong = 100u) =
        CommandRequestReceiver.bind(enrollment, wire, id(3), id(4)) { ElapsedInstant(0, time) }
    private suspend fun deliver(enrollment: CommandRequestEnrollment, mac: Mac, vararg messages: ByteArray, time: ULong = 100u) {
        val wire = Wire(scope(mac.identity))
        messages.forEach { wire.queue.send(it) }; wire.queue.close()
        bind(enrollment, wire, time).run()
        assertTrue(wire.closed)
    }
    @Test fun onlySharedImplementedSchemasEnableRequestDelivery() {
        fun offer(schema: ULong, features: Set<ULong> = emptySet()) = ChannelRequestCapability(0u, 1u, schema, features)
        assertEquals(setOf(1uL), commandChannelSchemas(listOf(offer(1u), offer(2u)), emptySet(), ChannelRole.MAC, listOf(offer(1u))))
        assertEquals(setOf(2uL), commandChannelSchemas(listOf(offer(1u), offer(2u)), emptySet(), ChannelRole.MAC,
            listOf(offer(2u), offer(3u), ChannelRequestCapability(8u, 1u, 1u, emptySet()))))
        assertFailsWith<IllegalArgumentException> { commandChannelSchemas(listOf(offer(1u)), emptySet(), ChannelRole.MAC, listOf(offer(2u))) }
        assertEquals(setOf(2uL), commandChannelSchemas(listOf(offer(2u)), emptySet(), ChannelRole.MAC, listOf(offer(2u, setOf(1u)))))
        assertFailsWith<IllegalArgumentException> { commandChannelSchemas(listOf(offer(2u, setOf(1u))), emptySet(), ChannelRole.MAC, listOf(offer(2u))) }
        assertEquals(setOf(3uL), commandChannelSchemas(listOf(offer(3u)), emptySet(), ChannelRole.MAC, listOf(offer(3u))))
        assertFailsWith<IllegalArgumentException> { commandChannelSchemas(listOf(offer(4u)), emptySet(), ChannelRole.MAC, listOf(offer(4u))) }
        assertFailsWith<IllegalArgumentException> { commandChannelSchemas(listOf(offer(1u)), setOf(1u), ChannelRole.MAC, listOf(offer(1u))) }
        assertFailsWith<IllegalArgumentException> { commandChannelSchemas(listOf(offer(1u)), emptySet(), ChannelRole.PHONE, listOf(offer(1u))) }
    }

    @Test fun receivingSchemaTwoRequiresItsContractOnThisConnection() = runBlocking<Unit> {
        val mac = Mac(); mac.schema = 2u
        val root = (DeterministicCbor.decode(capture, bound) as CborValue.Fields).values
        mac.captureBytes = DeterministicCbor.encode(CborValue.Fields(root + (0uL to CborValue.Unsigned(2u))), bound)
        val enrollment = mac.enroll()
        val old = Wire(scope()); old.queue.send(mac.issued()); old.queue.close()
        assertFailsWith<IOException> { bind(enrollment, old).run() }
        assertTrue(old.closed); assertTrue(enrollment.sessions().isEmpty())
        val current = Wire(scope(), commandSchemas = setOf(1u, 2u))
        current.queue.send(mac.issued()); current.queue.send(mac.status()); current.queue.close()
        bind(enrollment, current).run()
        val retained = enrollment.sessions().single()
        assertEquals(2uL, retained.snapshot(ElapsedInstant(0, 100u)).capture!!.schemaVersion)
        val downgrade = Wire(scope()); downgrade.queue.send(mac.issued()); downgrade.queue.close()
        assertFailsWith<IOException> { bind(enrollment, downgrade).run() }
        assertSame(retained, enrollment.sessions().single())
        enrollment.close()
    }

    @Test fun reconnectQueriesRetainedPendingAndTerminalOwnersWithoutSendingDecisions() = runBlocking<Unit> {
        withTimeout(3000) {
            val mac = Mac(); val enrollment = mac.enroll()
            deliver(enrollment, mac, mac.issued(), mac.status())
            val pending = enrollment.sessions().single()
            mac.requestID = 9
            deliver(enrollment, mac, mac.issued(), mac.status(true))
            val owners = enrollment.sessions()
            val wire = Wire(scope())
            val receiver = CommandRequestReceiver.bind(enrollment, wire, id(3), id(4), queryRetainedOnStart = true) { ElapsedInstant(0, 200u) }
            val receiving = async { receiver.run() }
            val queries = List(2) { RequestStatusQuery.decode(wire.sent.receive()).requestID }
            assertEquals(setOf(CborValue.Bytes(id(5)), CborValue.Bytes(id(9))), queries.toSet())
            mac.requestID = 5
            wire.queue.send(mac.status(true))
            pending.revisions.first { it == 2uL }
            assertEquals(RequestPhase.EXPIRED, pending.snapshot(ElapsedInstant(0, 200u)).status!!.status.phase)
            assertEquals(owners, enrollment.sessions())
            assertTrue(wire.sent.tryReceive().isFailure)
            receiver.close(); receiving.await(); enrollment.close()
        }
    }

    @Test fun initialConnectionDoesNotQueryNewCapturesReceivedAfterItStarts() = runBlocking<Unit> {
        withTimeout(3000) {
            val mac = Mac(); val enrollment = mac.enroll(); val wire = Wire(scope())
            val receiver = CommandRequestReceiver.bind(enrollment, wire, id(3), id(4), queryRetainedOnStart = true) { ElapsedInstant(0, 100u) }
            val receiving = async(start = CoroutineStart.UNDISPATCHED) { receiver.run() }
            wire.queue.send(mac.issued()); wire.queue.send(mac.status())
            enrollment.requestSessions.first { it.isNotEmpty() }.single().revisions.first { it == 1uL }
            assertTrue(wire.sent.tryReceive().isFailure)
            receiver.close(); receiving.await(); enrollment.close()
        }
    }

    private fun decisionCarrier() = ApprovalMessage(1u, ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION,
        byteArrayOf(0xa0.toByte()), ByteArray(64)).encode(bound.maxBytes)

    @Test fun decisionsAndReconnectQueriesShareOneWriter() = runBlocking<Unit> {
        withTimeout(3000) {
            val mac = Mac(); val enrollment = mac.enroll()
            deliver(enrollment, mac, mac.issued(), mac.status())
            mac.requestID = 9; deliver(enrollment, mac, mac.issued(), mac.status())
            val wire = Wire(scope()); val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
            val active = AtomicInteger(); val count = AtomicInteger()
            wire.onSend = {
                assertEquals(1, active.incrementAndGet())
                try { if (count.incrementAndGet() == 1) { entered.complete(Unit); release.await() } }
                finally { active.decrementAndGet() }
            }
            val receiver = CommandRequestReceiver.bind(enrollment, wire, id(3), id(4), queryRetainedOnStart = true) { ElapsedInstant(0, 100u) }
            val receiving = async { receiver.run() }; entered.await()
            val deciding = async(start = CoroutineStart.UNDISPATCHED) { receiver.sendDecision(decisionCarrier()) }
            assertEquals(1, count.get())
            release.complete(Unit); deciding.await()
            val output = List(3) { wire.sent.receive() }
            assertEquals(2, output.count { runCatching { RequestStatusQuery.decode(it) }.isSuccess })
            assertEquals(1, output.count { it.contentEquals(decisionCarrier()) })
            receiver.close(); receiving.await(); enrollment.close()
        }
    }

    @Test fun cancellationAndReconnectDoNotRetryAWaitingDecision() = runBlocking<Unit> {
        withTimeout(3000) {
            val mac = Mac(); val enrollment = mac.enroll()
            deliver(enrollment, mac, mac.issued(), mac.status())
            val owner = enrollment.sessions().single()
            val first = Wire(scope()); val entered = CompletableDeferred<Unit>()
            first.onSend = { entered.complete(Unit); awaitCancellation() }
            val receiver = CommandRequestReceiver.bind(enrollment, first, id(3), id(4), queryRetainedOnStart = true) { ElapsedInstant(0, 100u) }
            val receiving = launch { receiver.run() }; entered.await()
            val deciding = launch(start = CoroutineStart.UNDISPATCHED) { receiver.sendDecision(decisionCarrier()) }
            deciding.cancelAndJoin(); receiving.cancelAndJoin()
            assertTrue(first.closed); assertSame(owner, enrollment.sessions().single())
            val second = Wire(scope())
            val replacement = CommandRequestReceiver.bind(enrollment, second, id(3), id(4), queryRetainedOnStart = true) { ElapsedInstant(0, 200u) }
            val resumed = async { replacement.run() }
            assertEquals(owner.identity.requestID, RequestStatusQuery.decode(second.sent.receive()).requestID)
            assertTrue(second.sent.tryReceive().isFailure)
            replacement.close(); resumed.await(); enrollment.close()
        }
    }

    @Test fun queryWriteFailureClosesConnectionButKeepsOwner() = runBlocking<Unit> {
        withTimeout(3000) {
            val mac = Mac(); val enrollment = mac.enroll()
            deliver(enrollment, mac, mac.issued(), mac.status())
            val owner = enrollment.sessions().single(); val wire = Wire(scope()); var attempts = 0
            wire.onSend = { attempts++; throw IOException("Synthetic lost query") }
            val receiver = CommandRequestReceiver.bind(enrollment, wire, id(3), id(4), queryRetainedOnStart = true) { ElapsedInstant(0, 100u) }
            assertFailsWith<IOException> { receiver.run() }
            assertEquals(1, attempts); assertTrue(wire.closed); assertSame(owner, enrollment.sessions().single())
            enrollment.close()
        }
    }

    @Test fun decisionWriterRejectsReadOnlyQueriesAndMacMessages() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll(); val wire = Wire(scope()); val receiver = bind(enrollment, wire)
        for (bytes in listOf(mac.issued(), mac.status(), RequestStatusQuery(id(5)).encode())) {
            assertFails { receiver.sendDecision(bytes) }
        }
        assertTrue(wire.sent.tryReceive().isFailure)
        receiver.close(); enrollment.close()
    }

    @Test fun sharedMemoryCapacityPreservesExistingOwnersAndTerminalStatusReleasesCapture() = runBlocking<Unit> {
        val budget = CommandMemoryBudget(capture.size.toLong() + 2048, 10000)
        val firstInbox = CommandRequestInbox(1, 128, budget)
        val secondInbox = CommandRequestInbox(1, 128, budget)
        val a = Mac(); val b = Mac(8)
        val first = a.enroll(firstInbox); val second = b.enroll(secondInbox)
        deliver(first, a, a.issued(), a.status())
        val retained = first.sessions().single()
        // A duplicate needs no additional retained reservation.
        deliver(first, a, a.issued())
        assertSame(retained, first.sessions().single())
        deliver(second, b, b.issued())
        assertTrue(second.capacityLimited.value)
        assertTrue(second.sessions().isEmpty()); assertFalse(retained.closed.value)
        deliver(first, a, a.status(true))
        deliver(second, b, b.issued())
        assertEquals(1, second.sessions().size)
        firstInbox.close(); secondInbox.close()
        val third = a.enroll(CommandRequestInbox(1, 128, budget))
        deliver(third, a, a.issued()); third.close()
    }

    @Test fun capacityRejectionDoesNotBlockLaterStatusesOrRequestReplay() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired()
        val inbox = CommandRequestInbox(1, 1, CommandMemoryBudget(capture.size.toLong() + 1024, 10000))
        val enrollment = mac.enroll(inbox, index)
        val firstRequest = mac.issued(); val terminal = mac.status(true)
        mac.requestID = 9
        val nextRequest = mac.issued(); val nextStatus = mac.status()
        deliver(enrollment, mac, firstRequest, nextRequest, nextStatus, terminal, nextRequest, nextStatus)
        assertTrue(enrollment.capacityLimited.value)
        val next = enrollment.sessions().single()
        assertEquals(CborValue.Bytes(id(9)), next.identity.requestID)
        assertEquals(RequestPhase.PRESENTED, next.snapshot(ElapsedInstant(0, 100u)).status!!.status.phase)
        deliver(enrollment, mac, nextRequest, nextStatus)
        assertFalse(enrollment.capacityLimited.value)
        assertSame(next, enrollment.sessions().single())
        inbox.close()
    }

    @Test fun unknownStatusesAfterCapacityStillRequireTheEnrolledSignatureAndScope() = runBlocking<Unit> {
        for (wrongScope in listOf(false, true)) {
            val mac = Mac(); val enrollment = mac.enroll(CommandRequestInbox(1, 1))
            val first = mac.issued()
            mac.requestID = 9
            val skipped = mac.issued()
            val status = if (wrongScope) {
                val other = Mac(8)
                val body = ApprovalMessage.decode(other.status(), bound.maxBytes).body.copyBytes()
                mac.envelope(body, ApprovalMessageType.STATUS, SigningPurpose.STATUS)
            } else {
                val message = ApprovalMessage.decode(mac.status(), bound.maxBytes)
                ApprovalMessage(1u, message.type, message.purpose, message.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
            }
            assertFailsWith<IOException> { deliver(enrollment, mac, first, skipped, status) }
            assertTrue(enrollment.capacityLimited.value)
            assertEquals(CborValue.Bytes(id(5)), enrollment.sessions().single().identity.requestID)
            enrollment.close()
        }
    }

    @Test fun itemBudgetAndReservationReleaseAreIndependentOfByteCapacity() {
        val budget = CommandMemoryBudget(100000, 100)
        val first = budget.retain(100, 36)
        assertEquals(InboxRejection.CAPACITY, assertFailsWith<InboxException> { budget.retain(1, 1) }.reason)
        first.releaseCapture()
        // Terminal metadata remains reserved until retirement or closure.
        assertFailsWith<InboxException> { budget.retain(1, 1) }
        first.close(); first.close()
        budget.retain(999, 36).close()
    }

    @Test fun reconnectPreservesTimersAndTerminalOwnersInObservableState() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        deliver(enrollment, mac, mac.issued(), mac.status())
        val owner = enrollment.requestSessions.value.single()
        assertSame(owner, enrollment.sessions().single())
        val initial = owner.snapshot(ElapsedInstant(0, 100u)).status!!
        assertTrue(initial.timing.deliveryDelayUnknown)
        deliver(enrollment, mac, mac.issued(), mac.status(), time = 200u)
        assertSame(owner, enrollment.requestSessions.value.single())
        assertEquals(110uL, owner.snapshot(ElapsedInstant(0, 200u)).status!!.timing.ageLowerBoundMs)
        deliver(enrollment, mac, mac.status(true), mac.issued(), time = 300u)
        assertSame(owner, enrollment.requestSessions.value.single())
        assertNull(owner.snapshot(ElapsedInstant(0, 300u)).capture)
        assertEquals(RequestPhase.EXPIRED, owner.snapshot(ElapsedInstant(0, 300u)).status!!.status.phase)
    }
    @Test fun invalidSignatureAndCrossMacMessagesCannotPublishRequests() = runBlocking<Unit> {
        val mac = Mac(); val other = Mac(8); val enrollment = mac.enroll()
        val message = ApprovalMessage.decode(mac.issued(), bound.maxBytes)
        val bad = ApprovalMessage(1u, message.type, message.purpose, message.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
        for (bytes in listOf(bad, other.issued())) {
            assertFailsWith<IOException> { deliver(enrollment, mac, bytes) }
            assertTrue(enrollment.requestSessions.value.isEmpty())
        }
    }
    @Test fun statusesCannotCreateRequestsAndDecisionsCannotEnterPhoneInbox() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.status()) }
        val decision = mac.envelope(byteArrayOf(0xa0.toByte()), ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION)
        assertFailsWith<IOException> { deliver(enrollment, mac, decision) }
        assertTrue(enrollment.sessions().isEmpty())
    }
    @Test fun replacementClosesOldSocketAndRejectsItsLateCallback() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<ByteArray>()
        val oldWire = object : RequestMessageChannel {
            override val scope = scope()
            override val commandSchemas = setOf(1uL)
            override val maximumPayloadBytes = 65536
            var closed = false
            override suspend fun receive(): ByteArray? { entered.complete(Unit); return release.await() }
            override fun close() { closed = true }
        }
        val old = bind(enrollment, oldWire)
        val running = async { old.run() }
        entered.await()
        val replacement = Wire(scope()); val next = bind(enrollment, replacement)
        assertTrue(oldWire.closed)
        release.complete(mac.issued()); running.await()
        assertTrue(enrollment.sessions().isEmpty()); assertFalse(replacement.closed)
        replacement.queue.send(mac.issued()); replacement.queue.close(); next.run()
        assertEquals(1, enrollment.sessions().size)
    }
    @Test fun removingOneMacClosesItsPendingReadAndKeepsOtherMacState() = runBlocking<Unit> {
        val inbox = CommandRequestInbox(2, 4); val a = Mac(); val b = Mac(8)
        val first = a.enroll(inbox); val second = b.enroll(inbox)
        deliver(first, a, a.issued()); deliver(second, b, b.issued())
        val captured = first.sessions().single()
        val wire = Wire(scope()); val receiver = bind(first, wire)
        val running = async(start = CoroutineStart.UNDISPATCHED) { receiver.run() }
        assertTrue(inbox.remove(first)); running.await()
        assertTrue(wire.closed); assertTrue(captured.closed.value); assertTrue(first.requestSessions.value.isEmpty())
        assertFalse(second.sessions().single().closed.value)
    }
    @Test fun failedBindingClosesNewChannelWithoutDisplacingExistingReceiver() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        val current = Wire(scope()); val owner = bind(enrollment, current)
        for (wrong in listOf(Wire(scope(8)), Wire(scope(), supportsCommands = false), Wire(scope(), maximumPayloadBytes = 10))) {
            assertFails { bind(enrollment, wrong) }
            assertTrue(wrong.closed); assertFalse(current.closed)
        }
        current.queue.send(mac.issued()); current.queue.close(); owner.run()
        assertEquals(1, enrollment.sessions().size)
    }
    @Test fun cancellationClosesConnectionWithoutInventingTerminalOutcome() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        deliver(enrollment, mac, mac.issued(), mac.status())
        val wire = Wire(scope()); val receiver = bind(enrollment, wire)
        val running = launch(start = CoroutineStart.UNDISPATCHED) { receiver.run() }
        running.cancelAndJoin()
        assertTrue(wire.closed)
        val snapshot = enrollment.sessions().single().snapshot(ElapsedInstant(0, 100u))
        assertEquals(RequestPhase.PRESENTED, snapshot.status!!.status.phase); assertNotNull(snapshot.capture)
    }
    private class Retired : RetiredCommandRequests {
        val digests = mutableMapOf<CborValue.Bytes, ByteArray>()
        var failWrite = false
        var failRead = false
        var closed = false
        override fun lookup(requestID: ByteArray): ByteArray? {
            check(!closed && !failRead)
            return digests[CborValue.Bytes(requestID)]?.copyOf()
        }
        override fun remember(requestID: ByteArray, requestDigest: ByteArray) {
            check(!closed && !failWrite)
            val key = CborValue.Bytes(requestID)
            val previous = digests[key]
            check(previous == null || previous.contentEquals(requestDigest))
            digests[key] = requestDigest.copyOf()
        }
        override fun close() { closed = true }
    }

    @Test fun terminalReplacementReusesMetadataCapacityAndFailedPersistenceKeepsTheOwner() =
        checkTerminalReplacement(1)

    @Test fun sharedCapacityRetiresTerminalBeforeTheLocalWindowFills() = checkTerminalReplacement(128)

    private fun checkTerminalReplacement(window: Int) = runBlocking<Unit> {
        val budget = CommandMemoryBudget(capture.size.toLong() + 1024, 10000)
        val index = Retired(); val mac = Mac()
        val inbox = CommandRequestInbox(1, window, budget)
        val enrollment = mac.enroll(inbox, index)
        deliver(enrollment, mac, mac.issued(), mac.status(true))
        val previous = enrollment.sessions().single()
        mac.requestID = 9; index.failWrite = true
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertSame(previous, enrollment.sessions().single())
        assertFalse(previous.closed.value)
        index.failWrite = false
        deliver(enrollment, mac, mac.issued())
        assertTrue(previous.closed.value)
        assertEquals(CborValue.Bytes(id(9)), enrollment.sessions().single().identity.requestID)
        inbox.close()
    }

    @Test fun moreThan128RequestsRetireOnlyTerminalHandlesAndRejectReplays() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired(); val inbox = CommandRequestInbox(1, 128)
        val enrollment = mac.enroll(inbox, index)
        var first: CommandRequestSession? = null
        for (requestID in 1..200) {
            mac.requestID = requestID
            deliver(enrollment, mac, mac.issued(), mac.status(true))
            if (requestID == 1) first = enrollment.sessions().single()
        }
        assertEquals(128, enrollment.sessions().size)
        assertEquals(72, index.digests.size)
        assertTrue(checkNotNull(first).closed.value)
        val retained = enrollment.sessions()
        mac.requestID = 1
        deliver(enrollment, mac, mac.issued(), mac.status(), mac.status(true))
        assertEquals(retained, enrollment.sessions())
        assertEquals(128, enrollment.requestSessions.value.size)
        inbox.close(); assertTrue(index.closed)
    }

    @Test fun fullActiveWindowAndFailedRetirementKeepExistingRequests() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired(); val enrollment = mac.enroll(CommandRequestInbox(1, 2), index)
        mac.requestID = 1; deliver(enrollment, mac, mac.issued(), mac.status())
        mac.requestID = 2; deliver(enrollment, mac, mac.issued(), mac.status())
        val pending = enrollment.sessions()
        mac.requestID = 3
        deliver(enrollment, mac, mac.issued())
        assertTrue(enrollment.capacityLimited.value)
        assertEquals(pending, enrollment.sessions()); assertTrue(index.digests.isEmpty())
        mac.requestID = 1; deliver(enrollment, mac, mac.status(true))
        index.failWrite = true; mac.requestID = 3
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertEquals(pending, enrollment.sessions()); assertFalse(pending.first().closed.value)
        assertEquals(RequestPhase.EXPIRED, pending.first().snapshot(ElapsedInstant(0, 100u)).status!!.status.phase)
        index.failWrite = false
        deliver(enrollment, mac, mac.issued())
        assertTrue(pending.first().closed.value); assertFalse(pending.last().closed.value)
        assertEquals(RequestPhase.PRESENTED, pending.last().snapshot(ElapsedInstant(0, 100u)).status!!.status.phase)
    }

    @Test fun retiredMembershipNeverBypassesAuthenticationOrStorageErrors() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired(); val enrollment = mac.enroll(CommandRequestInbox(1, 1), index)
        mac.requestID = 1; deliver(enrollment, mac, mac.issued(), mac.status(true))
        mac.requestID = 2; deliver(enrollment, mac, mac.issued())
        mac.requestID = 1
        val message = ApprovalMessage.decode(mac.status(), bound.maxBytes)
        val bad = ApprovalMessage(1u, message.type, message.purpose, message.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
        assertFailsWith<IOException> { deliver(enrollment, mac, bad) }
        val request = ApprovalMessage.decode(mac.issued(), bound.maxBytes)
        val badRequest = ApprovalMessage(1u, request.type, request.purpose, request.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
        assertFailsWith<IOException> { deliver(enrollment, mac, badRequest) }
        mac.challengeValue = 9
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        mac.challengeValue = 6
        index.failRead = true
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertEquals(1, enrollment.sessions().size)
    }

    private fun snapshot(enrollment: CommandRequestEnrollment, wire: RequestMessageChannel) =
        CommandSnapshotReceiver.bind(enrollment, wire, id(3), id(4), 8u, 262_144u) { ElapsedInstant(0, 200u) }

    private fun Wire.snapshotReply(frames: List<ByteArray>, complete: Boolean = true) {
        onSend = { encoded ->
            val query = assertIs<PendingRequestSnapshotFrame.Query>(PendingRequestSnapshotFrame.decode(encoded))
            frames.forEachIndexed { index, bytes ->
                queue.send(PendingRequestSnapshotFrame.Item(query.nonce.copyBytes(), index.toULong(), bytes).encode())
            }
            if (complete) queue.send(PendingRequestSnapshotFrame.Complete(query.nonce.copyBytes(), frames.size.toULong(),
                frames.sumOf { it.size.toLong() }.toULong()).encode())
            queue.close()
        }
    }
    @Test fun snapshotConnectorBudgetAlsoHoldsTheLargestRetainedQuery() = runBlocking<Unit> {
        val retained = List(PendingRequestSnapshotFrame.MAXIMUM_RETAINED_REQUESTS) { index ->
            ByteArray(16).apply { this[14] = (index ushr 8).toByte(); this[15] = index.toByte() }
        }
        val query = PendingRequestSnapshotFrame.Query(id(9, 32), PendingRequestSnapshotFrame.MAXIMUM_FRAMES,
            PendingRequestSnapshotFrame.MAXIMUM_SNAPSHOT_BYTES, retained)
        val wire = Wire(scope(), maximumPayloadBytes = CommandSnapshotReceiver.requiredChannelPayloadBytes(limits))
        wire.snapshotReply(emptyList())
        val channel = PendingSnapshotMessageChannel(wire, query)
        try {
            assertNull(channel.receive()); channel.requireComplete()
            assertEquals(retained.size, (PendingRequestSnapshotFrame.decode(wire.sent.receive()) as PendingRequestSnapshotFrame.Query).retainedRequestIDs.size)
        } finally { channel.close() }
    }

    @Test fun snapshotConnectorBudgetReservesBothFrameLayers() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        val foregroundBudget = maxOf(limits.body.maxBytes, limits.status.maxBytes) + ApprovalMessage.OVERHEAD_BYTES
        val snapshotBudget = CommandSnapshotReceiver.requiredChannelPayloadBytes(limits)
        assertTrue(snapshotBudget >= foregroundBudget + 128)
        val tooSmall = Wire(scope(), maximumPayloadBytes = foregroundBudget)
        assertFails { snapshot(enrollment, tooSmall) }
        assertTrue(tooSmall.closed); assertTrue(tooSmall.sent.tryReceive().isFailure)
        val reserved = Wire(scope(), maximumPayloadBytes = snapshotBudget)
        reserved.snapshotReply(listOf(mac.issued(), mac.status()))
        snapshot(enrollment, reserved).run()
        assertTrue(reserved.closed); assertEquals(1, enrollment.sessions().size)
        enrollment.close()
    }

    @Test fun snapshotVerifiesEachFrameAndRequiresExactCompletion() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll(); val wire = Wire(scope())
        wire.snapshotReply(listOf(mac.issued(), mac.status()))
        snapshot(enrollment, wire).run()
        val retained = enrollment.sessions().single()
        assertEquals(RequestPhase.PRESENTED, retained.snapshot(ElapsedInstant(0, 200u)).status!!.status.phase)
        val query = assertIs<PendingRequestSnapshotFrame.Query>(PendingRequestSnapshotFrame.decode(wire.sent.receive()))
        assertTrue(query.retainedRequestIDs.isEmpty()); assertTrue(wire.sent.tryReceive().isFailure); assertTrue(wire.closed)
        enrollment.close()
    }
    @Test fun snapshotEarlyEofAndExplicitCloseCannotSucceed() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll(); val partial = Wire(scope())
        partial.snapshotReply(listOf(mac.issued()), complete = false)
        assertFailsWith<IOException> { snapshot(enrollment, partial).run() }
        val retained = enrollment.sessions().single()
        val closed = Wire(scope()); val receiver = snapshot(enrollment, closed)
        receiver.close()
        assertFailsWith<IOException> { receiver.run() }
        assertSame(retained, enrollment.sessions().single()); assertTrue(closed.sent.tryReceive().isFailure)
        enrollment.close()
    }
    @Test fun snapshotCannotReplaceForegroundAndForegroundCanPreemptIt() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll(); val first = Wire(scope()); val foreground = bind(enrollment, first)
        val rejected = Wire(scope())
        assertFailsWith<IOException> { snapshot(enrollment, rejected) }
        assertFalse(first.closed); assertTrue(rejected.closed)
        foreground.close()
        val background = Wire(scope()); val snapshot = snapshot(enrollment, background)
        val current = Wire(scope()); val next = bind(enrollment, current)
        assertTrue(background.closed); assertFalse(current.closed)
        assertFailsWith<IOException> { snapshot.run() }
        snapshot.close()
        current.queue.send(mac.issued()); current.queue.send(mac.status()); current.queue.close()
        next.run(); assertEquals(1, enrollment.sessions().size)
        enrollment.close()
    }
    @Test fun snapshotRefreshesRetainedTerminalStatusWithoutReplacingTheOwner() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        deliver(enrollment, mac, mac.issued(), mac.status())
        val retained = enrollment.sessions().single(); val wire = Wire(scope())
        wire.snapshotReply(listOf(mac.status(true)))
        snapshot(enrollment, wire).run()
        val query = assertIs<PendingRequestSnapshotFrame.Query>(PendingRequestSnapshotFrame.decode(wire.sent.receive()))
        assertEquals(listOf(CborValue.Bytes(id(5))), query.retainedRequestIDs)
        assertSame(retained, enrollment.sessions().single())
        assertEquals(RequestPhase.EXPIRED, retained.snapshot(ElapsedInstant(0, 200u)).status!!.status.phase)
        enrollment.close()
    }
    @Test fun snapshotEmptySetCannotExpireAnOmittedRetainedRequest() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        deliver(enrollment, mac, mac.issued(), mac.status())
        val retained = enrollment.sessions().single(); val wire = Wire(scope()); wire.snapshotReply(emptyList())
        snapshot(enrollment, wire).run()
        assertSame(retained, enrollment.sessions().single())
        assertEquals(RequestPhase.PRESENTED, retained.snapshot(ElapsedInstant(0, 200u)).status!!.status.phase)
        enrollment.close()
    }
    @Test fun snapshotMarkerCannotAuthenticateAFrameFromAnotherKey() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll(); val wrong = Mac(); val wire = Wire(scope())
        wire.snapshotReply(listOf(wrong.issued()))
        assertFailsWith<IOException> { snapshot(enrollment, wire).run() }
        assertTrue(enrollment.sessions().isEmpty()); assertTrue(wire.closed)
        enrollment.close()
    }
    @Test fun snapshotChannelCannotSendDecisions() = runBlocking<Unit> {
        val wire = Wire(scope())
        val channel = PendingSnapshotMessageChannel(wire, PendingRequestSnapshotFrame.Query(ByteArray(32), 8u, 262_144u))
        assertFailsWith<IOException> { channel.send(decisionCarrier()) }
        assertTrue(wire.sent.tryReceive().isFailure); channel.close()
    }
    @Test fun snapshotCapacityOmissionStaysFailedAfterForegroundResetsTheUiFlag() = runBlocking<Unit> {
        for (handoff in listOf(false, true)) {
            val mac = Mac(); val enrollment = mac.enroll(CommandRequestInbox(1, 1)); val first = mac.issued()
            mac.requestID = 9
            val wire = Wire(scope()); wire.snapshotReply(listOf(first, mac.issued(), mac.status()))
            var foreground: CommandRequestReceiver? = null
            if (handoff) wire.onClose = { foreground = bind(enrollment, Wire(scope())) }
            assertFailsWith<IOException> { snapshot(enrollment, wire).run() }
            assertEquals(1, enrollment.sessions().size)
            assertEquals(!handoff, enrollment.capacityLimited.value)
            foreground?.close(); enrollment.close()
        }
    }
}
