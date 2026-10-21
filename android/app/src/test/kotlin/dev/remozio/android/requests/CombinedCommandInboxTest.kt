package dev.remozio.android.requests

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.*
import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Test
import kotlin.test.*

class CombinedCommandInboxTest {
    private val bounds = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bounds, bounds, bounds, bounds)
    private fun id(n: Int, size: Int = 16) = ByteArray(size) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private inner class Peer(recordID: Int, macID: Int, accountID: Int) : AutoCloseable {
        private val authority = pair()
        private val mac = id(macID); private val account = id(accountID)
        var opens = 0
        private lateinit var enrollment: CommandRequestEnrollment
        private fun reference(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val key = pair()
            return EnrollmentKeyReference(role, id(10 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(10 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) key.public.encoded else key.public.encoded.takeLast(65).toByteArray())
        }
        private val record = StoredPhoneEnrollment(PhoneEnrollment(id(recordID), mac, account, id(101), id(102),
            "Synthetic Mac", authority.public.encoded.takeLast(65).toByteArray(), pair().public.encoded,
            reference(EnrollmentKeyRole.TRANSPORT), reference(EnrollmentKeyRole.DECISION), reference(EnrollmentKeyRole.BIOMETRIC), id(6, 32), null), EnrollmentPhase.ACTIVE)
        val connection = CommandConnection(record, limits, { _, e ->
            opens++; enrollment = e
            object : CommandConnectionWire {
                override suspend fun receive() { awaitCancellation() }
                override suspend fun send(bytes: ByteArray) = Unit
                override fun close() = Unit
            }
        }, { ElapsedInstant(0, 100u) }, dispatcher = Dispatchers.Unconfined)
        val owner = StoredCommandOwner(record.enrollment.recordID, record.enrollment.macID, record.enrollment.accountID, record.enrollment.label, connection)
        fun issue(requestID: Int = 7): CommandRequestSession {
            val request = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 1u), mac, account, id(requestID), id(8, 32),
                emptySet(), 1u, 60001u, File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes(),
                listOf(CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest), CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), bounds, bounds)
            val body = request.encode(bounds)
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(authority.private)
                update(SigningInput.make(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, body, bounds, bounds)); sign()
            })
            return enrollment.accept(body, signature)
        }
        fun status(session: CommandRequestSession, revision: ULong = 1u, remaining: ULong? = 59_000u) {
            val terminal = remaining == null
            val body = RequestStatusPayload(mac, account, session.identity.requestID.copyBytes(), session.issuedRequestDigest.copyBytes(), id(8, 32), revision,
                if (terminal) RequestPhase.CANCELLED else RequestPhase.PRESENTED,
                if (terminal) RequestStatusReason.USER_CANCELLED else RequestStatusReason.NONE,
                id(20), 1000u, remaining, null, false, if (terminal) 1000u else null, null).encode(bounds)
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(authority.private); update(SigningInput.make(1u, ApprovalMessageType.STATUS, SigningPurpose.STATUS, body, bounds, bounds)); sign()
            })
            session.observe(body, signature, ElapsedInstant(0, 100u))
        }
        override fun close() = connection.close()
    }

    @Test fun equalRequestIDsAndLabelsRemainDistinctAcrossMacsAndAccounts() = runBlocking<Unit> {
        val peers = listOf(Peer(1, 20, 100), Peer(2, 21, 100), Peer(3, 20, 101))
        val jobs = peers.map { launch(start = CoroutineStart.UNDISPATCHED) { it.connection.run() } }
        try {
            peers.forEach { it.issue() }
            val rows = withTimeout(5000) { observeCommandInbox(peers.map { it.owner }).first { it.size == 3 } }
            assertEquals(1, rows.map { it.session.identity.requestID }.toSet().size)
            assertEquals(3, rows.map { it.key }.toSet().size)
            rows.forEach { assertTrue(it.isCurrent(peers.map { p -> p.owner })) }
            assertEquals(2, peers.map { commandMacLabel(it.owner, peers.map { p -> p.owner }) }.toSet().size)
            assertNotEquals(commandAccountSuffix(peers[0].owner, peers.map { it.owner }), commandAccountSuffix(peers[2].owner, peers.map { it.owner }))
        } finally { peers.forEach { it.close() }; jobs.forEach { it.cancelAndJoin() } }
    }

    @Test fun observingAndFilteringNeverOpenAnotherTransportOrReplaceSelection() = runBlocking<Unit> {
        val a = Peer(1, 20, 100); val b = Peer(2, 21, 100); val owners = listOf(a.owner, b.owner)
        val jobs = listOf(a, b).map { launch(start = CoroutineStart.UNDISPATCHED) { it.connection.run() } }
        try {
            val original = a.issue(); b.issue()
            val selected = observeCommandInbox(owners).first().single { it.session === original }
            repeat(3) {
                val filtered = observeCommandInbox(owners).first().filter { it.owner.recordID == b.owner.recordID }
                assertEquals(1, filtered.size); assertTrue(selected.isCurrent(owners))
            }
            a.issue(9)
            val arrived = observeCommandInbox(owners).first { it.size == 3 }
            assertSame(original, arrived.single { it.key == selected.key }.session)
            assertTrue(selected.isCurrent(owners)); assertEquals(1, a.opens); assertEquals(1, b.opens)
            assertEquals("ScopedCommandRequest(redacted)", selected.toString())
        } finally { a.close(); b.close(); jobs.forEach { it.cancelAndJoin() } }
    }

    @Test fun selectionCannotCrossEnrollmentReplacementOrSurviveRemoval() = runBlocking<Unit> {
        val old = Peer(1, 20, 100); val replacement = Peer(2, 20, 100)
        val job = launch(start = CoroutineStart.UNDISPATCHED) { old.connection.run() }
        try {
            old.issue(); val selected = observeCommandInbox(listOf(old.owner)).first().single()
            assertFalse(selected.isCurrent(emptyList()))
            assertFalse(selected.isCurrent(listOf(replacement.owner)))
            val sameIDReplacement = StoredCommandOwner(old.owner.recordID, old.owner.macID, old.owner.accountID, old.owner.label, replacement.connection)
            assertFalse(selected.isCurrent(listOf(sameIDReplacement)))
            assertFailsWith<IllegalArgumentException> { ScopedCommandRequest(replacement.owner, selected.session) }
            old.close(); assertFalse(selected.isCurrent(listOf(old.owner)))
        } finally { old.close(); replacement.close(); job.cancelAndJoin() }
    }

    @Test fun labelsExpandCollidingPrefixesWithoutMergingIdentities() {
        fun bytes(last: Int) = CborValue.Bytes(ByteArray(16).also { it[15] = last.toByte() })
        val a = StoredCommandOwner(bytes(10), bytes(1), bytes(3), "Equal label", null)
        val b = StoredCommandOwner(bytes(11), bytes(2), bytes(3), "Equal label", null)
        val account = StoredCommandOwner(bytes(12), bytes(1), bytes(4), "Equal label", null)
        val owners = listOf(a, b, account)
        assertNotEquals(commandMacLabel(a, owners), commandMacLabel(b, owners))
        assertEquals(commandMacLabel(a, owners), commandMacLabel(account, owners))
        assertNotEquals(commandAccountSuffix(a, owners), commandAccountSuffix(account, owners))
        assertTrue(commandMacLabel(a, owners).endsWith(commandIdentityText(a.macID)))
    }

    @Test fun emptyAndUnavailableOwnersProduceAnEmptyProjection() = runBlocking<Unit> {
        assertTrue(observeCommandInbox(emptyList()).first().isEmpty())
        val peer = Peer(1, 20, 100)
        try {
            val absent = StoredCommandOwner(peer.owner.recordID, peer.owner.macID, peer.owner.accountID, peer.owner.label, null)
            assertTrue(observeCommandInbox(listOf(absent)).first().isEmpty()); assertEquals(0, peer.opens)
        } finally { peer.close() }
    }

    @Test fun notificationTargetsRoundTripStrictlyAndDoNotMatchAnotherScopeOrDigest() = runBlocking<Unit> {
        val a = Peer(1, 20, 100); val b = Peer(2, 21, 100)
        val jobs = listOf(a,b).map { launch(start = CoroutineStart.UNDISPATCHED) { it.connection.run() } }
        try {
            a.issue(); b.issue()
            val rows = observeCommandInbox(listOf(a.owner,b.owner)).first()
            val first = rows.single { it.owner === a.owner }; val second = rows.single { it.owner === b.owner }
            val target = CommandNotificationTarget.from(first)
            assertTrue(assertNotNull(CommandNotificationTarget.decode(target.encode())).matches(first))
            assertFalse(target.matches(second)); assertNotEquals(target.encode(), CommandNotificationTarget.from(second).encode())
            assertEquals("CommandNotificationTarget(redacted)", target.toString())
            listOf(null, "", target.encode()+":00", target.encode().uppercase(), target.encode().replace(":v1:",":v2:"),
                "https://example.test/"+target.encode(), target.encode().dropLast(1), target.encode().replaceFirst("request", "inbox")).forEach {
                assertNull(CommandNotificationTarget.decode(it))
            }
            val wrongDigest = CommandNotificationTarget(target.recordID,target.macID,target.accountID,target.epoch,target.requestID,CborValue.Bytes(ByteArray(32)))
            assertFalse(wrongDigest.matches(first))
            val wrongEpoch = CommandNotificationTarget(target.recordID,target.macID,target.accountID,CborValue.Bytes(id(9)),target.requestID,target.digest)
            assertFalse(wrongEpoch.matches(first))
            val copied = first.session.issuedRequestDigest.copyBytes(); copied.fill(0)
            assertTrue(target.matches(first))
        } finally { a.close();b.close();jobs.forEach { it.cancelAndJoin() } }
    }

    @Test fun aNotificationQueuesBehindAnOpenReviewAndResolvesAfterDismissal() = runBlocking<Unit> {
        val a=Peer(1,20,100);val b=Peer(2,21,100);val owners=listOf(a.owner,b.owner)
        val jobs=listOf(a,b).map { launch(start=CoroutineStart.UNDISPATCHED) { it.connection.run() } }
        try {
            val aSession=a.issue();val bSession=b.issue();a.status(aSession);b.status(bSession)
            val rows=observeCommandInbox(owners).first()
            val first=rows.single { it.owner===a.owner };val second=rows.single { it.owner===b.owner }
            val nav=CommandInboxNavigation { ElapsedInstant(0, 100u) };nav.show(first);nav.request(CommandNotificationTarget.from(second))
            val pending=assertNotNull(nav.state.value.pending)
            nav.synchronize(owners,rows,true);nav.expire(pending.serial)
            assertSame(first,nav.state.value.selected);assertNotNull(nav.state.value.pending)
            nav.show(second);assertSame(first,nav.state.value.selected)
            nav.dismiss();nav.synchronize(owners,rows,true)
            assertSame(second,nav.state.value.selected);assertNull(nav.state.value.pending)
            b.close();nav.synchronize(emptyList(),emptyList(),false);assertNull(nav.state.value.selected)
        } finally { a.close();b.close();jobs.forEach { it.cancelAndJoin() } }
    }

    @Test fun navigationWaitsForAuthenticatedArrivalAndOldTimeoutCannotOverrideANewerTap() = runBlocking<Unit> {
        val peer=Peer(1,20,100);val job=launch(start=CoroutineStart.UNDISPATCHED) { peer.connection.run() }
        try {
            val session=peer.issue();peer.status(session)
            val row=observeCommandInbox(listOf(peer.owner)).first().single();val target=CommandNotificationTarget.from(row)
            val nav=CommandInboxNavigation { ElapsedInstant(0, 100u) };nav.request(target);val old=assertNotNull(nav.state.value.pending).serial
            nav.synchronize(listOf(peer.owner),emptyList(),true);assertNull(nav.state.value.selected);assertNotNull(nav.state.value.pending)
            nav.request(target);nav.expire(old);assertNotNull(nav.state.value.pending)
            nav.synchronize(listOf(peer.owner),listOf(row),false);assertNull(nav.state.value.selected)
            nav.synchronize(listOf(peer.owner),listOf(row),true,canOpen=false);assertNull(nav.state.value.selected)
            nav.synchronize(listOf(peer.owner),listOf(row),true);assertSame(row,nav.state.value.selected)
            nav.dismiss();nav.request(target);nav.expire(assertNotNull(nav.state.value.pending).serial)
            assertTrue(nav.state.value.unavailable);assertNull(nav.state.value.selected)
            nav.request(null);assertFalse(nav.state.value.unavailable);assertTrue(nav.state.value.inboxRequested)
            assertTrue(nav.state.value.showAllScopes);nav.allScopesShown();assertFalse(nav.state.value.showAllScopes)
            nav.inboxShown();assertFalse(nav.state.value.inboxRequested)
        } finally { peer.close();job.cancelAndJoin() }
    }

    @Test fun changedDigestEpochOrEnrollmentCannotFallBackToARequestWithTheSameID() = runBlocking<Unit> {
        val peer=Peer(1,20,100);val job=launch(start=CoroutineStart.UNDISPATCHED) { peer.connection.run() }
        try {
            peer.issue();val row=observeCommandInbox(listOf(peer.owner)).first().single();val target=CommandNotificationTarget.from(row)
            val wrong=CommandNotificationTarget(target.recordID,target.macID,target.accountID,target.epoch,target.requestID,CborValue.Bytes(ByteArray(32)))
            val nav=CommandInboxNavigation { ElapsedInstant(0, 100u) };nav.request(wrong);nav.synchronize(listOf(peer.owner),listOf(row),true)
            assertNull(nav.state.value.selected);nav.expire(assertNotNull(nav.state.value.pending).serial);assertTrue(nav.state.value.unavailable)
            nav.request(target);nav.synchronize(emptyList(),listOf(row),true)
            assertNull(nav.state.value.selected);assertTrue(nav.state.value.unavailable)
            nav.request(target);nav.cancelPending();nav.synchronize(listOf(peer.owner),listOf(row),true)
            assertNull(nav.state.value.selected);assertNull(nav.state.value.pending)
        } finally { peer.close();job.cancelAndJoin() }
    }

    @Test fun notificationNavigationWaitsForSignedStatusAndRejectsRetainedTerminalOrExpiredRequests() = runBlocking<Unit> {
        val peer=Peer(1,20,100);val owners=listOf(peer.owner)
        val job=launch(start=CoroutineStart.UNDISPATCHED) { peer.connection.run() }
        var now=ElapsedInstant(0,100u)
        val nav=CommandInboxNavigation { now }
        try {
            val session=peer.issue();val rows=observeCommandInbox(owners).first();val target=CommandNotificationTarget.from(rows.single())
            nav.request(target);nav.synchronize(owners,rows,true)
            assertNull(nav.state.value.selected);assertNotNull(nav.state.value.pending)
            val updates=async(start=CoroutineStart.UNDISPATCHED) {
                observeCommandInbox(owners).first { it.single().session.snapshot(now).status != null }
            }
            peer.status(session);val authenticated=withTimeout(5000) { updates.await() }
            nav.synchronize(owners,authenticated,true);assertSame(session,assertNotNull(nav.state.value.selected).session)
            nav.dismiss();peer.status(session,2u,null)
            assertFalse(session.closed.value);assertTrue(rows.single().isCurrent(owners))
            nav.request(target);nav.synchronize(owners,rows,true)
            assertNull(nav.state.value.selected);assertNull(nav.state.value.pending);assertTrue(nav.state.value.unavailable)
            val pending=peer.issue(9);peer.status(pending,remaining=0u)
            val expired=observeCommandInbox(owners).first().single { it.session===pending }
            nav.request(CommandNotificationTarget.from(expired));nav.synchronize(owners,listOf(expired),true)
            assertNull(nav.state.value.selected);assertNull(nav.state.value.pending);assertTrue(nav.state.value.unavailable)
            val aging=peer.issue(10);peer.status(aging)
            val agingRow=observeCommandInbox(owners).first().single { it.session===aging }
            now=ElapsedInstant(0,59_100u)
            nav.request(CommandNotificationTarget.from(agingRow));nav.synchronize(owners,listOf(agingRow),true)
            assertNull(nav.state.value.selected);assertTrue(nav.state.value.unavailable)
        } finally { peer.close();job.cancelAndJoin() }
    }

    @Test fun onlySignedPendingStatusPostsAnAlertAndTerminalStatusCancelsIt() = runBlocking<Unit> {
        val peer=Peer(1,20,100);val job=launch(start=CoroutineStart.UNDISPATCHED) { peer.connection.run() }
        val posted=mutableListOf<Pair<CommandNotificationTarget,Long>>();val cancelled=mutableListOf<CommandNotificationTarget>()
        val alerts=CommandRequestNotifications({ ElapsedInstant(0,100u) }, { t,l->posted+=t to l }, { cancelled+=it })
        val observing=alerts.observe(this,peer.connection)
        try {
            val session=peer.issue();repeat(10) { yield() };assertTrue(posted.isEmpty())
            peer.status(session)
            withTimeout(5000) { while(posted.isEmpty()) yield() }
            assertEquals(59_000L,posted.single().second)
            val row=observeCommandInbox(listOf(peer.owner)).first().single();assertTrue(posted.single().first.matches(row))
            peer.status(session,2u,null)
            withTimeout(5000) { while(cancelled.isEmpty()) yield() }
            assertEquals(posted.single().first.encode(),cancelled.single().encode())
        } finally { peer.close();observing.cancelAndJoin();job.cancelAndJoin() }
    }

    @Test fun localNotificationFailureDoesNotStopUpdatesAndRetirementCancelsAttempts() = runBlocking<Unit> {
        val peer=Peer(1,20,100);val job=launch(start=CoroutineStart.UNDISPATCHED) { peer.connection.run() }
        var posts=0;val cancelled=mutableListOf<CommandNotificationTarget>()
        val alerts=CommandRequestNotifications({ ElapsedInstant(0,100u) }, { _,_->posts++;if(posts==1) error("Synthetic publisher failure") }, { cancelled+=it })
        val observing=alerts.observe(this,peer.connection)
        try {
            val session=peer.issue();peer.status(session)
            withTimeout(5000) { while(posts<1) yield() }
            assertTrue(observing.isActive);peer.status(session,2u,58_000u)
            withTimeout(5000) { while(posts<2) yield() }
            peer.close();withTimeout(5000) { observing.join() }
            assertTrue(cancelled.isNotEmpty())
        } finally { peer.close();observing.cancelAndJoin();job.cancelAndJoin() }
    }

}
