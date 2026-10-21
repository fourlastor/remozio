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
}
