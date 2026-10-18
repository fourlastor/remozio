package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.*

class CommandRequestSessionTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val pair = newKey()
    private val mac = ByteArray(16) { 1 }
    private val account = ByteArray(16) { 2 }
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private val request = request()
    private fun request(schema: ULong = 1u, features: Set<ULong> = emptySet(), capture: ByteArray = this.capture) =
        IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, schema), mac, account, ByteArray(16) { 3 },
            ByteArray(32) { 4 }, features, 1000u, 61000u, capture,
            listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), bound, bound)
    private fun open(request: IssuedRequestPayload = this.request): CommandRequestSession {
        val body = request.encode(bound)
        return CommandRequestSession.open(body, sign(body), mac, account, publicKey(pair), limits)
    }
    private fun time(ms: ULong = 100u) = ElapsedInstant(0, ms)
    private fun status(revision: ULong = 1u, terminal: Boolean = false) = RequestStatusPayload(
        mac, account, request.requestID, request.requestDigest(bound, bound), request.challenge,
        revision, if (terminal) RequestPhase.EXPIRED else RequestPhase.PRESENTED,
        if (terminal) RequestStatusReason.AUTHORIZATION_EXPIRED else RequestStatusReason.NONE,
        ByteArray(16) { 5 }, if (terminal) 60_000u else 1000u, if (terminal) null else 59_000u,
        null, false, if (terminal) 60_000u else null, null,
    )
    private fun observe(session: CommandRequestSession, status: RequestStatusPayload, at: ULong = 100u): StatusAcceptance {
        val body = status.encode(bound)
        return session.observe(body, sign(body, status = true), time(at))
    }

    @Test fun authenticatesCommandBeforeExposingDetailsAndCopiesInputs() {
        val body = request.encode(bound)
        val key = publicKey(pair)
        val signature = sign(body)
        val session = CommandRequestSession.open(body, signature, mac, account, key, limits)
        body.fill(0); key.fill(0); signature.fill(0)
        val snapshot = session.snapshot(time())
        assertNotNull(snapshot.capture)
        assertNull(snapshot.status)
        assertEquals(0uL, session.revisions.value)
        assertEquals(StatusAcceptance.APPLIED, observe(session, status()))
        assertEquals(1uL, session.revisions.value)
        assertNotNull(session.snapshot(time()).capture)
    }

    @Test fun rejectsWrongKeyDomainSignatureAndEnrollmentBeforeExposure() {
        val body = request.encode(bound)
        fun rejected(signature: ByteArray, expectedMac: ByteArray = mac, expectedAccount: ByteArray = account,
            reason: CommandSessionRejection = CommandSessionRejection.INVALID_SIGNATURE) {
            assertEquals(reason, assertFailsWith<CommandSessionException> {
                CommandRequestSession.open(body, signature, expectedMac, expectedAccount, publicKey(pair), limits)
            }.reason)
        }
        rejected(sign(body, key = newKey()))
        rejected(sign(body, status = true))
        rejected(ByteArray(64))
        rejected(ByteArray(63))
        rejected(sign(body), expectedMac = account, reason = CommandSessionRejection.WRONG_AUTHORITY)
        rejected(sign(body), expectedAccount = mac, reason = CommandSessionRejection.WRONG_AUTHORITY)
    }

    @Test fun rejectsUnsupportedContractsFeaturesAndCaptureSemantics() {
        assertEquals(IssuedRequestFailure.UNSUPPORTED_CONTRACT,
            assertFailsWith<IssuedRequestException> { open(request(schema = 2u)) }.reason)
        assertEquals(IssuedRequestFailure.UNSUPPORTED_FEATURES,
            assertFailsWith<IssuedRequestException> { open(request(features = setOf(1u))) }.reason)
        assertFailsWith<CommandCaptureException> { open(request(capture = byteArrayOf(0xa0.toByte()))) }
        assertFailsWith<CborException> {
            CommandRequestSession.open(ByteArray(bound.maxBytes + 1), ByteArray(64), mac, account, publicKey(pair), limits)
        }
    }

    private fun captureVersion(version: ULong): ByteArray {
        val root = (DeterministicCbor.decode(capture, bound) as CborValue.Fields).values
        return DeterministicCbor.encode(CborValue.Fields(root + (0uL to CborValue.Unsigned(version))), bound)
    }

    @Test fun signedContractMustMatchInnerCaptureAndNegotiatedSchema() {
        fun negotiated(request: IssuedRequestPayload, schemas: Set<ULong>): CommandRequestSession {
            val body = request.encode(bound)
            return CommandRequestSession.open(body, sign(body), mac, account, publicKey(pair), limits, schemas)
        }
        negotiated(request(schema = 2u, capture = captureVersion(2u)), setOf(1u, 2u)).use {
            assertEquals(2uL, it.snapshot(time()).capture!!.schemaVersion)
        }
        negotiated(request, setOf(1u, 2u)).close()
        assertEquals(CommandCaptureFailure.VERSION, assertFailsWith<CommandCaptureException> {
            negotiated(request(schema = 1u, capture = captureVersion(2u)), setOf(1u, 2u))
        }.reason)
        assertEquals(CommandCaptureFailure.VERSION, assertFailsWith<CommandCaptureException> {
            negotiated(request(schema = 2u), setOf(1u, 2u))
        }.reason)
        assertEquals(IssuedRequestFailure.UNSUPPORTED_CONTRACT, assertFailsWith<IssuedRequestException> {
            negotiated(request(schema = 2u, capture = captureVersion(2u)), setOf(1u))
        }.reason)
        assertFailsWith<IllegalArgumentException> { negotiated(request, setOf(5u)) }
    }

    @Test fun schemaThreeRequiresExplicitNegotiationAndExposesTheAuthenticatedStreamLayout() {
        val capture = schemaThreeCapture("schema3-terminal-mask-0")
        val issued = request(schema = 3u, capture = capture)
        val body = issued.encode(bound)
        val signature = sign(body)
        assertEquals(IssuedRequestFailure.UNSUPPORTED_CONTRACT, assertFailsWith<IssuedRequestException> {
            CommandRequestSession.open(body, signature, mac, account, publicKey(pair), limits)
        }.reason)
        CommandRequestSession.open(body, signature, mac, account, publicKey(pair), limits, setOf(3u)).use { session ->
            val parsed = assertNotNull(session.snapshot(time()).capture)
            assertContentEquals(capture, parsed.canonicalBytes)
            val layout = assertNotNull(parsed.stdioLayout)
            assertEquals(0u, layout.ptyMask)
            assertEquals(CommandInputKind.PIPE, layout.input.source.kind)
            assertEquals(CommandInputKind.FILE, layout.output.source.kind)
            assertTrue(layout.output.flags.append)
            assertEquals(CommandInputKind.SOCKET, layout.error.source.kind)
            assertNotNull(layout.terminal)
        }
        val altered = request(schema = 3u, capture = schemaThreeCapture("schema3-terminal-mask-1")).encode(bound)
        assertEquals(CommandSessionRejection.INVALID_SIGNATURE, assertFailsWith<CommandSessionException> {
            CommandRequestSession.open(altered, signature, mac, account, publicKey(pair), limits, setOf(3u))
        }.reason)
    }

    @Test fun schemaFourRequiresAuthenticatedSelectedContractAndPreservesLinuxRequester() {
        val bytes = schemaFourCapture()
        val issued = request(schema = 4u, capture = bytes)
        val body = issued.encode(bound)
        val signature = sign(body)
        assertEquals(IssuedRequestFailure.UNSUPPORTED_CONTRACT, assertFailsWith<IssuedRequestException> {
            CommandRequestSession.open(body, signature, mac, account, publicKey(pair), limits)
        }.reason)
        CommandRequestSession.open(body, signature, mac, account, publicKey(pair), limits, setOf(4u)).use { session ->
            val parsed = assertIs<LinuxCommandCapture>(session.snapshot(time()).capture)
            assertContentEquals(bytes, parsed.canonicalBytes)
            assertEquals("linux-protected-single-thread-v1", parsed.requester.profile)
            assertEquals(4uL, parsed.schemaVersion)
            assertEquals(AncestryReason.UNSUPPORTED, parsed.ancestry.reason)
            assertNull(parsed.stdioLayout?.terminal)
            assertFails { session.withPendingDecision(time(), ByteArray(16), ByteArray(16),
                CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)) { } }
            val status = RequestStatusPayload(mac, account, issued.requestID, issued.requestDigest(bound, bound), issued.challenge,
                1u, RequestPhase.PRESENTED, RequestStatusReason.NONE, ByteArray(16) { 5 }, 1000u, 59000u, null, false, null, null)
            val statusBody = status.encode(bound)
            session.observe(statusBody, sign(statusBody, status = true), time())
            session.withPendingDecision(time(), ByteArray(16), ByteArray(16), CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)) {
                assertContentEquals(issued.requestDigest(bound, bound), it.requestDigest)
                assertContentEquals(issued.macID, it.macID)
            }
        }
        val changed = (DeterministicCbor.decode(bytes, bound) as CborValue.Fields).values.toMutableMap()
        changed[11u] = CborValue.Text("synthetic changed rationale")
        val tampered = request(schema = 4u, capture = DeterministicCbor.encode(CborValue.Fields(changed), bound)).encode(bound)
        assertEquals(CommandSessionRejection.INVALID_SIGNATURE, assertFailsWith<CommandSessionException> {
            CommandRequestSession.open(tampered, signature, mac, account, publicKey(pair), limits, setOf(4u))
        }.reason)
        for ((expectedMac, expectedAccount) in listOf(account to account, mac to mac)) {
            assertEquals(CommandSessionRejection.WRONG_AUTHORITY, assertFailsWith<CommandSessionException> {
                CommandRequestSession.open(body, signature, expectedMac, expectedAccount, publicKey(pair), limits, setOf(4u))
            }.reason)
        }
        assertEquals(CommandSessionRejection.INVALID_SIGNATURE, assertFailsWith<CommandSessionException> {
            CommandRequestSession.open(body, sign(body, key = newKey()), mac, account, publicKey(pair), limits, setOf(4u))
        }.reason)
    }

    @Test fun linuxOuterInnerSelectedSchemaAndFeatureMismatchesNeverTranslate() {
        fun negotiated(issued: IssuedRequestPayload, schemas: Set<ULong>) {
            val body = issued.encode(bound)
            CommandRequestSession.open(body, sign(body), mac, account, publicKey(pair), limits, schemas).close()
        }
        val linux = schemaFourCapture()
        for (schema in listOf(1uL, 2uL, 3uL)) {
            assertFailsWith<IllegalArgumentException> { negotiated(request(schema = schema, capture = linux), setOf(schema, 4u)) }
            assertFailsWith<IssuedRequestException> { negotiated(request(schema = 4u, capture = linux), setOf(schema)) }
        }
        assertFailsWith<CommandCaptureException> { negotiated(request(schema = 4u), setOf(1u, 4u)) }
        assertEquals(IssuedRequestFailure.UNSUPPORTED_FEATURES, assertFailsWith<IssuedRequestException> {
            negotiated(request(schema = 4u, features = setOf(1u), capture = linux), setOf(4u))
        }.reason)
    }

    @Test fun linuxRequesterSupplementaryGroupsAreChargedToTheSharedItemBudget() {
        val issued = request(schema = 4u, capture = schemaFourCapture())
        val body = issued.encode(bound)
        val session = CommandRequestSession.open(body, sign(body), mac, account, publicKey(pair), limits, setOf(4u))
        session.use {
            val capture = assertIs<LinuxCommandCapture>(session.snapshot(time()).capture)
            val groups = capture.requester.credentials.supplementaryGroups.size.toLong()
            assertTrue(groups > 0)
            val common = capture.arguments.size.toLong() + capture.environment.size.toLong() * 3 +
                capture.ancestry.entries.size.toLong() * 2 + capture.target.supplementaryGroups.size.toLong()
            val insufficient = CommandMemoryBudget(100000, 64 + common + groups - 1)
            assertEquals(InboxRejection.CAPACITY, assertFailsWith<InboxException> { session.retainMemory(insufficient) }.reason)
            session.retainMemory(CommandMemoryBudget(100000, 64 + common + groups))
        }
    }

    @Test fun validTerminalUpdateReleasesCaptureBeforePublishingRevisionAndCannotResurrect() {
        val session = open()
        observe(session, status())
        assertEquals(StatusAcceptance.APPLIED, observe(session, status(2u, terminal = true)))
        assertEquals(2uL, session.revisions.value)
        assertNull(session.snapshot(time()).capture)
        assertEquals(RequestPhase.EXPIRED, session.snapshot(time()).status!!.status.phase)
        assertEquals(StatusAcceptance.OLDER, observe(session, status()))
        assertEquals(StatusAcceptance.DUPLICATE, observe(session, status(2u, terminal = true)))
        assertFailsWith<StatusTrackingException> { observe(session, status(3u)) }
        assertNull(session.snapshot(time()).capture)
        assertEquals(2uL, session.revisions.value)
    }

    @Test fun invalidOrConflictingTerminalCannotPurgePendingDetails() {
        val session = open()
        observe(session, status())
        val terminal = status(2u, terminal = true).encode(bound)
        assertFailsWith<StatusTrackingException> { session.observe(terminal, ByteArray(64), time()) }
        assertFailsWith<StatusTrackingException> { observe(session, status(1u, terminal = true)) }
        assertNotNull(session.snapshot(time()).capture)
        assertEquals(RequestPhase.PRESENTED, session.snapshot(time()).status!!.status.phase)
        assertEquals(1uL, session.revisions.value)
    }

    @Test fun duplicatesDoNotPublishOrReanchorAndElapsedCountdownDoesNotPurge() {
        val session = open()
        observe(session, status())
        assertEquals(StatusAcceptance.DUPLICATE, observe(session, status(), 30_100u))
        val snapshot = session.snapshot(time(60_100u))
        assertEquals(1uL, session.revisions.value)
        assertEquals(61_000uL, snapshot.status!!.timing.ageLowerBoundMs)
        assertEquals(0uL, snapshot.status.timing.authorizationRemainingUpperBoundMs)
        assertFalse(snapshot.status.status.phase.isTerminal)
        assertNotNull(snapshot.capture)
    }

    @Test fun terminalFirstSnapshotNeverNeedsAPendingCaptureView() {
        val session = open()
        observe(session, status(9u, terminal = true))
        assertNull(session.snapshot(time()).capture)
        assertEquals(9uL, session.revisions.value)
    }

    private fun newKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun publicKey(pair: KeyPair): ByteArray {
        val point = (pair.public as ECPublicKey).w
        fun coordinate(value: java.math.BigInteger) = value.toByteArray().let {
            ByteArray(32 - minOf(it.size, 32)) + it.takeLast(32).toByteArray()
        }
        return byteArrayOf(4) + coordinate(point.affineX) + coordinate(point.affineY)
    }
    private fun sign(bytes: ByteArray, status: Boolean = false, key: KeyPair = pair): ByteArray =
        Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initSign(key.private)
            update(SigningInput.make(1u, if (status) ApprovalMessageType.STATUS else ApprovalMessageType.REQUEST,
                if (status) SigningPurpose.STATUS else SigningPurpose.ISSUED_REQUEST, bytes, bound, bound))
            sign()
        }
}
