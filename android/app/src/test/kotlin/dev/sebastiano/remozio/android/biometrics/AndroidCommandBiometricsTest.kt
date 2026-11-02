package dev.sebastiano.remozio.android.biometrics

import dev.sebastiano.remozio.android.decisions.decisionPublicPoint
import dev.sebastiano.remozio.android.decisions.AndroidDecisionIdentity
import dev.sebastiano.remozio.android.decisions.DecisionKeySecurity
import dev.sebastiano.remozio.android.decisions.DecisionIdentityUnavailable
import dev.sebastiano.remozio.android.requests.commandActionAvailability
import dev.remozio.phone.requests.*

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Test
import kotlin.test.*

class AndroidCommandBiometricsTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private fun id(n: Int, size: Int = 16) = ByteArray(size) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = pair()
    private val decisionKey = pair()
    private val biometricKey = pair()
    private fun reference(role: EnrollmentKeyRole) = pair().let { pair ->
        EnrollmentKeyReference(role, id(role.ordinal + 10), "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else decisionPublicPoint(pair.public as ECPublicKey))
    }
    private val enrollment = PhoneEnrollment(id(1), id(2), id(3), id(4), id(5), "Synthetic Mac",
        decisionPublicPoint(authority.public as ECPublicKey), pair().public.encoded, reference(EnrollmentKeyRole.TRANSPORT),
        EnrollmentKeyReference(EnrollmentKeyRole.DECISION, id(11), "remozio.decision.v1.${"b".repeat(32)}",
            decisionPublicPoint(decisionKey.public as ECPublicKey)), EnrollmentKeyReference(EnrollmentKeyRole.BIOMETRIC, id(12), "remozio.biometric.v1.${"c".repeat(32)}",
            decisionPublicPoint(biometricKey.public as ECPublicKey)), id(6, 32), null)
    private val decline = CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest)
    private val execute = CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)
    private fun request(mac: Int = 2, account: Int = 3, requestID: Int = 7, actions: List<CapturedAction> = listOf(decline, execute),
                        kind: RequestKind = RequestKind.COMMAND, schema: ULong = 1u, features: Set<ULong> = emptySet(),
                        bytes: ByteArray = capture) =
        IssuedRequestPayload(RequestContract(kind, 1u, schema), id(mac), id(account), id(requestID), id(8, 32), features,
            1u, 60001u, bytes, actions, bound, bound)
    private fun sign(request: IssuedRequestPayload, key: java.security.PrivateKey = authority.private): ByteArray =
        P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(key); update(SigningInput.make(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST,
                request.encode(bound), bound, bound)); sign()
        })
    private var time = ElapsedInstant(0, 100u)
    private fun session(request: IssuedRequestPayload = request()) = CommandRequestSession.open(
        request.encode(bound), sign(request), enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
        enrollment.authorityPublicKey.copyBytes(), limits)
    private fun status(session: CommandRequestSession, request: IssuedRequestPayload = request(), terminal: Boolean = false, authorized: Boolean = false) {
        val payload = RequestStatusPayload(request.macID, request.accountID, request.requestID,
            request.requestDigest(bound, bound), request.challenge, if (terminal || authorized) 2u else 1u,
            if (terminal) RequestPhase.EXPIRED else if (authorized) RequestPhase.AUTHORIZED else RequestPhase.PRESENTED,
            if (terminal) RequestStatusReason.AUTHORIZATION_EXPIRED else RequestStatusReason.NONE,
            id(20), if (terminal) 60_000u else 1000u, if (terminal || authorized) null else 59_000u,
            null, false, if (terminal) 60_000u else null, if (authorized) id(99) else null).encode(bound)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(authority.private)
            update(SigningInput.make(1u, ApprovalMessageType.STATUS, SigningPurpose.STATUS, payload, bound, bound))
            P256SignatureEncoding.fromDer(sign())
        }
        session.observe(payload, signature, time)
    }
    private fun identity(session: CommandRequestSession, key: java.security.PrivateKey = biometricKey.private) =
        AndroidCommandBiometrics(enrollment, session, key, biometricKey.public, limits) { time }
    private fun prepare(identity: AndroidCommandBiometrics) = identity.prepare(identity.beginAttempt())

    @Test fun signsTheExactSessionWithTheEnrolledBiometricKeyAndPurposeOnce() {
        val request = request()
        val session = session(request); status(session, request)
        identity(session).use { identity ->
            val operation = prepare(identity)
            val message = operation.complete(operation.signature)
            val decision = DecisionPayload.decode(message.body.copyBytes(), bound)
            assertEquals(execute, decision.action)
            assertContentEquals(request.macID, decision.macID)
            assertContentEquals(request.accountID, decision.accountID)
            assertContentEquals(request.requestID, decision.requestID)
            assertContentEquals(request.challenge, decision.challenge)
            assertContentEquals(request.requestDigest(bound, bound), decision.requestDigest)
            assertContentEquals(enrollment.phoneID.copyBytes(), decision.phoneID)
            assertContentEquals(enrollment.biometricKey.keyID.copyBytes(), decision.keyID)
            assertEquals(SigningPurpose.BIOMETRIC_AUTHORIZATION, message.purpose)
            assertTrue(ApprovalSignature.verify(message.signature.copyBytes(), enrollment.biometricKey.publicKey.copyBytes(),
                1u, message.type, message.purpose, message.body.copyBytes(), bound, bound))
            assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
        }
    }

    @Test fun missingStatusAbsentExecuteAndClosedSessionNeverPrepare() {
        val missing = session()
        identity(missing).use { assertFailsWith<BiometricAuthorizationUnavailable> { prepare(it) } }
        val request = request(actions = listOf(decline))
        val denied = session(request); status(denied, request)
        identity(denied).use { assertFailsWith<BiometricAuthorizationUnavailable> { prepare(it) } }
        val closed = session(); status(closed); closed.close()
        identity(closed).use { assertFailsWith<BiometricAuthorizationUnavailable> { prepare(it) } }
    }

    @Test fun cancellationAndReplacementCannotAcceptLateCallbacks() {
        val session = session(); status(session)
        identity(session).use { identity ->
            val old = prepare(identity)
            old.close()
            val current = prepare(identity)
            assertFailsWith<BiometricAuthorizationUnavailable> { old.complete(old.signature) }
            assertEquals(SigningPurpose.BIOMETRIC_AUTHORIZATION, current.complete(current.signature).purpose)
            val pending = identity.beginAttempt()
            identity.cancelAttempt(pending)
            assertFailsWith<BiometricAuthorizationUnavailable> { identity.prepare(pending) }
            val replacement = prepare(identity)
            identity.close()
            assertFailsWith<BiometricAuthorizationUnavailable> { replacement.complete(replacement.signature) }
        }
    }

    @Test fun terminalStatusExpiryClockChangeAndSessionClosureInvalidatePreparedSignatures() {
        for (invalidate in listOf<(CommandRequestSession) -> Unit>(
            { status(it, terminal = true) }, { status(it, authorized = true) }, { time = ElapsedInstant(0, 60_000u) },
            { time = ElapsedInstant(1, 100u) }, { it.close() },
        )) {
            time = ElapsedInstant(0, 100u)
            val session = session(); status(session)
            identity(session).use { identity ->
                val operation = prepare(identity)
                invalidate(session)
                assertFalse(identity.available())
                assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
            }
        }
    }

    @Test fun wrongCryptoObjectAndWrongPrivateKeyCannotProduceAMessage() {
        val session = session(); status(session)
        identity(session).use { identity ->
            val operation = prepare(identity)
            assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(Signature.getInstance("SHA256withECDSA")) }
        }
        identity(session, pair().private).use { identity ->
            val operation = prepare(identity)
            assertFailsWith<BiometricAuthorizationUnavailable> { operation.complete(operation.signature) }
        }
    }

    @Test fun sameIDsWithAnotherAuthorityCannotOwnTheDisplayedSession() {
        val request = request()
        val attacker = pair()
        val forged = CommandRequestSession.open(request.encode(bound), sign(request, attacker.private),
            request.macID, request.accountID, decisionPublicPoint(attacker.public as ECPublicKey), limits)
        assertFails { identity(forged) }
    }

    @Test fun sessionDeclineUsesOnlyTheDecisionKeyAndExactDisplayedBindings() {
        val request = request()
        val session = session(request); status(session, request)
        AndroidDecisionIdentity(enrollment, decisionKey.private, DecisionKeySecurity.TRUSTED_ENVIRONMENT).use { identity ->
            val message = identity.declineSession(session, time, limits)
            val payload = DecisionPayload.decode(message.body.copyBytes(), bound)
            assertEquals(decline, payload.action)
            assertEquals(SigningPurpose.CANCELLATION, message.purpose)
            assertContentEquals(request.requestDigest(bound, bound), payload.requestDigest)
            assertContentEquals(request.challenge, payload.challenge)
            assertContentEquals(enrollment.decisionKey.keyID.copyBytes(), payload.keyID)
            assertTrue(ApprovalSignature.verify(message.signature.copyBytes(), enrollment.decisionKey.publicKey.copyBytes(),
                1u, message.type, message.purpose, message.body.copyBytes(), bound, bound))
            assertFalse(ApprovalSignature.verify(message.signature.copyBytes(), enrollment.biometricKey.publicKey.copyBytes(),
                1u, message.type, message.purpose, message.body.copyBytes(), bound, bound))
            session.close()
            assertFailsWith<DecisionIdentityUnavailable> { identity.declineSession(session, time, limits) }
        }
    }

    @Test fun sessionDeclineRejectsAnotherAuthorityAndAnUnpermittedAction() {
        val request = request()
        val attacker = pair()
        val forged = CommandRequestSession.open(request.encode(bound), sign(request, attacker.private), request.macID,
            request.accountID, decisionPublicPoint(attacker.public as ECPublicKey), limits)
        val executeOnly = request(actions = listOf(execute))
        val session = session(executeOnly); status(session, executeOnly)
        AndroidDecisionIdentity(enrollment, decisionKey.private, DecisionKeySecurity.TRUSTED_ENVIRONMENT).use { identity ->
            assertFailsWith<DecisionIdentityUnavailable> { identity.declineSession(forged, time, limits) }
            assertFailsWith<DecisionIdentityUnavailable> { identity.declineSession(session, time, limits) }
        }
    }

    @Test fun controlsExposeOnlyPermittedPendingActionsForAnActiveEnrollment() {
        val request = request(actions = listOf(decline))
        val session = session(request)
        val active = StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE)
        assertFalse(commandActionAvailability(session, active, time).decline)
        status(session, request)
        assertTrue(commandActionAvailability(session, active, time).decline)
        assertFalse(commandActionAvailability(session, active, time).execute)
        assertFalse(commandActionAvailability(session, StoredPhoneEnrollment(enrollment, EnrollmentPhase.REMOVED), time).decline)
        assertFalse(commandActionAvailability(session, active, ElapsedInstant(0, 60_000u)).decline)
    }

    @Test fun anotherEnrollmentCannotOwnTheDisplayedSession() {
        val other = request(mac = 99)
        val session = CommandRequestSession.open(other.encode(bound), sign(other), other.macID, other.accountID,
            enrollment.authorityPublicKey.copyBytes(), limits)
        assertFails { identity(session) }
        for (phase in listOf(EnrollmentPhase.PREPARED, EnrollmentPhase.REMOVED)) {
            assertFailsWith<BiometricAuthorizationUnavailable> {
                AndroidCommandBiometrics.load(StoredPhoneEnrollment(enrollment, phase), session, limits) { time }
            }
        }
    }
}
