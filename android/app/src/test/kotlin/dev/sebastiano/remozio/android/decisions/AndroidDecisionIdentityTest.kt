package dev.sebastiano.remozio.android.decisions

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.protocol.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Test
import kotlin.test.*

class AndroidDecisionIdentityTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private fun id(n: Int, size: Int = 16) = ByteArray(size) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = pair()
    private val decisionKey = pair()
    private fun reference(role: EnrollmentKeyRole) = pair().let { pair ->
        EnrollmentKeyReference(role, id(role.ordinal + 10), "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else decisionPublicPoint(pair.public as ECPublicKey))
    }
    private val enrollment = PhoneEnrollment(id(1), id(2), id(3), id(4), id(5), "Synthetic Mac",
        decisionPublicPoint(authority.public as ECPublicKey), pair().public.encoded, reference(EnrollmentKeyRole.TRANSPORT),
        EnrollmentKeyReference(EnrollmentKeyRole.DECISION, id(11), "remozio.decision.v1.${"b".repeat(32)}",
            decisionPublicPoint(decisionKey.public as ECPublicKey)), reference(EnrollmentKeyRole.BIOMETRIC), id(6, 32), null)
    private val decline = CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest)
    private val execute = CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)
    private val receivedAt = ElapsedInstant(0, 100u)

    private fun request(mac: Int = 2, account: Int = 3, schema: ULong = 1u,
                        actions: List<CapturedAction> = listOf(decline, execute), bytes: ByteArray = capture) =
        IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, schema), id(mac), id(account), id(7), id(8, 32),
            emptySet(), 1u, 60001u, bytes, actions, bound, bound)

    private fun sign(body: ByteArray, type: ApprovalMessageType, purpose: SigningPurpose, signer: KeyPair) =
        P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(signer.private)
            update(SigningInput.make(1u, type, purpose, body, bound, bound))
            sign()
        })

    private fun session(request: IssuedRequestPayload, signer: KeyPair = authority, presented: Boolean = true): CommandRequestSession {
        val body = request.encode(bound)
        val session = CommandRequestSession.open(body, sign(body, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, signer),
            request.macID, request.accountID, decisionPublicPoint(signer.public as ECPublicKey), limits, setOf(request.contract.schemaVersion))
        if (presented) {
            val status = RequestStatusPayload(request.macID, request.accountID, request.requestID, request.requestDigest(bound, bound),
                request.challenge, 1u, RequestPhase.PRESENTED, RequestStatusReason.NONE, id(20), 1000u, 59000u,
                null, false, null, null).encode(bound)
            session.observe(status, sign(status, ApprovalMessageType.STATUS, SigningPurpose.STATUS, signer), receivedAt)
        }
        return session
    }

    private fun identity() = AndroidDecisionIdentity(enrollment, decisionKey.private, DecisionKeySecurity.TRUSTED_ENVIRONMENT)

    private fun vector(property: String, name: String): ByteArray {
        val source = File(checkNotNull(System.getProperty(property))).readText()
        val row = Json.parseToJsonElement(source).jsonObject.getValue("valid").jsonArray
            .map { it.jsonObject }.single { it.getValue("name").jsonPrimitive.content == name }
        return row.getValue("hex").jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    @Test fun declineBindsTheAuthenticatedRequestForEveryNegotiatedCommandSchema() {
        val fields = (DeterministicCbor.decode(capture, bound) as CborValue.Fields).values
        val captureV2 = DeterministicCbor.encode(CborValue.Fields(fields + (0uL to CborValue.Unsigned(2u))), bound)
        val captures = mapOf(
            1uL to capture,
            2uL to captureV2,
            3uL to vector("remozio.test.commandStreamVectors", "schema3-terminal-mask-0"),
            4uL to vector("remozio.test.linuxCommandCaptureVectors", "schema4-base"),
        )
        identity().use { signer ->
            for ((schema, bytes) in captures) {
                val request = request(schema = schema, bytes = bytes)
                session(request).use { displayed ->
                    assertEquals(schema, assertNotNull(displayed.snapshot(receivedAt).capture).schemaVersion)
                    val carrier = signer.declineSession(displayed, receivedAt, limits)
                    val decision = DecisionPayload.decode(carrier.body.copyBytes(), bound)
                    assertEquals(ApprovalMessageType.DECISION, carrier.type)
                    assertEquals(SigningPurpose.CANCELLATION, carrier.purpose)
                    assertEquals(decline, decision.action)
                    assertContentEquals(request.macID, decision.macID)
                    assertContentEquals(request.accountID, decision.accountID)
                    assertContentEquals(request.requestID, decision.requestID)
                    assertContentEquals(request.challenge, decision.challenge)
                    assertContentEquals(request.requestDigest(bound, bound), decision.requestDigest)
                    assertContentEquals(enrollment.phoneID.copyBytes(), decision.phoneID)
                    assertContentEquals(enrollment.decisionKey.keyID.copyBytes(), decision.keyID)
                    assertTrue(ApprovalSignature.verify(carrier.signature.copyBytes(), enrollment.decisionKey.publicKey.copyBytes(), 1u,
                        carrier.type, carrier.purpose, carrier.body.copyBytes(), bound, bound))
                    assertFalse(ApprovalSignature.verify(carrier.signature.copyBytes(), enrollment.decisionKey.publicKey.copyBytes(), 1u,
                        carrier.type, SigningPurpose.BIOMETRIC_AUTHORIZATION, carrier.body.copyBytes(), bound, bound))
                }
            }
        }
    }

    @Test fun declineRejectsAValidatedSessionFromAnotherMacAccountOrAuthority() {
        identity().use { signer ->
            for (request in listOf(request(mac = 99), request(account = 99))) {
                session(request).use {
                    assertFailsWith<DecisionIdentityUnavailable> { signer.declineSession(it, receivedAt, limits) }
                }
            }
            session(request(), signer = pair()).use {
                assertFailsWith<DecisionIdentityUnavailable> { signer.declineSession(it, receivedAt, limits) }
            }
        }
    }

    @Test fun declineRequiresCurrentStatusAndAnAllowedDecline() {
        identity().use { signer ->
            session(request(), presented = false).use {
                assertFailsWith<DecisionIdentityUnavailable> { signer.declineSession(it, receivedAt, limits) }
            }
            session(request(actions = listOf(execute))).use {
                assertFailsWith<DecisionIdentityUnavailable> { signer.declineSession(it, receivedAt, limits) }
            }
            session(request()).use {
                val expiredAt = ElapsedInstant(0, 60_000u)
                assertFailsWith<DecisionIdentityUnavailable> { signer.declineSession(it, expiredAt, limits) }
            }
        }
    }

    @Test fun closeInvalidatesOnlyItsHandleAndWrongLocalKeyCannotProduceACarrier() {
        session(request()).use { displayed ->
            val closed = identity()
            closed.close()
            closed.close()
            assertEquals("Decision identity unavailable", assertFailsWith<DecisionIdentityUnavailable> {
                closed.declineSession(displayed, receivedAt, limits)
            }.message)
            assertEquals("AndroidDecisionIdentity(redacted)", closed.toString())
            identity().use { assertEquals(SigningPurpose.CANCELLATION, it.declineSession(displayed, receivedAt, limits).purpose) }
            AndroidDecisionIdentity(enrollment, pair().private, DecisionKeySecurity.TRUSTED_ENVIRONMENT).use { wrong ->
                assertFailsWith<DecisionIdentityUnavailable> { wrong.declineSession(displayed, receivedAt, limits) }
            }
        }
    }

    @Test fun inactiveRecordsCannotLoadKeys() {
        for (phase in listOf(EnrollmentPhase.PREPARED, EnrollmentPhase.REMOVED)) {
            assertFailsWith<DecisionIdentityUnavailable> { AndroidDecisionIdentities.load(StoredPhoneEnrollment(enrollment, phase)) }
        }
    }

    private val updateControlLimits = CborLimits(1024, 2, 32)
    private val updateResponseLimits = CborLimits(2048, 2, 32)
    private val updateSigningLimits = CborLimits(4096, 2, 32)
    private fun updateControl(action: UpdateSchedulingAction) = UpdateSchedulingControl(id(2), id(3), id(4), id(5),
        id(20), id(21, 32), enrollment.decisionKey.keyID.copyBytes(), id(22, 32), 7u, 8u, 1000u, 31000u, action)
        .encode(updateControlLimits)
    private fun updateChallenge(action: UpdateSchedulingAction = UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES,
                                now: () -> Long = { 1_000_000L }): dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge {
        val record = StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE)
        val query = PhoneUpdateSchedulingQuery.begin(record, id(22, 32), 7u, 8u, action, now)
        val body = RootUpdateSchedulingChallenge(query.queryNonce, updateControl(action), updateControlLimits).encode(updateResponseLimits)
        val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(authority.private)
            update(RootUpdateSchedulingChallengeSigningInput.make(1u, body, updateResponseLimits, updateSigningLimits))
            sign()
        })
        return query.use { it.verify(record, body, signature) }
    }

    @Test fun schedulingUsesTheExistingDecisionKeyForEachVerifiedExplicitChoice() {
        identity().use { signer ->
            for (action in UpdateSchedulingAction.entries) {
                val challenge = updateChallenge(action)
                val signature = signer.signUpdateScheduling(challenge, StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE))
                assertTrue(UpdateSchedulingSignature.verify(signature, enrollment.decisionKey.publicKey.copyBytes(),
                    1u, updateControl(action), updateControlLimits, updateSigningLimits))
                assertFalse(UpdateSchedulingSignature.verify(signature, enrollment.biometricKey.publicKey.copyBytes(),
                    1u, updateControl(action), updateControlLimits, updateSigningLimits))
                assertFailsWith<DecisionIdentityUnavailable> {
                    signer.signUpdateScheduling(challenge, StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE))
                }
            }
        }
    }

    @Test fun schedulingRejectsClosedAndWrongPrivateKeyHandles() {
        val signer = identity(); signer.close()
        assertFailsWith<DecisionIdentityUnavailable> {
            signer.signUpdateScheduling(updateChallenge(), StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE))
        }
        AndroidDecisionIdentity(enrollment, pair().private, DecisionKeySecurity.TRUSTED_ENVIRONMENT).use { wrong ->
            assertFailsWith<DecisionIdentityUnavailable> {
                wrong.signUpdateScheduling(updateChallenge(), StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE))
            }
        }
    }

    @Test fun schedulingRejectsAnInactiveEnrollmentWithoutUsingBiometrics() {
        identity().use { signer ->
            for (phase in listOf(EnrollmentPhase.PREPARED, EnrollmentPhase.REMOVED)) {
                assertEquals("Decision identity unavailable", assertFailsWith<DecisionIdentityUnavailable> {
                    signer.signUpdateScheduling(updateChallenge(), StoredPhoneEnrollment(enrollment, phase))
                }.message)
            }
        }
    }

    @Test fun schedulingCannotSignAfterSleepExhaustsTheOriginalLifetime() {
        var nanos = 1_000_000L
        val challenge = updateChallenge(now = { nanos }); nanos += 30_000_000_000L
        identity().use { signer ->
            assertFailsWith<DecisionIdentityUnavailable> {
                signer.signUpdateScheduling(challenge, StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE))
            }
        }
    }

    @Test fun publicEncodingRejectsOtherCurves() {
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        assertFailsWith<IllegalArgumentException> { decisionPublicPoint(other.public as ECPublicKey) }
        assertContentEquals(decisionKey.public.encoded.takeLast(65).toByteArray(), decisionPublicPoint(decisionKey.public as ECPublicKey))
    }
}
