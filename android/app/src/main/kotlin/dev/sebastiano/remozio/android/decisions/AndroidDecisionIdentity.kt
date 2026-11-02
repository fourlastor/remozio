package dev.sebastiano.remozio.android.decisions

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.WorkerThread
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PhoneRoutingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.protocol.*
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec

enum class DecisionKeySecurity { STRONGBOX, TRUSTED_ENVIRONMENT }
class DecisionIdentityUnavailable : IllegalStateException("Decision identity unavailable")

internal data class DecisionKeyFacts(
    val securityLevel: Int,
    val origin: Int,
    val keySize: Int,
    val purposes: Int,
    val digests: Set<String>,
    val authenticationRequired: Boolean,
    val presenceRequired: Boolean,
    val confirmationRequired: Boolean,
)

internal fun decisionKeySecurity(facts: DecisionKeyFacts): DecisionKeySecurity {
    val security = when (facts.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> DecisionKeySecurity.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> DecisionKeySecurity.TRUSTED_ENVIRONMENT
        else -> throw DecisionIdentityUnavailable()
    }
    val allowed = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    require(facts.origin == KeyProperties.ORIGIN_GENERATED && facts.keySize == 256 &&
        facts.purposes and KeyProperties.PURPOSE_SIGN != 0 && facts.purposes and allowed.inv() == 0 &&
        facts.digests == setOf(KeyProperties.DIGEST_SHA256) && !facts.authenticationRequired &&
        !facts.presenceRequired && !facts.confirmationRequired)
    return security
}

/** Local key custody only. The enrollment owner must close this handle when trust changes or the phone is removed. */
class AndroidDecisionIdentity internal constructor(
    private val enrollment: PhoneEnrollment,
    private var key: PrivateKey?,
    val security: DecisionKeySecurity,
) : AutoCloseable {
    /** Call only for an explicit decline of the displayed request. This method does not establish request freshness. */
    @WorkerThread
    @Synchronized
    fun declineCommand(body: ByteArray, authoritySignature: ByteArray, limits: RequestLimits): ApprovalMessage {
        try {
            val signingKey = key ?: throw DecisionIdentityUnavailable()
            require(body.size <= limits.body.maxBytes && authoritySignature.size == 64)
            val captured = body.copyOf()
            CommandRequestSession.open(captured, authoritySignature, enrollment.macID.copyBytes(),
                enrollment.accountID.copyBytes(), enrollment.authorityPublicKey.copyBytes(), limits).use {
                val request = IssuedRequestPayload.decode(captured, limits.body, limits.capture,
                    ContractCapabilities(mapOf(RequestContract(RequestKind.COMMAND, 1u, 1u) to emptySet())))
                val action = CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest)
                check(ActionPolicy.requirement(action, request.contract.requestKind, request.permittedActions.toSet()) ==
                    ActionRequirement(ApprovalKeyClass.DECISION, ApprovalPurpose.CANCELLATION, ActionEffect.RESOLVE_REQUEST))
                val decision = DecisionPayload(request.macID, request.accountID, request.requestID,
                    request.requestDigest(limits.body, limits.signing), request.challenge, enrollment.phoneID.copyBytes(),
                    enrollment.decisionKey.keyID.copyBytes(), action).encode(limits.body)
                val input = SigningInput.make(1u, ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION,
                    decision, limits.body, limits.signing)
                val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                    initSign(signingKey)
                    update(input)
                    sign()
                })
                check(ApprovalSignature.verify(signature, enrollment.decisionKey.publicKey.copyBytes(), 1u,
                    ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION, decision, limits.body, limits.signing))
                return ApprovalMessage(1u, ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION, decision, signature)
            }
        } catch (_: Exception) { throw DecisionIdentityUnavailable() }
    }

    /** Declines the retained displayed session without biometrics. The Mac remains authoritative for consumption. */
    @WorkerThread
    @Synchronized
    fun declineSession(session: CommandRequestSession, now: ElapsedInstant, limits: RequestLimits): ApprovalMessage {
        try {
            val signingKey = key ?: throw DecisionIdentityUnavailable()
            require(session.isBoundToAuthority(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
                enrollment.authorityPublicKey.copyBytes()))
            return session.withPendingDecision(now, enrollment.phoneID.copyBytes(), enrollment.decisionKey.keyID.copyBytes(),
                CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest)) { payload ->
                val body = payload.encode(limits.body)
                val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                    initSign(signingKey)
                    update(SigningInput.make(1u, ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION, body,
                        limits.body, limits.signing))
                    sign()
                })
                check(ApprovalSignature.verify(signature, enrollment.decisionKey.publicKey.copyBytes(), 1u,
                    ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION, body, limits.body, limits.signing))
                ApprovalMessage(1u, ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION, body, signature)
            }
        } catch (_: Exception) { throw DecisionIdentityUnavailable() }
    }

    /** Signs an explicit Away choice with the existing decision key. No biometric operation is used. */
    @WorkerThread
    @Synchronized
    fun signRoutingAway(challenge: PhoneRoutingChallenge): ByteArray {
        try {
            val signingKey = key ?: throw DecisionIdentityUnavailable()
            return challenge.sign(enrollment) { input ->
                P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                    initSign(signingKey); update(input); sign()
                })
            }
        } catch (_: Exception) { throw DecisionIdentityUnavailable() }
    }

    /** Signs the selected update control with the existing decision key. The challenge retains its original lifetime. */
    @WorkerThread
    @Synchronized
    fun signUpdateScheduling(challenge: PhoneUpdateSchedulingChallenge, current: StoredPhoneEnrollment): ByteArray {
        try {
            val signingKey = key ?: throw DecisionIdentityUnavailable()
            require(current.phase == EnrollmentPhase.ACTIVE && current.sameConnectionAs(
                StoredPhoneEnrollment(enrollment, current.phase, current.pairing)))
            return challenge.sign(current) { input ->
                P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                    initSign(signingKey); update(input); sign()
                })
            }
        } catch (_: Exception) { throw DecisionIdentityUnavailable() }
    }

    @Synchronized override fun close() { key = null }
    override fun toString() = "AndroidDecisionIdentity(redacted)"
}

/** Loads an existing enrolled key. Missing or invalid keys require recovery; loading never replaces them. */
object AndroidDecisionIdentities {
    @WorkerThread
    fun load(record: StoredPhoneEnrollment): AndroidDecisionIdentity {
        try {
            require(record.phase == EnrollmentPhase.ACTIVE)
            val material = loadDecisionKey(record.enrollment.decisionKey)
            return AndroidDecisionIdentity(record.enrollment, material.key, material.security)
        } catch (_: Exception) { throw DecisionIdentityUnavailable() }
    }
}

internal class DecisionKeyMaterial(val key: PrivateKey, val security: DecisionKeySecurity)

internal fun loadDecisionKey(reference: EnrollmentKeyReference): DecisionKeyMaterial {
    require(reference.role == EnrollmentKeyRole.DECISION)
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val key = store.getKey(reference.alias, null) as? PrivateKey ?: throw DecisionIdentityUnavailable()
    require(key.algorithm == KeyProperties.KEY_ALGORITHM_EC && key.encoded == null && key.format == null)
    val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
    require(info.keystoreAlias == reference.alias)
    val security = decisionKeySecurity(DecisionKeyFacts(info.securityLevel, info.origin, info.keySize, info.purposes,
        info.digests.toSet(), info.isUserAuthenticationRequired, info.isTrustedUserPresenceRequired, info.isUserConfirmationRequired))
    val point = decisionPublicPoint(store.getCertificate(reference.alias)?.publicKey as? ECPublicKey
        ?: throw DecisionIdentityUnavailable())
    require(MessageDigest.isEqual(reference.publicKey.copyBytes(), point))
    return DecisionKeyMaterial(key, security)
}

internal fun decisionPublicPoint(key: ECPublicKey): ByteArray {
    val expected = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(ECParameterSpec::class.java)
    require(key.params.curve == expected.curve && key.params.generator == expected.generator &&
        key.params.order == expected.order && key.params.cofactor == expected.cofactor)
    fun coordinate(value: java.math.BigInteger): ByteArray {
        require(value.signum() >= 0 && value.bitLength() <= 256)
        val bytes = value.toByteArray().takeLast(32).toByteArray()
        return ByteArray(32 - bytes.size) + bytes
    }
    return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
}
