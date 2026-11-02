package dev.sebastiano.remozio.android.biometrics

import androidx.annotation.WorkerThread
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.protocol.*
import java.security.PrivateKey
import java.security.Signature

class BiometricAuthorizationUnavailable : IllegalStateException("Biometric authorization unavailable")

/** One enrolled identity and one displayed session. Close when the screen or enrollment owner changes. */
class AndroidCommandBiometrics internal constructor(
    private val enrollment: PhoneEnrollment,
    private val session: CommandRequestSession,
    private var key: PrivateKey?,
    private val publicKey: java.security.PublicKey,
    private val limits: RequestLimits,
    private val now: () -> ElapsedInstant,
) : AutoCloseable {
    private val action = CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)
    private var attempt: Any? = null
    private var current: CommandBiometricOperation? = null
    private var decision: ByteArray? = null

    init {
        require(session.isBoundToAuthority(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
            enrollment.authorityPublicKey.copyBytes()))
    }

    @Synchronized
    internal fun beginAttempt(): Any {
        check(key != null && attempt == null)
        return Any().also { attempt = it }
    }

    @Synchronized
    internal fun cancelAttempt(ticket: Any) {
        if (attempt !== ticket) return
        current?.let(::cancel)
        attempt = null
    }

    /** The caller invokes this only after the user selects the displayed command's execute action. */
    @WorkerThread
    @Synchronized
    internal fun prepare(ticket: Any): CommandBiometricOperation {
        try {
            check(attempt === ticket && current == null)
            val signingKey = checkNotNull(key)
            val body = pending { it.encode(limits.body) }
            val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(signingKey) }
            return CommandBiometricOperation(this, signature).also { current = it; decision = body }
        } catch (_: Exception) { throw BiometricAuthorizationUnavailable() }
    }

    @Synchronized
    internal fun available(): Boolean = try { checkNotNull(key); pending { true } }
        catch (_: Exception) { false }

    @Synchronized
    internal fun complete(operation: CommandBiometricOperation, returned: Signature): ApprovalMessage {
        try {
            check(key != null && current === operation && returned === operation.signature)
            val retained = checkNotNull(decision)
            return pending { payload ->
                val body = payload.encode(limits.body)
                check(body.contentEquals(retained))
                returned.update(SigningInput.make(1u, ApprovalMessageType.DECISION, SigningPurpose.BIOMETRIC_AUTHORIZATION,
                    body, limits.body, limits.signing))
                val signed = P256SignatureEncoding.fromDer(returned.sign())
                check(ApprovalSignature.verify(signed, enrollment.biometricKey.publicKey.copyBytes(), 1u,
                    ApprovalMessageType.DECISION, SigningPurpose.BIOMETRIC_AUTHORIZATION, body, limits.body, limits.signing))
                ApprovalMessage(1u, ApprovalMessageType.DECISION, SigningPurpose.BIOMETRIC_AUTHORIZATION, body, signed)
            }
        } catch (_: Exception) { throw BiometricAuthorizationUnavailable() }
        finally { cancel(operation) }
    }

    private fun <T> pending(block: (DecisionPayload) -> T): T = session.withPendingDecision(now(),
        enrollment.phoneID.copyBytes(), enrollment.biometricKey.keyID.copyBytes(), action, block)

    @Synchronized
    internal fun cancel(operation: CommandBiometricOperation) {
        if (current !== operation) return
        current = null
        attempt = null
        decision?.fill(0)
        decision = null
        // Reinitializing the provider releases an unfinished operation without requesting a signature.
        try {
            operation.signature.initVerify(publicKey)
        } catch (_: Exception) { /* A provider failure cannot restore this owner or its decision. */ }
    }

    @Synchronized override fun close() { current?.let(::cancel); attempt = null; key = null }
    override fun toString() = "AndroidCommandBiometrics(redacted)"

    companion object {
        @WorkerThread
        fun load(record: StoredPhoneEnrollment, session: CommandRequestSession, limits: RequestLimits,
                 now: () -> ElapsedInstant): AndroidCommandBiometrics {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE)
                val material = loadBiometricKey(record.enrollment.biometricKey)
                return AndroidCommandBiometrics(record.enrollment, session, material.key, material.publicKey, limits, now)
            } catch (_: Exception) { throw BiometricAuthorizationUnavailable() }
        }
    }
}

internal class CommandBiometricOperation(
    private val owner: AndroidCommandBiometrics,
    val signature: Signature,
) : AutoCloseable {
    fun complete(returned: Signature) = owner.complete(this, returned)
    override fun close() = owner.cancel(this)
}
