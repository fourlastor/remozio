package dev.sebastiano.remozio.android.biometrics

import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.enrollment.PairingDeadline
import dev.sebastiano.remozio.android.enrollment.PairingDeadlineExpired
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/** Owns one locally verified, durably prepared pairing. Close when setup changes or leaves the screen. */
class AndroidPairingBiometrics internal constructor(
    private val record: StoredPhoneEnrollment,
    private var key: PrivateKey?,
    private val publicKey: PublicKey,
    private val deadline: PairingDeadline,
    private val now: () -> ElapsedInstant,
    private val isCurrent: () -> Boolean,
) : AutoCloseable {
    private val transcript = requireNotNull(record.pairing).transcript
    private var attempt: Any? = null
    private var current: PairingBiometricOperation? = null
    init {
        require(record.phase == EnrollmentPhase.PREPARED)
        require(deadline.matches(transcript))
        require(transcript.biometricKey.keyID == record.enrollment.biometricKey.keyID &&
            transcript.biometricKey.publicKey == record.enrollment.biometricKey.publicKey)
    }

    @Synchronized internal fun beginAttempt(): Any {
        check(available() && attempt == null)
        return Any().also { attempt = it }
    }
    @Synchronized internal fun cancelAttempt(ticket: Any) {
        if (attempt !== ticket) return
        current?.let(::cancel)
        attempt = null
    }
    @WorkerThread
    @Synchronized internal fun prepare(ticket: Any): PairingBiometricOperation {
        try {
            check(attempt === ticket && current == null && available())
            val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(checkNotNull(key)) }
            return PairingBiometricOperation(this, signature).also { current = it }
        } catch (_: Exception) { throw BiometricAuthorizationUnavailable() }
    }
    @Synchronized internal fun available(): Boolean = try {
        key != null && deadline.isOpen(now()) && isCurrent()
    } catch (_: Exception) { false }

    @Synchronized internal fun complete(operation: PairingBiometricOperation, returned: Signature): ByteArray {
        try {
            check(current === operation && returned === operation.signature && available())
            returned.update(transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC))
            val signed = P256SignatureEncoding.fromDer(returned.sign())
            check(available() && transcript.verify(signed, record.enrollment.biometricKey.publicKey.copyBytes(), PairingProofPurpose.PHONE_BIOMETRIC))
            return signed
        } catch (_: Exception) { throw BiometricAuthorizationUnavailable() }
        finally { cancel(operation) }
    }
    @Synchronized internal fun cancel(operation: PairingBiometricOperation) {
        if (current !== operation) return
        current = null; attempt = null
        try { operation.signature.initVerify(publicKey) } catch (_: Exception) { }
    }
    @Synchronized override fun close() { current?.let(::cancel); attempt = null; key = null }
    override fun toString() = "AndroidPairingBiometrics(redacted)"

    companion object {
        /** The host supplies a local current-record check; network input cannot supply setup authorization. */
        @WorkerThread
        internal fun load(record: StoredPhoneEnrollment, deadline: PairingDeadline,
            now: () -> ElapsedInstant, isCurrent: () -> Boolean): AndroidPairingBiometrics {
            deadline.requireOpen(now())
            val signer = try {
                require(record.phase == EnrollmentPhase.PREPARED && record.pairing != null)
                val material = loadBiometricKey(record.enrollment.biometricKey)
                AndroidPairingBiometrics(record, material.key, material.publicKey, deadline, now, isCurrent)
            } catch (_: Exception) { throw BiometricAuthorizationUnavailable() }
            if (!deadline.isOpen(now())) {
                signer.close()
                throw PairingDeadlineExpired()
            }
            return signer
        }
    }
}

internal class PairingBiometricOperation(private val owner: AndroidPairingBiometrics, val signature: Signature) : AutoCloseable {
    fun complete(returned: Signature) = owner.complete(this, returned)
    override fun close() = owner.cancel(this)
}
