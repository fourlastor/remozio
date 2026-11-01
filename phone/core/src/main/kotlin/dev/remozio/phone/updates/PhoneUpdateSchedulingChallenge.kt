package dev.remozio.phone.updates

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

class PhoneUpdateSchedulingUnavailable : IllegalStateException("Update scheduling unavailable")

/** Starts before the query leaves the phone. Device sleep counts toward both deadlines. */
internal class UpdateSchedulingAge(private val started: Long, private val now: () -> Long) {
    private var previous = started
    private var retired = started < 0
    @Synchronized fun retire() { retired = true }
    @Synchronized fun milliseconds(): Long? {
        if (retired) return null
        val sampled = try { now() } catch (_: Exception) { retired = true; return null }
        if (sampled < previous) { retired = true; return null }
        previous = sampled
        val elapsed = sampled - started
        return elapsed / 1_000_000 + if (elapsed % 1_000_000 == 0L) 0 else 1
    }
}

/** Retains one explicit choice until the enrolled Root returns its matching challenge. */
class PhoneUpdateSchedulingQuery private constructor(
    private val record: StoredPhoneEnrollment,
    private val updateID: CborValue.Bytes,
    private val generation: ULong,
    private val revision: ULong,
    private val action: UpdateSchedulingAction,
    private val nonce: CborValue.Bytes,
    private val age: UpdateSchedulingAge,
    private val replyTimeoutMillis: Long,
) : AutoCloseable {
    private enum class State { PENDING, VERIFYING, TRANSFERRED, CLOSED }
    private val state = AtomicReference(State.PENDING)
    val queryNonce: ByteArray get() = nonce.copyBytes()

    /** Retains the original choice and timeout. Creating a frame does not renew the query. */
    internal fun requestFrame(current: StoredPhoneEnrollment): PhoneUpdateSchedulingFrame.Challenge {
        require(state.get() == State.PENDING && current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        require(age.milliseconds()?.let { it < replyTimeoutMillis } == true)
        return PhoneUpdateSchedulingFrame.Challenge(nonce.copyBytes(), updateID.copyBytes(), generation, revision, action)
    }

    fun verify(current: StoredPhoneEnrollment, payload: ByteArray, signature: ByteArray): PhoneUpdateSchedulingChallenge {
        if (!state.compareAndSet(State.PENDING, State.VERIFYING)) throw PhoneUpdateSchedulingUnavailable()
        try {
            require(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
            require(age.milliseconds()?.let { it < replyTimeoutMillis } == true)
            require(payload.size <= RESPONSE_LIMITS.maxBytes && signature.size == 64)
            val captured = payload.copyOf()
            val signed = signature.copyOf()
            require(RootUpdateSchedulingChallengeSignature.verify(signed, record.enrollment.authorityPublicKey.copyBytes(),
                1u, captured, RESPONSE_LIMITS, SIGNING_LIMITS))
            val response = RootUpdateSchedulingChallenge.decode(captured, RESPONSE_LIMITS)
            require(MessageDigest.isEqual(response.queryNonce, nonce.copyBytes()))
            val canonical = response.canonicalControl
            val control = UpdateSchedulingControl.decode(canonical, CONTROL_LIMITS)
            val e = record.enrollment
            require(MessageDigest.isEqual(control.macID, e.macID.copyBytes()) &&
                MessageDigest.isEqual(control.accountID, e.accountID.copyBytes()) &&
                MessageDigest.isEqual(control.phoneID, e.phoneID.copyBytes()) &&
                MessageDigest.isEqual(control.enrollmentEpoch, e.epoch.copyBytes()) &&
                MessageDigest.isEqual(control.keyID, e.decisionKey.keyID.copyBytes()) &&
                MessageDigest.isEqual(control.updateID, updateID.copyBytes()) &&
                control.expectedGeneration == generation && control.expectedRevision == revision && control.action == action)
            val lifetime = control.expiresAtUnixMillis - control.issuedAtUnixMillis
            require(lifetime <= Long.MAX_VALUE.toULong())
            require(age.milliseconds()?.let { it < replyTimeoutMillis && it.toULong() < lifetime } == true)
            val challenge = PhoneUpdateSchedulingChallenge(record, canonical, age, lifetime)
            if (!state.compareAndSet(State.VERIFYING, State.TRANSFERRED)) {
                challenge.close()
                throw PhoneUpdateSchedulingUnavailable()
            }
            return challenge
        } catch (_: Exception) {
            close()
            throw PhoneUpdateSchedulingUnavailable()
        }
    }

    /** Verifies a late challenge reply against the original choice and deadline. It grants no decision signature. */
    fun verifyTooLate(current: StoredPhoneEnrollment, payload: ByteArray,
                      signature: ByteArray): PhoneUpdateSchedulingTooLateObservation {
        var produced: PhoneUpdateSchedulingTooLateObservation? = null
        try {
            val request = requestFrame(current)
            if (!state.compareAndSet(State.PENDING, State.VERIFYING)) throw PhoneUpdateSchedulingUnavailable()
            val result = verifyPhoneUpdateSchedulingTooLate(record, current, request, payload, signature, age, replyTimeoutMillis)
            produced = result
            if (!state.compareAndSet(State.VERIFYING, State.TRANSFERRED)) throw PhoneUpdateSchedulingUnavailable()
            return result
        } catch (_: Exception) {
            produced?.close()
            close()
            throw PhoneUpdateSchedulingUnavailable()
        }
    }

    /** After verification, the challenge owns the retained lifetime. Closing the query does not retire that challenge. */
    override fun close() {
        while (true) {
            val previous = state.get()
            if (previous == State.TRANSFERRED || previous == State.CLOSED) return
            if (state.compareAndSet(previous, State.CLOSED)) { age.retire(); return }
        }
    }
    override fun toString() = "PhoneUpdateSchedulingQuery(redacted)"

    companion object {
        /** Android supplies elapsedRealtimeNanos. Start only for an explicit choice of the displayed update. */
        fun begin(record: StoredPhoneEnrollment, updateID: ByteArray, expectedGeneration: ULong, expectedRevision: ULong,
                  action: UpdateSchedulingAction, elapsedRealtimeNanos: () -> Long,
                  replyTimeoutMillis: Long = 5_000): PhoneUpdateSchedulingQuery =
            begin(record, updateID, expectedGeneration, expectedRevision, action, elapsedRealtimeNanos, replyTimeoutMillis) {
                ByteArray(32).also { SecureRandom().nextBytes(it) }
            }

        internal fun begin(record: StoredPhoneEnrollment, updateID: ByteArray, expectedGeneration: ULong,
                           expectedRevision: ULong, action: UpdateSchedulingAction, elapsedRealtimeNanos: () -> Long,
                           replyTimeoutMillis: Long, newNonce: () -> ByteArray): PhoneUpdateSchedulingQuery {
            require(record.phase == EnrollmentPhase.ACTIVE && updateID.size == 32 && expectedGeneration > 0uL)
            require(replyTimeoutMillis in 1..60_000)
            val age = UpdateSchedulingAge(elapsedRealtimeNanos(), elapsedRealtimeNanos)
            require(age.milliseconds() != null)
            val selected = CborValue.Bytes(updateID)
            val nonce = newNonce()
            require(nonce.size == 32)
            require(age.milliseconds()?.let { it < replyTimeoutMillis } == true)
            return PhoneUpdateSchedulingQuery(record, selected, expectedGeneration, expectedRevision, action,
                CborValue.Bytes(nonce), age, replyTimeoutMillis)
        }
    }
}

/** Permits one decision signature for a verified Root challenge. The Root still consumes the operation once. */
class PhoneUpdateSchedulingChallenge internal constructor(
    private val record: StoredPhoneEnrollment,
    canonicalControl: ByteArray,
    private val age: UpdateSchedulingAge,
    private val lifetimeMillis: ULong,
) : AutoCloseable {
    private val canonical = CborValue.Bytes(canonicalControl)
    private enum class State { READY, SIGNING, SIGNED, CLOSED }
    private val state = AtomicReference(State.READY)

    private fun requireUsable(current: StoredPhoneEnrollment) {
        require(state.get() != State.CLOSED && current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        require(age.milliseconds()?.let { it.toULong() < lifetimeMillis } == true)
    }

    /** The custody owner supplies only its enrolled decision key. No biometric operation is required. */
    fun sign(current: StoredPhoneEnrollment, signer: (ByteArray) -> ByteArray): ByteArray {
        if (!state.compareAndSet(State.READY, State.SIGNING)) throw PhoneUpdateSchedulingUnavailable()
        try {
            requireUsable(current)
            val input = UpdateSchedulingSigningInput.make(1u, canonical.copyBytes(), CONTROL_LIMITS, SIGNING_LIMITS)
            val candidate = signer(input)
            require(candidate.size == 64)
            val signature = candidate.copyOf()
            requireUsable(current)
            require(UpdateSchedulingSignature.verify(signature, record.enrollment.decisionKey.publicKey.copyBytes(),
                1u, canonical.copyBytes(), CONTROL_LIMITS, SIGNING_LIMITS))
            requireUsable(current)
            require(state.compareAndSet(State.SIGNING, State.SIGNED))
            return signature
        } catch (_: Exception) {
            close()
            throw PhoneUpdateSchedulingUnavailable()
        }
    }

    internal fun bytes(current: StoredPhoneEnrollment): ByteArray {
        require(state.get() == State.SIGNED)
        requireUsable(current)
        return canonical.copyBytes()
    }
    override fun close() { state.set(State.CLOSED); age.retire() }
    override fun toString() = "PhoneUpdateSchedulingChallenge(redacted)"
}

private val CONTROL_LIMITS = CborLimits(1024, 2, 32)
private val RESPONSE_LIMITS = CborLimits(2048, 2, 32)
private val SIGNING_LIMITS = CborLimits(4096, 2, 32)
