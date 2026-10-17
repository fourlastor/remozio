package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeout

sealed interface PhonePushRecoveryResult {
    /** Observation freshness stays anchored to Resume, including time spent waiting for the caller to read this result. */
    class Current(private val retained: PhonePushRecoveryState, private val requestedAtNanos: Long,
                  private val nowNanos: () -> Long) : PhonePushRecoveryResult {
        private val expired = AtomicBoolean(false)
        val state: PhonePushRecoveryState get() {
            if (retained.phase != PhonePushRecoveryPhase.MAPPING_OBSERVED) return retained
            fun committed() = PhonePushRecoveryState(retained.metadata, PhonePushRecoveryPhase.PROOF_COMMITTED)
            if (expired.get()) return committed()
            val elapsed = nowNanos() - requestedAtNanos
            val originalAge = requireNotNull(retained.observationAgeMilliseconds).toLong()
            val remaining = PhonePushRecoveryState.MAXIMUM_OBSERVATION_AGE_MILLISECONDS.toLong() - originalAge
            val milliseconds = if (elapsed < 0) Long.MAX_VALUE else {
                elapsed / 1_000_000 + if (elapsed % 1_000_000 == 0L) 0 else 1
            }
            if (milliseconds > remaining) { expired.set(true); return committed() }
            return PhonePushRecoveryState(retained.metadata, retained.phase, (originalAge + milliseconds).toULong())
        }
        override fun toString() = "PhonePushRecoveryResult.Current(redacted)"
    }
    class Failure(val failure: PhonePushRecoveryFailure) : PhonePushRecoveryResult
}

/** One preflight and resume operation. Callers recheck current enrollment and provider revision after suspension. */
class PhonePushRecoveryChannel private constructor(
    private val channel: NegotiatedTLSChannel,
    private val record: StoredPhoneEnrollment,
    private val timeoutMillis: Long,
    private val newID: () -> ByteArray,
    private val nowNanos: () -> Long,
) : AutoCloseable {
    private val used = AtomicBoolean(false)

    suspend fun recover(offer: PhonePushTokenOffer): PhonePushRecoveryResult = operation {
        val probeID = newID()
        when (val response = exchange(PhonePushRecoveryFrame.Probe(probeID))) {
            is PhonePushRecoveryFrame.Outcome -> return@operation PhonePushRecoveryResult.Failure(response.failure)
            is PhonePushRecoveryFrame.Ready -> Unit
            else -> throw IOException("Invalid recovery readiness")
        }
        val resumeID = newID(); require(!resumeID.contentEquals(probeID))
        val started = nowNanos()
        when (val response = exchange(PhonePushRecoveryFrame.Resume(resumeID, offer))) {
            is PhonePushRecoveryFrame.State -> {
                validate(response.state.metadata, offer)
                PhonePushRecoveryResult.Current(response.state, started, nowNanos)
            }
            is PhonePushRecoveryFrame.Outcome -> PhonePushRecoveryResult.Failure(response.failure)
            else -> throw IOException("Invalid recovery response")
        }
    }

    private fun validate(metadata: PhonePushRegistrationMetadata, offer: PhonePushTokenOffer) {
        val e = record.enrollment
        require(metadata.scope == ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()))
        require(metadata.enrollmentTag.contentEquals(e.enrollmentTag.copyBytes()))
        require(metadata.tokenDigest.contentEquals(MessageDigest.getInstance("SHA-256").digest(offer.token.toByteArray(Charsets.UTF_8))))
    }
    private suspend fun exchange(request: PhonePushRecoveryFrame): PhonePushRecoveryFrame {
        channel.send(request.encode())
        val bytes = channel.receive() ?: throw IOException("Missing recovery response")
        val response = PhonePushRecoveryFrame.decode(bytes)
        require(response.correlationID == request.correlationID)
        return response
    }
    private suspend fun <T> operation(body: suspend () -> T): T {
        try {
            check(used.compareAndSet(false, true))
            return withTimeout(timeoutMillis) { body() }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { throw IOException("Push recovery unavailable") }
        finally { close() }
    }
    override fun close() = channel.close()
    suspend fun closeAndJoin() = channel.closeAndJoin()
    override fun toString() = "PhonePushRecoveryChannel(redacted)"

    companion object {
        fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, timeoutMillis: Long = 5_000): PhonePushRecoveryChannel =
            bind(record, channel, timeoutMillis, { ByteArray(16).also { SecureRandom().nextBytes(it) } }, System::nanoTime)

        internal fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, timeoutMillis: Long,
                          newID: () -> ByteArray, nowNanos: () -> Long): PhonePushRecoveryChannel {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
                val e = record.enrollment
                val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == EnrolledChannelPurpose.PUSH_RECOVERY && channel.localRequests.isEmpty() && channel.localAuditVersions.isEmpty())
                require(channel.maximumPayloadBytes >= PhonePushRecoveryFrame.MAXIMUM_BYTES)
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= (record.pairing?.minimumEnvelopeVersion ?: 1uL) && peer.peer.requests.isEmpty() && peer.peer.auditVersions.isEmpty())
                return PhonePushRecoveryChannel(channel, record, timeoutMillis, newID, nowNanos)
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}
