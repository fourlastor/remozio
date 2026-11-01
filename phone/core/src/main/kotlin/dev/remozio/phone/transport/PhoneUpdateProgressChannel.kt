package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.updates.UpdateSchedulingAge
import dev.remozio.protocol.*
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout

/** A Root-verified observation. It cannot acknowledge a scheduling attempt or authorize an action. */
class PhoneUpdateProgressObservation internal constructor(
    val response: UpdateSchedulingProgressResponse,
    private val record: StoredPhoneEnrollment,
    private val age: UpdateSchedulingAge,
) : AutoCloseable {
    fun matchesEnrollment(current: StoredPhoneEnrollment) =
        current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current)
    fun ageMilliseconds(): Long? = age.milliseconds()
    fun isFresh(maximumAgeMilliseconds: Long): Boolean {
        require(maximumAgeMilliseconds > 0)
        return ageMilliseconds()?.let { it < maximumAgeMilliseconds } == true
    }
    /** Includes the complete query lifetime. Unknown clocks and overflow cannot produce a younger age. */
    fun readyAgeUpperBoundMilliseconds(): ULong? = response.readyAgeMillisecondsAfterObservation(ageMilliseconds()?.toULong())
    override fun close() = age.retire()
    override fun toString() = "PhoneUpdateProgressObservation(redacted)"
}

/** Reads one observation through the dedicated enrolled purpose. It never loads a key or retries an application message. */
class PhoneUpdateProgressChannel private constructor(
    private val record: StoredPhoneEnrollment,
    private val channel: NegotiatedTLSChannel,
    private val nowNanos: () -> Long,
    private val currentEnrollment: suspend () -> StoredPhoneEnrollment,
    private val timeoutMillis: Long,
    private val newNonce: () -> ByteArray,
) : AutoCloseable {
    private val used = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)

    private suspend fun current(): StoredPhoneEnrollment {
        currentCoroutineContext().ensureActive()
        check(!closed.get())
        val current = currentEnrollment()
        currentCoroutineContext().ensureActive()
        check(!closed.get())
        require(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        return current
    }

    suspend fun read(): PhoneUpdateProgressObservation {
        var produced: PhoneUpdateProgressObservation? = null
        var transferred = false
        try {
            check(used.compareAndSet(false, true) && !closed.get())
            return withTimeout(timeoutMillis) {
                val age = UpdateSchedulingAge(nowNanos(), nowNanos)
                current()
                require(age.milliseconds() != null)
                val query = PhoneUpdateProgressFrame.Status(newNonce())
                val bytes = query.encode()
                current()
                require(age.milliseconds()?.let { it < timeoutMillis } == true)
                channel.send(bytes)
                val reply = PhoneUpdateProgressFrame.decode(channel.receive() ?: throw IOException("Missing update progress"))
                require(reply.queryNonce == query.queryNonce)
                val frame = reply as? PhoneUpdateProgressFrame.Response ?: throw IOException("Update progress unavailable")
                val payload = frame.canonicalPayload.copyBytes()
                require(UpdateSchedulingProgressSignature.verify(frame.signature.copyBytes(),
                    record.enrollment.authorityPublicKey.copyBytes(), 1u, payload, SIGNING_LIMITS))
                val response = UpdateSchedulingProgressResponse.decode(payload)
                val enrollment = record.enrollment
                require(response.status.queryNonce == query.queryNonce && response.status.scope == ChannelScope(
                    enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
                    enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes()))
                current()
                val result = PhoneUpdateProgressObservation(response, record, age)
                produced = result
                current()
                require(age.milliseconds()?.let { it < timeoutMillis } == true)
                currentCoroutineContext().ensureActive()
                check(!closed.get())
                transferred = true
                result
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            throw IOException("Update progress unavailable")
        } finally {
            if (!transferred) produced?.close()
            close()
        }
    }

    override fun close() { if (closed.compareAndSet(false, true)) channel.close() }
    suspend fun closeAndJoin() { close(); channel.closeAndJoin() }
    override fun toString() = "PhoneUpdateProgressChannel(redacted)"

    companion object {
        /** Android supplies elapsedRealtimeNanos. Device sleep counts toward the original query deadline. */
        suspend fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                         currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long = 5_000): PhoneUpdateProgressChannel =
            bind(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis) {
                ByteArray(32).also { SecureRandom().nextBytes(it) }
            }

        internal suspend fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                                  currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long,
                                  newNonce: () -> ByteArray): PhoneUpdateProgressChannel {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
                currentCoroutineContext().ensureActive()
                val current = currentEnrollment()
                currentCoroutineContext().ensureActive()
                require(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
                val enrollment = record.enrollment
                val scope = ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
                    enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == EnrolledChannelPurpose.UPDATE_PROGRESS &&
                    channel.localRequests.isEmpty() && channel.localAuditVersions.isEmpty())
                require(channel.maximumPayloadBytes >= PhoneUpdateProgressFrame.MAXIMUM_BYTES)
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= (record.pairing?.minimumEnvelopeVersion ?: 1uL) &&
                    peer.peer.requests.isEmpty() && peer.peer.auditVersions.isEmpty())
                return PhoneUpdateProgressChannel(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis, newNonce)
            } catch (failure: Throwable) {
                channel.close()
                throw failure
            }
        }
    }
}

private val SIGNING_LIMITS = CborLimits(8192, 2, 32)
