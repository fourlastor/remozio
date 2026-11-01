package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.phone.updates.UpdateSchedulingAge
import dev.remozio.phone.updates.verifyPhoneUpdateSchedulingTooLate
import dev.remozio.protocol.*
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout

/** A fresh signed observation, not authority to install, close admission or dispatch a command. */
class PhoneUpdateSchedulingStatus internal constructor(
    val response: UpdateSchedulingStatusResponse,
    private val record: StoredPhoneEnrollment,
    private val age: UpdateSchedulingAge,
) : AutoCloseable {
    fun matchesEnrollment(current: StoredPhoneEnrollment) = current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current)
    fun ageMilliseconds(): Long? = age.milliseconds()
    fun isFresh(maximumAgeMilliseconds: Long): Boolean {
        require(maximumAgeMilliseconds > 0)
        return ageMilliseconds()?.let { it < maximumAgeMilliseconds } == true
    }
    override fun close() = age.retire()
    override fun toString() = "PhoneUpdateSchedulingStatus(redacted)"
}

/** One scheduling exchange over an enrolled TLS channel. Application messages are never retried. */
class PhoneUpdateSchedulingChannel private constructor(
    private val record: StoredPhoneEnrollment,
    private val channel: NegotiatedTLSChannel,
    private val nowNanos: () -> Long,
    private val currentEnrollment: suspend () -> StoredPhoneEnrollment,
    private val timeoutMillis: Long,
    private val newNonce: () -> ByteArray,
    private val version2: Boolean,
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
    suspend fun status(): PhoneUpdateSchedulingStatus = operation({ PhoneUpdateSchedulingFrame.Status(newNonce()) }) { reply, query, age ->
        val response = verifiedStatus(message(reply), query, age)
        require(response.response.controlDigest == null)
        response
    }
    suspend fun challenge(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallenge = when (val result = challengeResult(query)) {
        is PhoneUpdateSchedulingChallengeResult.Ready -> result.challenge
        is PhoneUpdateSchedulingChallengeResult.TooLate -> { result.close(); throw IOException("Update scheduling unavailable") }
    }

    suspend fun challengeResult(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallengeResult {
        try {
            return operation({ query.requestFrame(current()) }, beforeSend = { query.requestFrame(current()); Unit }) { reply, _, _ ->
                when (reply) {
                    is PhoneUpdateSchedulingFrameV2.TooLate -> PhoneUpdateSchedulingChallengeResult.TooLate(
                        query.verifyTooLate(current(), reply.canonicalPayload.copyBytes(), reply.signature.copyBytes()))
                    is PhoneUpdateSchedulingFrameV2.Message -> {
                        val response = reply.frame as? PhoneUpdateSchedulingFrame.ChallengeResponse
                            ?: throw IOException("Invalid scheduling response role")
                        PhoneUpdateSchedulingChallengeResult.Ready(
                            query.verify(current(), response.canonicalPayload.copyBytes(), response.signature.copyBytes()))
                    }
                }
            }
        } finally { query.close() }
    }

    suspend fun apply(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingStatus =
        when (val result = applyResult(challenge, signature)) {
            is PhoneUpdateSchedulingApplyResult.Applied -> result.status
            is PhoneUpdateSchedulingApplyResult.TooLate -> { result.close(); throw IOException("Update scheduling unavailable") }
        }

    suspend fun applyResult(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingApplyResult {
        val retainedSignature = signature.copyOf()
        try {
            return operation({
                val control = challenge.bytes(current())
                require(UpdateSchedulingSignature.verify(retainedSignature, record.enrollment.decisionKey.publicKey.copyBytes(),
                    1u, control, CONTROL_LIMITS, SIGNING_LIMITS))
                PhoneUpdateSchedulingFrame.Apply(newNonce(), control, retainedSignature)
            }, beforeSend = { challenge.bytes(current()); Unit }) { reply, query, age ->
                val applied = query as? PhoneUpdateSchedulingFrame.Apply ?: throw IOException("Invalid scheduling query role")
                when (reply) {
                    is PhoneUpdateSchedulingFrameV2.TooLate -> PhoneUpdateSchedulingApplyResult.TooLate(
                        verifyPhoneUpdateSchedulingTooLate(record, current(), applied,
                            reply.canonicalPayload.copyBytes(), reply.signature.copyBytes(), age, timeoutMillis))
                    is PhoneUpdateSchedulingFrameV2.Message -> {
                        val response = verifiedStatus(reply.frame, query, age)
                        try {
                            val control = UpdateSchedulingControl.decode(applied.canonicalControl.copyBytes(), CONTROL_LIMITS)
                            val state = response.response
                            require(control.expectedRevision < ULong.MAX_VALUE && state.revision == control.expectedRevision + 1u &&
                                state.generation == control.expectedGeneration && state.updateID == CborValue.Bytes(control.updateID) &&
                                state.requestedAction == control.action && state.controlDigest == CborValue.Bytes(
                                    MessageDigest.getInstance("SHA-256").digest(applied.canonicalControl.copyBytes())))
                            PhoneUpdateSchedulingApplyResult.Applied(response)
                        } catch (failure: Throwable) { response.close(); throw failure }
                    }
                }
            }
        } finally { challenge.close() }
    }

    private fun message(frame: PhoneUpdateSchedulingFrameV2): PhoneUpdateSchedulingFrame =
        (frame as? PhoneUpdateSchedulingFrameV2.Message)?.frame ?: throw IOException("Invalid scheduling response role")

    private suspend fun verifiedStatus(reply: PhoneUpdateSchedulingFrame, query: PhoneUpdateSchedulingFrame,
                               age: UpdateSchedulingAge): PhoneUpdateSchedulingStatus {
        val frame = reply as? PhoneUpdateSchedulingFrame.StateResponse ?: throw IOException("Invalid scheduling response role")
        val bytes = frame.canonicalPayload.copyBytes()
        require(UpdateSchedulingStatusSignature.verify(frame.signature.copyBytes(), record.enrollment.authorityPublicKey.copyBytes(), 1u, bytes, SIGNING_LIMITS))
        val response = UpdateSchedulingStatusResponse.decode(bytes)
        val e = record.enrollment
        require(response.queryNonce == query.queryNonce && response.scope == ChannelScope(
            e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()))
        current()
        return PhoneUpdateSchedulingStatus(response, record, age)
    }
    private suspend fun <T : AutoCloseable> operation(request: suspend () -> PhoneUpdateSchedulingFrame,
        beforeSend: suspend () -> Unit = {}, response: suspend (PhoneUpdateSchedulingFrameV2, PhoneUpdateSchedulingFrame, UpdateSchedulingAge) -> T): T {
        var produced: T? = null
        var transferred = false
        try {
            check(used.compareAndSet(false, true) && !closed.get())
            return withTimeout(timeoutMillis) {
                val age = UpdateSchedulingAge(nowNanos(), nowNanos)
                current(); require(age.milliseconds() != null)
                val query = request()
                val bytes = if (version2) PhoneUpdateSchedulingFrameV2.Message(query).encode() else query.encode()
                current(); beforeSend(); require(age.milliseconds()?.let { it < timeoutMillis } == true)
                channel.send(bytes)
                val received = channel.receive() ?: throw IOException("Missing scheduling response")
                val reply = if (version2) PhoneUpdateSchedulingFrameV2.decode(received)
                    else PhoneUpdateSchedulingFrameV2.Message(PhoneUpdateSchedulingFrame.decode(received))
                require(reply.queryNonce == query.queryNonce &&
                    !(reply is PhoneUpdateSchedulingFrameV2.Message && reply.frame is PhoneUpdateSchedulingFrame.Failure))
                val result = response(reply, query, age)
                produced = result
                current(); require(age.milliseconds()?.let { it < timeoutMillis } == true)
                transferred = true
                result
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { throw IOException("Update scheduling unavailable") }
        finally { if (!transferred) produced?.close(); close() }
    }
    override fun close() { if (closed.compareAndSet(false, true)) channel.close() }
    suspend fun closeAndJoin() { close(); channel.closeAndJoin() }
    override fun toString() = "PhoneUpdateSchedulingChannel(redacted)"

    companion object {
        /** Android supplies elapsedRealtimeNanos and its current enrolled identity. Device sleep counts toward every deadline. */
        suspend fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                 currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long = 5_000): PhoneUpdateSchedulingChannel =
            bind(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis) { ByteArray(32).also { SecureRandom().nextBytes(it) } }

        internal suspend fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                          currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long,
                          newNonce: () -> ByteArray): PhoneUpdateSchedulingChannel {
            return bindFormat(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis, newNonce, false)
        }

        /** Select only after the retained release contract permits the version2 purpose. No fallback follows an application send. */
        suspend fun bindV2(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                           currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long = 5_000): PhoneUpdateSchedulingChannel =
            bindV2(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis) {
                ByteArray(32).also { SecureRandom().nextBytes(it) }
            }

        internal suspend fun bindV2(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                                   currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long,
                                   newNonce: () -> ByteArray): PhoneUpdateSchedulingChannel =
            bindFormat(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis, newNonce, true)

        private suspend fun bindFormat(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                                      currentEnrollment: suspend () -> StoredPhoneEnrollment, timeoutMillis: Long,
                                      newNonce: () -> ByteArray, version2: Boolean): PhoneUpdateSchedulingChannel {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
                currentCoroutineContext().ensureActive()
                val current = currentEnrollment()
                currentCoroutineContext().ensureActive()
                require(record.sameConnectionAs(current.also { require(it.phase == EnrollmentPhase.ACTIVE) }))
                val e = record.enrollment
                val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == (if (version2) EnrolledChannelPurpose.UPDATE_SCHEDULING_V2 else EnrolledChannelPurpose.UPDATE_SCHEDULING) &&
                    channel.localRequests.isEmpty() && channel.localAuditVersions.isEmpty())
                require(channel.maximumPayloadBytes >= (if (version2) PhoneUpdateSchedulingFrameV2.MAXIMUM_BYTES else PhoneUpdateSchedulingFrame.MAXIMUM_BYTES))
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= (record.pairing?.minimumEnvelopeVersion ?: 1uL) && peer.peer.requests.isEmpty() && peer.peer.auditVersions.isEmpty())
                return PhoneUpdateSchedulingChannel(record, channel, elapsedRealtimeNanos, currentEnrollment, timeoutMillis, newNonce, version2)
            } catch (failure: Throwable) { channel.close(); throw failure }
        }
    }
}

private val CONTROL_LIMITS = CborLimits(1024, 2, 32)
private val SIGNING_LIMITS = CborLimits(4096, 2, 32)
