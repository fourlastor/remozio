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

sealed interface PhonePushPreparation {
    class Ready(val metadata: PhonePushRegistrationMetadata) : PhonePushPreparation {
        override fun toString() = "PhonePushPreparation.Ready(redacted)"
    }
    class Status(val outcome: PhonePushRegistrationOutcome) : PhonePushPreparation
}

/** One registration exchange. Callers recheck current enrollment and provider state before publishing its result. */
class PhonePushRegistrationChannel private constructor(
    private val channel: NegotiatedTLSChannel,
    private val record: StoredPhoneEnrollment,
    private val timeoutMillis: Long,
    private val newID: () -> ByteArray,
) : AutoCloseable {
    private val used = AtomicBoolean(false)

    suspend fun prepare(offer: PhonePushTokenOffer): PhonePushPreparation = operation {
        val id = newID()
        val response = exchange(PhonePushRegistrationFrame.Offer(id, offer))
        when (response) {
            is PhonePushRegistrationFrame.Prepared -> {
                validate(response.metadata, offer)
                PhonePushPreparation.Ready(response.metadata)
            }
            is PhonePushRegistrationFrame.Outcome -> PhonePushPreparation.Status(response.outcome)
            else -> throw IOException("Invalid push registration response")
        }
    }

    /** Challenge receipt must come from the provider. Matching metadata alone is not token-possession proof. */
    suspend fun prove(metadata: PhonePushRegistrationMetadata, challenge: PushData.TokenChallenge,
                      offer: PhonePushTokenOffer): PhonePushRegistrationOutcome = operation {
        validate(metadata, offer)
        val response = exchange(PhonePushRegistrationFrame.Proof(newID(), metadata.proof(challenge)))
        (response as? PhonePushRegistrationFrame.Outcome)?.outcome ?: throw IOException("Invalid push registration response")
    }

    private fun validate(metadata: PhonePushRegistrationMetadata, offer: PhonePushTokenOffer) {
        val e = record.enrollment
        require(metadata.scope == ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()))
        require(metadata.enrollmentTag.contentEquals(e.enrollmentTag.copyBytes()))
        require(metadata.tokenDigest.contentEquals(MessageDigest.getInstance("SHA-256").digest(offer.token.toByteArray(Charsets.UTF_8))))
    }
    private suspend fun exchange(request: PhonePushRegistrationFrame): PhonePushRegistrationFrame {
        channel.send(request.encode())
        val bytes = channel.receive() ?: throw IOException("Missing push registration response")
        val response = PhonePushRegistrationFrame.decode(bytes)
        require(response.correlationID == request.correlationID)
        return response
    }
    private suspend fun <T> operation(body: suspend () -> T): T {
        try {
            check(used.compareAndSet(false, true))
            return withTimeout(timeoutMillis) { body() }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { throw IOException("Push registration unavailable") }
        finally { close() }
    }
    override fun close() = channel.close()
    suspend fun closeAndJoin() = channel.closeAndJoin()
    override fun toString() = "PhonePushRegistrationChannel(redacted)"

    companion object {
        fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, timeoutMillis: Long = 5_000): PhonePushRegistrationChannel =
            bind(record, channel, timeoutMillis) { ByteArray(16).also { SecureRandom().nextBytes(it) } }

        internal fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, timeoutMillis: Long,
                          newID: () -> ByteArray): PhonePushRegistrationChannel {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
                val e = record.enrollment
                val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == EnrolledChannelPurpose.PUSH_REGISTRATION && channel.localRequests.isEmpty() && channel.localAuditVersions.isEmpty())
                require(channel.maximumPayloadBytes >= PhonePushRegistrationFrame.MAXIMUM_BYTES)
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= (record.pairing?.minimumEnvelopeVersion ?: 1uL) && peer.peer.requests.isEmpty() && peer.peer.auditVersions.isEmpty())
                return PhonePushRegistrationChannel(channel, record, timeoutMillis, newID)
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}
