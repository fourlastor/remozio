package dev.remozio.android.updates

import android.content.Context
import android.os.SystemClock
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.AndroidTransportIdentity
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidDirectRoutes
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.ApprovalChannelConnector
import dev.remozio.phone.transport.EnrolledChannelPurpose
import dev.remozio.phone.transport.NegotiatedTLSChannel
import dev.remozio.phone.transport.PhoneUpdateSchedulingChannel
import dev.remozio.phone.transport.PhoneUpdateSchedulingStatus
import dev.remozio.phone.transport.PhoneUpdateSchedulingChallengeResult
import dev.remozio.phone.transport.PhoneUpdateSchedulingApplyResult
import dev.remozio.phone.transport.RelayConnector
import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingQuery
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PhoneUpdateSchedulingFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

internal interface MacUpdateSchedulingWire : AutoCloseable {
    suspend fun status(): PhoneUpdateSchedulingStatus
    suspend fun challenge(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallenge
    suspend fun apply(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingStatus
    suspend fun challengeResult(query: PhoneUpdateSchedulingQuery): PhoneUpdateSchedulingChallengeResult =
        PhoneUpdateSchedulingChallengeResult.Ready(challenge(query))
    suspend fun applyResult(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray): PhoneUpdateSchedulingApplyResult =
        PhoneUpdateSchedulingApplyResult.Applied(apply(challenge, signature))
    suspend fun closeAndJoin()
}

/** One enrolled exchange. The caller owns cleanup and supplies a fresh read under the enrollment mutex. */
internal suspend fun androidMacUpdateSchedulingWire(
    context: Context,
    parent: CoroutineScope,
    record: StoredPhoneEnrollment,
    timeoutMillis: Long,
    currentEnrollment: suspend () -> StoredPhoneEnrollment,
): MacUpdateSchedulingWire {
    require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
    var identity: AndroidTransportIdentity? = null
    var channel: NegotiatedTLSChannel? = null
    try {
        currentCoroutineContext().ensureActive()
        val current = currentEnrollment()
        currentCoroutineContext().ensureActive()
        require(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        val enrollment = record.enrollment
        identity = AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes())
        val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), enrollment.transportPublicKey.copyBytes(),
            ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(), enrollment.phoneID.copyBytes(),
                enrollment.epoch.copyBytes()), emptyList(), emptySet(), PhoneUpdateSchedulingFrame.MAXIMUM_BYTES,
            trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u, purpose = EnrolledChannelPurpose.UPDATE_SCHEDULING)
        val relay = enrollment.relayCredential?.let { credential ->
            ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential) }
        }
        channel = connector.connect(parent, androidDirectRoutes(context, enrollment.macID.copyBytes()), relay,
            directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
        val scheduling = PhoneUpdateSchedulingChannel.bind(record, channel, SystemClock::elapsedRealtimeNanos,
            currentEnrollment, timeoutMillis)
        return AndroidMacUpdateSchedulingWire(scheduling, identity)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { try { channel?.closeAndJoin() } finally { identity?.close() } }
        throw failure
    }
}

private class AndroidMacUpdateSchedulingWire(
    private val channel: PhoneUpdateSchedulingChannel,
    private val identity: AndroidTransportIdentity,
) : MacUpdateSchedulingWire {
    override suspend fun status() = channel.status()
    override suspend fun challenge(query: PhoneUpdateSchedulingQuery) = channel.challenge(query)
    override suspend fun apply(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray) = channel.apply(challenge, signature)
    override suspend fun challengeResult(query: PhoneUpdateSchedulingQuery) = channel.challengeResult(query)
    override suspend fun applyResult(challenge: PhoneUpdateSchedulingChallenge, signature: ByteArray) = channel.applyResult(challenge, signature)
    override fun close() { try { channel.close() } finally { identity.close() } }
    override suspend fun closeAndJoin() { try { channel.closeAndJoin() } finally { identity.close() } }
    override fun toString() = "AndroidMacUpdateSchedulingWire(redacted)"
}
