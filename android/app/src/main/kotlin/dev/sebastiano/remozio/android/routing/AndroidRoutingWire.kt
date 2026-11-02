package dev.sebastiano.remozio.android.routing

import android.content.Context
import android.os.SystemClock
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentity
import dev.sebastiano.remozio.android.transport.LocalNetworkSettings
import dev.sebastiano.remozio.android.transport.androidDirectRoutes
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.*
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PhoneRoutingFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal interface RoutingWire : AutoCloseable {
    suspend fun status(): PhoneRoutingResult
    suspend fun challenge(expectedRevision: ULong): PhoneRoutingResult
    suspend fun apply(challenge: PhoneRoutingChallenge, signature: ByteArray): PhoneRoutingResult
    suspend fun closeAndJoin()
}

/** All routes use the same enrolled TLS identity, peer pin and routing-only purpose. */
internal suspend fun androidRoutingWire(context: Context, parent: CoroutineScope, record: StoredPhoneEnrollment,
                                        timeoutMillis: Long): RoutingWire {
    require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
    val e = record.enrollment
    var identity: AndroidTransportIdentity? = null
    var channel: NegotiatedTLSChannel? = null
    try {
        identity = AndroidTransportIdentities.load(e.transportKey.alias, e.transportKey.publicKey.copyBytes())
        val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), e.transportPublicKey.copyBytes(),
            ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
            emptyList(), emptySet(), PhoneRoutingFrame.MAXIMUM_BYTES,
            trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u, purpose = EnrolledChannelPurpose.ROUTING)
        val relay = e.relayCredential?.let { credential -> ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential) } }
        channel = connector.connect(parent, androidDirectRoutes(context, e.macID.copyBytes()), relay,
            directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
        return AndroidRoutingWire(PhoneRoutingChannel.bind(record, channel, SystemClock::elapsedRealtimeNanos, timeoutMillis), identity)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { try { channel?.closeAndJoin() } finally { identity?.close() } }
        throw failure
    }
}
private class AndroidRoutingWire(private val channel: PhoneRoutingChannel,
                                 private val identity: AndroidTransportIdentity) : RoutingWire {
    override suspend fun status() = channel.status()
    override suspend fun challenge(expectedRevision: ULong) = channel.challenge(expectedRevision)
    override suspend fun apply(challenge: PhoneRoutingChallenge, signature: ByteArray) = channel.apply(challenge, signature)
    override fun close() { try { channel.close() } finally { identity.close() } }
    override suspend fun closeAndJoin() { try { channel.closeAndJoin() } finally { identity.close() } }
}
