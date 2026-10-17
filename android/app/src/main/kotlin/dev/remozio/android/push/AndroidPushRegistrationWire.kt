package dev.remozio.android.push

import android.content.Context
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.AndroidTransportIdentity
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidDirectRoutes
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.*
import dev.remozio.protocol.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal interface PushRecoveryWire : AutoCloseable {
    suspend fun recover(offer: PhonePushTokenOffer): PhonePushRecoveryResult
    suspend fun closeAndJoin()
}
internal interface PushProofWire : AutoCloseable {
    suspend fun prove(metadata: PhonePushRegistrationMetadata, challenge: PushData.TokenChallenge,
                      offer: PhonePushTokenOffer): PhonePushRegistrationOutcome
    suspend fun closeAndJoin()
}

/** Routing completes before the private exchange. Neither operation loads a decision or biometric key. */
internal suspend fun androidPushRecoveryWire(context: Context, parent: CoroutineScope, record: StoredPhoneEnrollment,
                                             timeoutMillis: Long): PushRecoveryWire {
    require(timeoutMillis in 1..60_000)
    val carrier = openPushCarrier(context, parent, record, EnrolledChannelPurpose.PUSH_RECOVERY)
    try { return AndroidRecoveryWire(PhonePushRecoveryChannel.bind(record, carrier.channel, timeoutMillis), carrier.identity) }
    catch (failure: Throwable) { carrier.closeAndJoin(); throw failure }
}
internal suspend fun androidPushProofWire(context: Context, parent: CoroutineScope, record: StoredPhoneEnrollment,
                                          timeoutMillis: Long): PushProofWire {
    require(timeoutMillis in 1..60_000)
    val carrier = openPushCarrier(context, parent, record, EnrolledChannelPurpose.PUSH_REGISTRATION)
    try { return AndroidProofWire(PhonePushRegistrationChannel.bind(record, carrier.channel, timeoutMillis), carrier.identity) }
    catch (failure: Throwable) { carrier.closeAndJoin(); throw failure }
}
private class PushCarrier(val channel: NegotiatedTLSChannel, val identity: AndroidTransportIdentity) {
    suspend fun closeAndJoin() = withContext(NonCancellable) { try { channel.closeAndJoin() } finally { identity.close() } }
}
private suspend fun openPushCarrier(context: Context, parent: CoroutineScope, record: StoredPhoneEnrollment,
                                     purpose: EnrolledChannelPurpose): PushCarrier {
    require(record.phase == EnrollmentPhase.ACTIVE)
    val e = record.enrollment
    var identity: AndroidTransportIdentity? = null
    var channel: NegotiatedTLSChannel? = null
    try {
        identity = AndroidTransportIdentities.load(e.transportKey.alias, e.transportKey.publicKey.copyBytes())
        val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), e.transportPublicKey.copyBytes(),
            ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
            emptyList(), emptySet(), PhonePushRecoveryFrame.MAXIMUM_BYTES,
            trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u, purpose = purpose)
        val relay = e.relayCredential?.let { credential -> ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential) } }
        channel = connector.connect(parent, androidDirectRoutes(context, e.macID.copyBytes()), relay,
            directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
        return PushCarrier(channel, identity)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { try { channel?.closeAndJoin() } finally { identity?.close() } }
        throw failure
    }
}
private class AndroidRecoveryWire(private val channel: PhonePushRecoveryChannel,
                                  private val identity: AndroidTransportIdentity) : PushRecoveryWire {
    override suspend fun recover(offer: PhonePushTokenOffer) = channel.recover(offer)
    override fun close() { channel.close(); identity.close() }
    override suspend fun closeAndJoin() { try { channel.closeAndJoin() } finally { identity.close() } }
}
private class AndroidProofWire(private val channel: PhonePushRegistrationChannel,
                               private val identity: AndroidTransportIdentity) : PushProofWire {
    override suspend fun prove(metadata: PhonePushRegistrationMetadata, challenge: PushData.TokenChallenge, offer: PhonePushTokenOffer) =
        channel.prove(metadata, challenge, offer)
    override fun close() { channel.close(); identity.close() }
    override suspend fun closeAndJoin() { try { channel.closeAndJoin() } finally { identity.close() } }
}
