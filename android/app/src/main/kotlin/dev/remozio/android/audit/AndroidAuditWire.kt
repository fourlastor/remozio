package dev.remozio.android.audit

import android.content.Context
import android.os.SystemClock
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.AndroidTransportIdentity
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidDirectRoutes
import dev.remozio.phone.audit.AuditExchange
import dev.remozio.phone.audit.AuditQuery
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.transport.*
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PhoneAuditFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** The audit uses its own ALPN and the existing enrolled identity, peer pin and route selection. */
internal suspend fun androidAuditWire(context: Context, parent: CoroutineScope, record: StoredPhoneEnrollment,
                                      timeoutMillis: Long): AuditExchange {
    require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
    val enrollment = record.enrollment
    var identity: AndroidTransportIdentity? = null
    var channel: NegotiatedTLSChannel? = null
    try {
        identity = AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes())
        val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), enrollment.transportPublicKey.copyBytes(),
            ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(), enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes()),
            emptyList(), setOf(1u), PhoneAuditFrame.MAXIMUM_BYTES,
            trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u, purpose = EnrolledChannelPurpose.AUDIT)
        val relay = enrollment.relayCredential?.let { credential -> ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential) } }
        channel = connector.connect(parent, androidDirectRoutes(context, enrollment.macID.copyBytes()), relay,
            directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
        return AndroidAuditWire(PhoneAuditChannel.bind(record, channel,
            { ElapsedInstant(1, SystemClock.elapsedRealtime().toULong()) }, timeoutMillis), identity)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { try { channel?.closeAndJoin() } finally { identity?.close() } }
        throw failure
    }
}
private class AndroidAuditWire(private val channel: PhoneAuditChannel,
                               private val identity: AndroidTransportIdentity) : AuditExchange {
    override suspend fun exchange(query: AuditQuery) = channel.exchange(query)
    override fun close() { try { channel.close() } finally { identity.close() } }
    override suspend fun closeAndJoin() { try { channel.closeAndJoin() } finally { identity.close() } }
}
