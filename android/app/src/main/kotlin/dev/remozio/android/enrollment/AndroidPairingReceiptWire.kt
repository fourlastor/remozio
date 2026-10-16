package dev.remozio.android.enrollment

import android.content.Context
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.AndroidTransportIdentity
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidDirectRoutes
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.*
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingReceiptFrame
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal suspend fun androidPairingReceiptWire(context: Context, parent: CoroutineScope, record: StoredPhoneEnrollment): PairingReceiptWire {
    require(record.phase == EnrollmentPhase.PREPARED)
    val enrollment = record.enrollment
    var identity: AndroidTransportIdentity? = null
    var channel: NegotiatedTLSChannel? = null
    try {
        identity = AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes())
        val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), enrollment.transportPublicKey.copyBytes(),
            ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(), enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes()),
            emptyList(), emptySet(), PairingReceiptFrame.MAXIMUM_BYTES,
            trustedMinimum = checkNotNull(record.pairing).minimumEnvelopeVersion, purpose = EnrolledChannelPurpose.PAIRING_RECEIPT)
        val relay = enrollment.relayCredential?.let { credential -> ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential) } }
        channel = connector.connect(parent, androidDirectRoutes(context, enrollment.macID.copyBytes()), relay,
            directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
        return AndroidPairingReceiptWire(PairingReceiptChannel.bind(record, channel), identity)
    } catch (failure: Throwable) {
        withContext(NonCancellable) {
            try { channel?.closeAndJoin() } finally { identity?.close() }
        }
        throw failure
    }
}

private class AndroidPairingReceiptWire(
    private val channel: PairingReceiptChannel,
    private val identity: AndroidTransportIdentity,
) : PairingReceiptWire {
    override suspend fun recover() = channel.recover()
    override fun close() { channel.close(); identity.close() }
    override suspend fun closeAndJoin() {
        try { channel.closeAndJoin() } finally { identity.close() }
    }
}
