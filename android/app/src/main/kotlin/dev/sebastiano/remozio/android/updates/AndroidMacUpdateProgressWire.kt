package dev.sebastiano.remozio.android.updates

import android.content.Context
import android.os.SystemClock
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentity
import dev.sebastiano.remozio.android.transport.LocalNetworkSettings
import dev.sebastiano.remozio.android.transport.androidDirectRoutes
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.ApprovalChannelConnector
import dev.remozio.phone.transport.EnrolledChannelPurpose
import dev.remozio.phone.transport.NegotiatedTLSChannel
import dev.remozio.phone.transport.PhoneUpdateProgressChannel
import dev.remozio.phone.transport.RelayConnector
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PhoneUpdateProgressFrame
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** Opens the dedicated progress purpose with the enrolled transport identity. */
internal suspend fun androidMacUpdateProgressWire(
    context: Context,
    parent: CoroutineScope,
    record: StoredPhoneEnrollment,
    timeoutMillis: Long,
    currentEnrollment: suspend () -> StoredPhoneEnrollment,
): MacUpdateProgressWire {
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
                enrollment.epoch.copyBytes()), emptyList(), emptySet(), PhoneUpdateProgressFrame.MAXIMUM_BYTES,
            trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u, purpose = EnrolledChannelPurpose.UPDATE_PROGRESS)
        val relay = enrollment.relayCredential?.let { credential ->
            ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential) }
        }
        channel = connector.connect(parent, androidDirectRoutes(context, enrollment.macID.copyBytes()), relay,
            directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
        val progress = PhoneUpdateProgressChannel.bind(record, channel, SystemClock::elapsedRealtimeNanos,
            currentEnrollment, timeoutMillis)
        return AndroidMacUpdateProgressWire(progress, identity)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { try { channel?.closeAndJoin() } finally { identity?.close() } }
        throw failure
    }
}

private class AndroidMacUpdateProgressWire(
    private val channel: PhoneUpdateProgressChannel,
    private val identity: AndroidTransportIdentity,
) : MacUpdateProgressWire {
    private val closed = AtomicBoolean(false)
    override suspend fun read() = channel.read()
    override fun close() {
        if (closed.compareAndSet(false, true)) try { channel.close() } finally { identity.close() }
    }
    override suspend fun closeAndJoin() { try { close() } finally { channel.closeAndJoin() } }
    override fun toString() = "AndroidMacUpdateProgressWire(redacted)"
}
