package dev.remozio.android.requests

import android.content.Context
import androidx.annotation.WorkerThread
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidDirectRoutes
import dev.remozio.android.transport.AndroidTransportIdentity
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.requests.CommandMemoryBudget
import dev.remozio.phone.requests.CommandRequestEnrollment
import dev.remozio.phone.requests.CommandSnapshotReceiver
import dev.remozio.phone.requests.CommandRequestReceiver
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.phone.transport.*
import dev.remozio.protocol.ApprovalMessage
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PendingRequestSnapshotFrame
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import java.util.concurrent.atomic.AtomicBoolean

/** Direct-first routing uses the same enrolled TLS pin and protocol scope on every path. */
@WorkerThread
internal fun androidCommandConnection(context: Context, record: StoredPhoneEnrollment, limits: RequestLimits, memoryBudget: CommandMemoryBudget? = null): CommandConnection {
    require(record.phase == EnrollmentPhase.ACTIVE)
    val retired = AndroidRetiredCommandRequests.open(context, record.enrollment)
    try {
        suspend fun openWire(scope: CoroutineScope, enrollment: CommandRequestEnrollment, snapshot: Boolean): CommandConnectionWire {
            val e = record.enrollment
            var identity: AndroidTransportIdentity? = null
            var channel: NegotiatedTLSChannel? = null
            try {
                identity = AndroidTransportIdentities.load(e.transportKey.alias, e.transportKey.publicKey.copyBytes())
                val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), e.transportPublicKey.copyBytes(),
                    ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
                    commandInspectionCapabilities(), emptySet(),
                    if (snapshot) CommandSnapshotReceiver.requiredChannelPayloadBytes(limits)
                    else maxOf(limits.body.maxBytes, limits.status.maxBytes) + ApprovalMessage.OVERHEAD_BYTES,
                    trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u,
                    purpose = if (snapshot) EnrolledChannelPurpose.PENDING_SNAPSHOT else EnrolledChannelPurpose.APPROVALS)
                val relay = e.relayCredential?.let { credential -> ApprovalCarrierRoute { parent -> RelayConnector().connect(parent, credential) } }
                channel = connector.connect(scope, androidDirectRoutes(context, e.macID.copyBytes()), relay,
                    directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
                return if (snapshot) NativeSnapshotWire(CommandSnapshotReceiver.bind(enrollment, channel,
                    e.phoneID.copyBytes(), e.epoch.copyBytes(), PendingRequestSnapshotFrame.MAXIMUM_FRAMES,
                    PendingRequestSnapshotFrame.MAXIMUM_SNAPSHOT_BYTES, RequestElapsedClock::now), identity)
                else NativeCommandWire(CommandRequestReceiver.bind(enrollment, channel,
                    e.phoneID.copyBytes(), e.epoch.copyBytes(), clock = RequestElapsedClock::now), identity)
            } catch (failure: Throwable) {
                channel?.close()
                identity?.close()
                throw failure
            }
        }
        return CommandConnection(record, limits, open = { scope, enrollment -> openWire(scope, enrollment, false) },
            clock = RequestElapsedClock::now, retired = retired, memoryBudget = memoryBudget,
            openSnapshot = { scope, enrollment -> openWire(scope, enrollment, true) })
    } catch (failure: Throwable) { retired.close(); throw failure }
}

private class NativeCommandWire(
    private val receiver: CommandRequestReceiver,
    private val identity: AndroidTransportIdentity,
) : CommandConnectionWire {
    private val closed = AtomicBoolean(false)
    override suspend fun receive() = receiver.run()
    override suspend fun send(bytes: ByteArray) = receiver.sendDecision(bytes)
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { receiver.close() } finally { identity.close() }
        }
    }
}

/** Read-only snapshot transport. The connection owner never publishes it for decisions. */
private class NativeSnapshotWire(
    private val receiver: CommandSnapshotReceiver,
    private val identity: AndroidTransportIdentity,
) : CommandConnectionWire {
    private val closed = AtomicBoolean(false)
    override suspend fun receive() = receiver.run()
    override suspend fun send(bytes: ByteArray): Unit = throw IOException("Snapshot is read-only")
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { receiver.close() } finally { identity.close() }
        }
    }
}
