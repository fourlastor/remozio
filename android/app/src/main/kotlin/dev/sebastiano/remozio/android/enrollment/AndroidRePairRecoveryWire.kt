package dev.sebastiano.remozio.android.enrollment

import android.content.Context
import android.net.ssl.SSLEngines
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.PairingRecoveryChannel
import dev.remozio.phone.transport.PairingRecoveryTLSProvider
import dev.remozio.phone.transport.RelayConnector
import dev.remozio.protocol.PairingRecoveryFrame
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.sebastiano.remozio.android.transport.LocalNetworkSettings
import dev.sebastiano.remozio.android.transport.androidDirectRoutes
import java.io.IOException
import javax.net.ssl.SSLEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal suspend fun androidRePairRecoveryWire(context: Context, parent: CoroutineScope, store: StoredPairingHost,
    access: PreparedPairingAccess,
): RePairRecoveryWire {
    val record = access.record
    val enrollment = record.enrollment
    val transcript = checkNotNull(record.pairing).transcript
    val predecessor = store.recoveryRelayPredecessor(access)
    suspend fun requireRelayCurrent() {
        val current = store.recoveryRelayPredecessor(access)
        if (predecessor == null || current == null || !current.sameConnectionAs(predecessor)) {
            throw IOException("Pairing recovery relay unavailable")
        }
    }
    val relay = predecessor?.enrollment?.relayCredential?.let { credential ->
        ApprovalCarrierRoute { owner -> RelayConnector().connect(owner, credential, ::requireRelayCurrent) }
    }
    val identity = AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes())
    val channel = try {
        PairingRecoveryChannel.connect(parent, androidDirectRoutes(context, enrollment.macID.copyBytes()), relay,
            LocalNetworkSettings(context).timeoutSeconds() * 1_000L, identity.keyManager,
            enrollment.transportPublicKey.copyBytes(), transcript, AndroidRecoveryExporter,
            { check(access.lease.isCurrent()) }, ::requireRelayCurrent)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { identity.close() }
        throw failure
    }
    return object : RePairRecoveryWire {
        override suspend fun lookup() = channel.lookup()
        override suspend fun closeAndJoin() {
            try { channel.closeAndJoin() } finally { identity.close() }
        }
    }
}

private object AndroidRecoveryExporter : PairingRecoveryTLSProvider {
    override fun configure(engine: SSLEngine) {
        if (!SSLEngines.isSupportedEngine(engine)) throw IOException("Pairing recovery TLS provider unavailable")
        SSLEngines.setUseSessionTickets(engine, false)
    }

    override fun export(engine: SSLEngine): ByteArray? =
        SSLEngines.exportKeyingMaterial(engine, PairingRecoveryFrame.EXPORTER_LABEL, ByteArray(0), 32)
}
