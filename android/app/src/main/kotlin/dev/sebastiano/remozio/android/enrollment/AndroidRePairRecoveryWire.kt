package dev.sebastiano.remozio.android.enrollment

import android.content.Context
import android.net.ssl.SSLEngines
import dev.remozio.phone.transport.ApprovalCarrierRoute
import dev.remozio.phone.transport.PairingRecoveryChannel
import dev.remozio.phone.transport.PairingRecoveryTLSProvider
import dev.remozio.phone.transport.RelayConnector
import dev.remozio.protocol.PairingRecoveryFrame
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentity
import dev.sebastiano.remozio.android.transport.LocalNetworkSettings
import dev.sebastiano.remozio.android.transport.androidDirectRoutes
import java.io.IOException
import javax.net.ssl.SSLEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal suspend fun androidRePairRecoveryWire(context: Context, parent: CoroutineScope, store: StoredPairingHost,
    access: PreparedPairingAccess, attemptMillis: Long,
): RePairRecoveryWire {
    val record = access.record
    val enrollment = record.enrollment
    val transcript = checkNotNull(record.pairing).transcript
    val borrow = withContext(NonCancellable) { store.borrowRecoveryRelay(access) }
    suspend fun closeRelay() { borrow?.let { store.releaseRecoveryRelay(access, it) } }
    suspend fun requireRelayCurrent() {
        val current = store.recoveryRelayPredecessor(access)
        if (borrow == null || !borrow.lease.isCurrent() || current == null || !current.sameConnectionAs(borrow.predecessor)) {
            throw IOException("Pairing recovery relay unavailable")
        }
    }
    val relay = borrow?.let { relayAccess ->
        val credential = checkNotNull(relayAccess.predecessor.enrollment.relayCredential)
        ApprovalCarrierRoute { owner -> RelayConnector().connectRecovery(owner, credential, relayAccess.lease, ::requireRelayCurrent) }
    }
    var identity: AndroidTransportIdentity? = null
    try {
        currentCoroutineContext().ensureActive()
        val heldIdentity = AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes())
        identity = heldIdentity
        val directMillis = recoveryDirectBudget(LocalNetworkSettings(context).timeoutSeconds() * 1_000L, attemptMillis)
        val channel = PairingRecoveryChannel.connect(parent, androidDirectRoutes(context, enrollment.macID.copyBytes()), relay,
            directMillis, heldIdentity.keyManager, enrollment.transportPublicKey.copyBytes(), transcript, AndroidRecoveryExporter,
            { check(access.lease.isCurrent()) }, ::requireRelayCurrent)
        return object : RePairRecoveryWire {
            override suspend fun lookup() = channel.lookup()
            override suspend fun closeAndJoin() {
                try { channel.closeAndJoin() } finally {
                    try { heldIdentity.close() } finally { closeRelay() }
                }
            }
        }
    } catch (failure: Throwable) {
        withContext(NonCancellable) { try { identity?.close() } finally { closeRelay() } }
        throw failure
    }
}

internal fun recoveryDirectBudget(settingMillis: Long, attemptMillis: Long): Long =
    minOf(settingMillis, (attemptMillis / 2).coerceAtLeast(1))

private object AndroidRecoveryExporter : PairingRecoveryTLSProvider {
    override fun configure(engine: SSLEngine) {
        if (!SSLEngines.isSupportedEngine(engine)) throw IOException("Pairing recovery TLS provider unavailable")
        SSLEngines.setUseSessionTickets(engine, false)
    }

    override fun export(engine: SSLEngine): ByteArray? =
        SSLEngines.exportKeyingMaterial(engine, PairingRecoveryFrame.EXPORTER_LABEL, ByteArray(0), 32)
}
