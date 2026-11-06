package dev.remozio.phone.transport

import dev.remozio.pairing.PairingByteStream
import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.pairing.firstAuthenticatedPairingRoute
import dev.remozio.protocol.*
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow

private class PairingTLSStream(private val session: TLSRecordSession) : PairingByteStream {
    override suspend fun awaitOpen() = session.awaitOpen()
    override suspend fun send(bytes: ByteArray) = session.send(bytes)
    override suspend fun receive(): ByteArray? = session.receive()
    override fun close() = session.close()
    override suspend fun awaitClosed() = session.closeAndJoin()
}

private val P256_SPKI_PREFIX = byteArrayOf(0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x02,0x01,
    0x06,0x08,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x03,0x01,0x07,0x03,0x42,0x00)

/** The carrier is untrusted. Fresh TLS authenticates the invitation pin with the separate pairing ALPN.
 * The Android caller supplies its newly created hardware transport key manager.
 * Only pinned TLS and the restricted hello are read here. No phone proposal or enrollment action is sent. */
suspend fun PairingSetupChannel.Companion.authenticate(parent: CoroutineScope, carrier: EncryptedRecordTransport,
    localKeys: Array<KeyManager>, invitation: PairingInvitation, proposal: PairingPhoneProposal, timeoutMillis: Long = 300_000,
): PairingSetupChannel = authenticate(parent, invitation, proposal, timeoutMillis) { scope -> openPairingTLS(scope, carrier, localKeys, invitation) }

/** [authenticate], then the sole proposal and the transcript. */
suspend fun PairingSetupChannel.Companion.connect(parent: CoroutineScope, carrier: EncryptedRecordTransport,
    localKeys: Array<KeyManager>, invitation: PairingInvitation, proposal: PairingPhoneProposal, timeoutMillis: Long = 300_000,
): PairingSetupChannel = connect(parent, invitation, proposal, timeoutMillis) { scope -> openPairingTLS(scope, carrier, localKeys, invitation) }

// Releases whatever it created if it throws, because the caller never receives the stream.
private suspend fun openPairingTLS(scope: CoroutineScope, carrier: EncryptedRecordTransport, localKeys: Array<KeyManager>,
    invitation: PairingInvitation,
): PairingByteStream {
    var engine: PinnedTLSClient? = null
    var session: TLSRecordSession? = null
    try {
        engine = PinnedTLSClient(localKeys, P256_SPKI_PREFIX + invitation.transportPublicKey.copyBytes(),
            PairingSetupFrame.APPLICATION_PROTOCOL, 1_048_576)
        session = TLSRecordSession(scope, engine, carrier)
        return PairingTLSStream(session)
    } catch (failure: Throwable) {
        withContext(NonCancellable) {
            if (session != null) session.closeAndJoin() else { carrier.close(); carrier.awaitClosed(); engine?.close() }
        }
        throw failure
    }
}

/** Race at most eight hints under one discovery/authentication budget. No proposal is sent before route selection. */
suspend fun authenticatePairingRoutes(parent: CoroutineScope, direct: Flow<ApprovalCarrierRoute>,
    localKeys: Array<KeyManager>, invitation: PairingInvitation, proposal: PairingPhoneProposal, timeoutMillis: Long,
): PairingSetupChannel = firstAuthenticatedPairingRoute(direct, timeoutMillis, { route ->
    val carrier = route.open(parent)
    try {
        currentCoroutineContext().ensureActive()
        PairingSetupChannel.authenticate(parent, carrier, localKeys, invitation, proposal)
    } catch (failure: Throwable) {
        withContext(NonCancellable) { carrier.close(); carrier.awaitClosed() }
        throw failure
    }
}, { it.closeAndJoin() })
