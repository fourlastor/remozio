package dev.remozio.phone.transport

import dev.remozio.protocol.ChannelRequestCapability
import dev.remozio.protocol.ChannelScope
import dev.remozio.protocol.PairingReceiptFrame
import java.io.IOException
import javax.net.ssl.KeyManager
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

enum class EnrolledChannelPurpose(val applicationProtocol: String) {
    APPROVALS("remozio/1"), PAIRING_RECEIPT(PairingReceiptFrame.APPLICATION_PROTOCOL),
}

/** Supplies ciphertext only. All routes use the same enrolled identity and peer pin. */
fun interface ApprovalCarrierRoute {
    suspend fun open(parent: CoroutineScope): EncryptedRecordTransport
}

/** Selects a route only after pinned TLS and protocol negotiation succeed. Never retries an application message. */
class ApprovalChannelConnector(
    localKeys: Array<KeyManager>, peerPublicKey: ByteArray,
    private val scope: ChannelScope,
    requests: List<ChannelRequestCapability>, auditVersions: Set<ULong>,
    private val maximumPayloadBytes: Int, private val trustedMinimum: ULong = 1u,
    private val purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.APPROVALS,
) {
    private val keys = localKeys.copyOf()
    private val pin = peerPublicKey.copyOf()
    private val requests = requests.toList()
    private val auditVersions = auditVersions.toSet()

    suspend fun connect(parent: CoroutineScope, direct: Flow<ApprovalCarrierRoute>, relay: ApprovalCarrierRoute?,
                        directTimeoutMillis: Long = 3_000): NegotiatedTLSChannel =
        directFirst(direct, relay, directTimeoutMillis, { open(parent, it) }, { it.close() })

    private suspend fun open(parent: CoroutineScope, route: ApprovalCarrierRoute): NegotiatedTLSChannel {
        var carrier: EncryptedRecordTransport? = null
        var engine: PinnedTLSClient? = null
        var session: TLSRecordSession? = null
        var channel: NegotiatedTLSChannel? = null
        try {
            carrier = route.open(parent)
            currentCoroutineContext().ensureActive()
            engine = PinnedTLSClient(keys, pin, purpose.applicationProtocol, 1_048_576)
            session = TLSRecordSession(parent, engine, carrier)
            channel = NegotiatedTLSChannel.connect(session, scope, requests, auditVersions, maximumPayloadBytes, trustedMinimum, purpose = purpose)
            currentCoroutineContext().ensureActive()
            return channel
        } catch (failure: Throwable) {
            // Abort I/O now. The parent still owns workers that finish provider calls and release their engine later.
            when {
                channel != null -> channel.close()
                session != null -> session.close()
                else -> { engine?.close(); carrier?.close() }
            }
            throw failure
        }
    }
}

/** The opener releases failed attempts. The selector owns a successful result until it returns it. */
internal suspend fun <R, T : Any> directFirst(direct: Flow<R>, relay: R?, timeoutMillis: Long,
                                       open: suspend (R) -> T, release: suspend (T) -> Unit): T {
    require(timeoutMillis in 1..10_000)
    var selected: T? = null
    var transferred = false
    try {
        val result = withTimeoutOrNull(timeoutMillis) {
            try {
                direct.take(8).mapNotNull { route ->
                    try { open(route).also { selected = it } }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { null }
                }.firstOrNull()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { null }
        }
        currentCoroutineContext().ensureActive()
        if (result != null) { transferred = true; return result }
    } finally {
        if (!transferred) selected?.let { withContext(NonCancellable) { release(it) } }
    }
    currentCoroutineContext().ensureActive()
    val route = relay ?: throw IOException("No authenticated route available")
    return open(route)
}
