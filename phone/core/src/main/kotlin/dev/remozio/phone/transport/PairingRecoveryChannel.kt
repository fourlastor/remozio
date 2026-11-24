package dev.remozio.phone.transport

import dev.remozio.protocol.PairingRecoveryFrame
import dev.remozio.protocol.PairingRecoveryQuery
import dev.remozio.protocol.PairingTranscript
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

/** Platform operations confined to the engine for a single authenticated recovery connection. */
interface PairingRecoveryTLSProvider {
    fun configure(engine: SSLEngine)
    fun export(engine: SSLEngine): ByteArray?
}

/** The opener authenticates a route before this channel sends one lookup. The caller owns the lease and key manager. */
class PairingRecoveryChannel private constructor(
    private val session: TLSRecordSession,
    private val exporter: ByteArray,
    private val query: PairingRecoveryQuery,
    private val keys: ClientTLSKeyManager,
    private val requireCurrent: suspend () -> Unit,
) : AutoCloseable {
    private val started = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)

    suspend fun lookup(): PairingRecoveryFrame.Reply {
        check(started.compareAndSet(false, true))
        val material = synchronized(exporter) {
            check(!closed.get())
            exporter.copyOf().also { exporter.fill(0) }
        }
        return try {
            exchange(query, material, session::send, session::receive, keys::signRecovery) {
                check(!closed.get())
                requireCurrent()
            }
        } finally {
            material.fill(0)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        session.close()
        synchronized(exporter) { exporter.fill(0) }
    }

    suspend fun closeAndJoin() { close(); session.closeAndJoin() }

    companion object {
        suspend fun connect(parent: CoroutineScope, direct: Flow<ApprovalCarrierRoute>, relay: ApprovalCarrierRoute?,
            directTimeoutMillis: Long, keys: ClientTLSKeyManager, pin: ByteArray, transcript: PairingTranscript,
            provider: PairingRecoveryTLSProvider, requireCurrent: suspend () -> Unit,
            requireRelayCurrent: suspend () -> Unit,
        ): PairingRecoveryChannel {
            val query = PairingRecoveryQuery.fromTranscript(transcript)
            return directFirst(direct, relay, directTimeoutMillis, { route ->
                val checkRoute: suspend () -> Unit = {
                    requireCurrent()
                    if (route === relay) requireRelayCurrent()
                }
                var carrier: EncryptedRecordTransport? = null
                var engine: PinnedTLSClient? = null
                var session: TLSRecordSession? = null
                try {
                    checkRoute()
                    carrier = route.open(parent)
                    engine = PinnedTLSClient.forPairingRecovery(arrayOf(keys), pin, provider)
                    session = TLSRecordSession(parent, engine, carrier)
                    session.awaitOpen()
                    checkRoute()
                    PairingRecoveryChannel(session, engine.recoveryExporter(), query, keys, checkRoute)
                } catch (failure: Throwable) {
                    withContext(NonCancellable) {
                        if (session != null) session.closeAndJoin() else {
                            try { carrier?.close(); carrier?.awaitClosed() } finally { engine?.close() }
                        }
                    }
                    throw failure
                }
            }, { it.closeAndJoin() })
        }

        internal suspend fun exchange(query: PairingRecoveryQuery, exporter: ByteArray, send: suspend (ByteArray) -> Unit,
            receive: suspend () -> ByteArray?, sign: (PairingRecoveryQuery, ByteArray, ByteArray) -> ByteArray,
            requireCurrent: suspend () -> Unit,
        ): PairingRecoveryFrame.Reply {
            suspend fun checkCurrent() {
                currentCoroutineContext().ensureActive()
                requireCurrent()
                currentCoroutineContext().ensureActive()
            }
            suspend fun write(frame: PairingRecoveryFrame) {
                checkCurrent()
                val body = frame.encode()
                send(ByteBuffer.allocate(4 + body.size).putInt(body.size).put(body).array())
            }
            val reader = RecoveryFrameReader(receive)
            require(exporter.size == 32)
            write(PairingRecoveryFrame.Lookup(query))
            val challenge = reader.read() as? PairingRecoveryFrame.Challenge ?: throw IOException("Missing recovery challenge")
            checkCurrent()
            val proof = sign(query, exporter, challenge.bytes.copyBytes())
            write(PairingRecoveryFrame.Proof(proof))
            val reply = reader.read() as? PairingRecoveryFrame.Reply ?: throw IOException("Missing recovery reply")
            checkCurrent()
            return reply
        }
    }
}

/** The peer must wait for the matching next message before writing more bytes. */
private class RecoveryFrameReader(private val receive: suspend () -> ByteArray?) {
    private var pending = ByteBuffer.allocate(0)

    suspend fun read(): PairingRecoveryFrame {
        val length = ByteBuffer.wrap(exact(4)).int
        require(length in 1..PairingRecoveryFrame.MAXIMUM_BYTES)
        val frame = PairingRecoveryFrame.decode(exact(length))
        if (pending.hasRemaining()) throw IOException("Unexpected bytes after recovery frame")
        return frame
    }

    private suspend fun exact(size: Int): ByteArray {
        val bytes = ByteArray(size)
        var offset = 0
        while (offset < size) {
            if (!pending.hasRemaining()) {
                val next = receive() ?: throw IOException("Truncated recovery frame")
                require(next.size in 1..32_768)
                pending = ByteBuffer.wrap(next)
            }
            val count = minOf(size - offset, pending.remaining())
            pending.get(bytes, offset, count)
            offset += count
        }
        return bytes
    }
}
