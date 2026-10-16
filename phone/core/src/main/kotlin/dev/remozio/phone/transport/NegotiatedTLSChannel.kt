package dev.remozio.phone.transport

import dev.remozio.protocol.*
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeout

internal interface ApprovalByteStream : AutoCloseable {
    suspend fun awaitOpen()
    suspend fun send(bytes: ByteArray)
    suspend fun receive(): ByteArray?
    suspend fun awaitClosed()
}
private class TLSApprovalStream(private val session: TLSRecordSession) : ApprovalByteStream {
    override suspend fun awaitOpen() = session.awaitOpen()
    override suspend fun send(bytes: ByteArray) = session.send(bytes)
    override suspend fun receive() = session.receive()
    override fun close() = session.close()
    override suspend fun awaitClosed() = session.closeAndJoin()
}

/** Owns framing, negotiation, and sequences for one enrolled TLS session. It grants no action authority. */
class NegotiatedTLSChannel private constructor(private val stream: ApprovalByteStream, internal val maximumPayloadBytes: Int,
    val purpose: EnrolledChannelPurpose) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val readLock = Mutex()
    private val writeLock = Mutex()
    private var pending = ByteArray(0)
    private var offset = 0
    private var outgoing: ULong? = 0u
    private var incoming: ULong? = 0u
    internal var localAuditVersions: Set<ULong> = emptySet()
        private set
    private lateinit var metadata: NegotiatedChannel
    internal var localRequests: List<ChannelRequestCapability> = emptyList()
        private set
    val negotiated: NegotiatedChannel get() { check(!closed.get()); return metadata }

    suspend fun send(payload: ByteArray): Unit = operation {
        require(payload.size in 1..maximumPayloadBytes)
        check(writeLock.tryLock())
        try {
            active()
            val bytes = payload.copyOf()
            val sequence = outgoing ?: throw IOException("Sequence exhausted")
            writeFrame(SessionEnvelope(metadata.sessionID.copyBytes(), sequence, bytes).encode(maximumPayloadBytes))
            outgoing = if (sequence == ULong.MAX_VALUE) null else sequence + 1u
        } finally { writeLock.unlock() }
    }
    suspend fun receive(): ByteArray? = operation {
        check(readLock.tryLock())
        try {
            active()
            val frame = readFrame(maximumPayloadBytes + 64) ?: return@operation null.also { close() }
            val envelope = SessionEnvelope.decode(frame, maximumPayloadBytes)
            check(envelope.sessionID == metadata.sessionID && envelope.sequence == incoming)
            incoming = if (envelope.sequence == ULong.MAX_VALUE) null else envelope.sequence + 1u
            active()
            envelope.payload.copyBytes()
        } finally { readLock.unlock() }
    }
    override fun close() { if (closed.compareAndSet(false, true)) stream.close() }
    suspend fun closeAndJoin() { close(); stream.awaitClosed() }

    private suspend fun negotiate(scope: ChannelScope, requests: List<ChannelRequestCapability>, auditVersions: Set<ULong>,
                                  trustedMinimum: ULong, timeoutMillis: Long) = operation {
        require(timeoutMillis in 1..60_000 && maximumPayloadBytes in 1..16_777_216)
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val offer = ChannelOffer(ChannelRole.PHONE, scope, nonce, setOf(1u), requests, auditVersions)
        val owner = ChannelNegotiation(offer, trustedMinimum)
        try {
            withTimeout(timeoutMillis) {
                stream.awaitOpen(); active()
                writeFrame(owner.offer())
                owner.receiveOffer(readFrame(65_536) ?: throw IOException("Missing offer"))
                writeFrame(owner.confirmation())
                owner.receiveConfirmation(readFrame(128) ?: throw IOException("Missing confirmation"))
                active(); metadata = owner.confirmed(); localRequests = offer.requests; localAuditVersions = offer.auditVersions
            }
        } finally { owner.close() }
    }
    private suspend fun writeFrame(bytes: ByteArray) {
        active()
        val size = bytes.size
        stream.send(byteArrayOf((size ushr 24).toByte(), (size ushr 16).toByte(), (size ushr 8).toByte(), size.toByte()))
        active()
        var position = 0
        while (position < size) {
            val end = minOf(position + 32_768, size)
            stream.send(bytes.copyOfRange(position, end)); active(); position = end
        }
    }
    private suspend fun readFrame(maximum: Int): ByteArray? {
        val header = exact(4, true) ?: return null
        val length = header.fold(0L) { value, byte -> (value shl 8) or (byte.toLong() and 255) }
        require(length in 1..maximum.toLong())
        return exact(length.toInt(), false)
    }
    private suspend fun exact(size: Int, allowEOF: Boolean): ByteArray? {
        val result = ByteArray(size)
        var position = 0
        while (position < size) {
            active()
            if (offset == pending.size) {
                val next = stream.receive(); active()
                if (next == null) {
                    if (allowEOF && position == 0) return null
                    throw IOException("Truncated frame")
                }
                require(next.size in 1..32_768)
                pending = next; offset = 0
            }
            val count = minOf(size - position, pending.size - offset)
            pending.copyInto(result, position, offset, offset + count)
            position += count; offset += count
        }
        return result
    }
    private suspend fun active() { kotlin.coroutines.coroutineContext.ensureActive(); check(!closed.get()) }
    private suspend fun <T> operation(block: suspend () -> T): T = try { active(); block() }
        catch (cancelled: CancellationException) { close(); throw cancelled }
        catch (_: Exception) { close(); throw IOException("Approval channel closed") }

    companion object {
        /** Takes exclusive ownership of the session, including on negotiation failure. The caller already verified enrollment pins. */
        suspend fun connect(session: TLSRecordSession, scope: ChannelScope, requests: List<ChannelRequestCapability>, auditVersions: Set<ULong>,
                            maximumPayloadBytes: Int, trustedMinimum: ULong = 1u, timeoutMillis: Long = 15_000,
                            purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.APPROVALS): NegotiatedTLSChannel =
            connect(TLSApprovalStream(session), scope, requests, auditVersions, maximumPayloadBytes, trustedMinimum, timeoutMillis, purpose)

        internal suspend fun connect(stream: ApprovalByteStream, scope: ChannelScope, requests: List<ChannelRequestCapability>, auditVersions: Set<ULong>,
                                     maximumPayloadBytes: Int, trustedMinimum: ULong = 1u, timeoutMillis: Long = 15_000,
                            purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.APPROVALS): NegotiatedTLSChannel {
            val owner = NegotiatedTLSChannel(stream, maximumPayloadBytes, purpose)
            owner.negotiate(scope, requests, auditVersions, trustedMinimum, timeoutMillis)
            return owner
        }
    }
}
