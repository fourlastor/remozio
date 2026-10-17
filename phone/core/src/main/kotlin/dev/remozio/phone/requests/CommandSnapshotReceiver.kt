package dev.remozio.phone.requests

import dev.remozio.phone.transport.EnrolledChannelPurpose
import dev.remozio.phone.transport.NegotiatedTLSChannel
import dev.remozio.protocol.*
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

/** Bounded read-only delivery. The host rechecks its enrollment and wake reservation around every await. */
class CommandSnapshotReceiver private constructor(
    private val receiver: CommandRequestReceiver,
    private val snapshot: PendingSnapshotMessageChannel,
) : AutoCloseable {
    /** Keeps individually verified updates. Early close, preemption and capacity loss cannot complete the fetch. */
    suspend fun run() {
        receiver.run()
        coroutineContext.ensureActive()
        snapshot.requireComplete()
        if (receiver.capacityOmitted) throw IOException("Snapshot exceeded request capacity")
    }
    override fun close() = receiver.close()
    override fun toString() = "CommandSnapshotReceiver(redacted)"

    companion object {
        /** Reserve signed frames, snapshot wrapping and the largest retained-ID query when creating the connector. */
        fun requiredChannelPayloadBytes(limits: RequestLimits): Int {
            val body = maxOf(limits.body.maxBytes, limits.status.maxBytes)
            require(body in 1..(PendingRequestSnapshotFrame.MAXIMUM_FRAME_BYTES - ApprovalMessage.OVERHEAD_BYTES))
            val signedFrames = body + ApprovalMessage.OVERHEAD_BYTES +
                (PendingRequestSnapshotFrame.MAXIMUM_BYTES - PendingRequestSnapshotFrame.MAXIMUM_FRAME_BYTES)
            // Each retained ID uses 17 CBOR bytes. The remaining fixed query fields fit within 256 bytes.
            val retainedQuery = PendingRequestSnapshotFrame.MAXIMUM_RETAINED_REQUESTS * 17 + 256
            return maxOf(signedFrames, retainedQuery)
        }

        /** Takes channel ownership. Background binding refuses an active receiver without closing that receiver. */
        fun bind(enrollment: CommandRequestEnrollment, channel: NegotiatedTLSChannel, phoneID: ByteArray,
                 enrollmentEpoch: ByteArray, maximumFrames: ULong, maximumBytes: ULong,
                 clock: () -> ElapsedInstant): CommandSnapshotReceiver {
            try { require(channel.purpose == EnrolledChannelPurpose.PENDING_SNAPSHOT) }
            catch (failure: Exception) { channel.close(); throw failure }
            return bind(enrollment, SnapshotNegotiatedRequestChannel(channel), phoneID, enrollmentEpoch,
                maximumFrames, maximumBytes, clock)
        }
        internal fun bind(enrollment: CommandRequestEnrollment, channel: RequestMessageChannel, phoneID: ByteArray,
                          enrollmentEpoch: ByteArray, maximumFrames: ULong, maximumBytes: ULong,
                          clock: () -> ElapsedInstant): CommandSnapshotReceiver {
            val query = try {
                val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
                PendingRequestSnapshotFrame.Query(nonce, maximumFrames, maximumBytes,
                    enrollment.sessions().map { it.identity.requestID.copyBytes() })
            } catch (failure: Exception) { channel.close(); throw failure }
            val snapshot = PendingSnapshotMessageChannel(channel, query)
            val receiver = CommandRequestReceiver.bind(enrollment, snapshot, phoneID, enrollmentEpoch,
                queryRetainedOnStart = false, replaceExisting = false, clock = clock)
            return CommandSnapshotReceiver(receiver, snapshot)
        }
    }
}

private class SnapshotNegotiatedRequestChannel(private val channel: NegotiatedTLSChannel) : RequestMessageChannel {
    override val scope get() = channel.negotiated.peer.scope
    override val maximumPayloadBytes get() = channel.maximumPayloadBytes
    override val commandSchemas get() = commandChannelSchemas(channel.localRequests, channel.localAuditVersions,
        channel.negotiated.peer.role, channel.negotiated.peer.requests)
    override suspend fun receive() = channel.receive()
    override suspend fun send(bytes: ByteArray) = channel.send(bytes)
    override fun close() = channel.close()
}

/** Framing only. The ordinary request receiver verifies each returned Root-signed frame. */
internal class PendingSnapshotMessageChannel(
    private val channel: RequestMessageChannel,
    private val query: PendingRequestSnapshotFrame.Query,
) : RequestMessageChannel {
    private val progress = PendingRequestSnapshotProgress(query)
    private val started = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    override val scope get() = channel.scope
    override val commandSchemas get() = channel.commandSchemas
    override val maximumPayloadBytes get() = minOf(channel.maximumPayloadBytes - (PendingRequestSnapshotFrame.MAXIMUM_BYTES - PendingRequestSnapshotFrame.MAXIMUM_FRAME_BYTES), PendingRequestSnapshotFrame.MAXIMUM_FRAME_BYTES)
    override suspend fun receive(): ByteArray? {
        coroutineContext.ensureActive()
        if (closed.get()) throw IOException("Snapshot channel closed")
        if (started.compareAndSet(false, true)) {
            val bytes = query.encode()
            require(bytes.size <= channel.maximumPayloadBytes)
            channel.send(bytes)
            coroutineContext.ensureActive()
            if (closed.get()) throw IOException("Snapshot channel closed")
        }
        if (progress.isComplete) return null
        val bytes = channel.receive() ?: throw IOException("Snapshot completion missing")
        coroutineContext.ensureActive()
        if (closed.get()) throw IOException("Snapshot channel closed")
        return progress.accept(bytes)
    }
    fun requireComplete() {
        try { progress.requireComplete() } catch (_: Exception) { throw IOException("Snapshot incomplete") }
    }
    override fun close() { if (closed.compareAndSet(false, true)) channel.close() }
}
