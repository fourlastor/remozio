package dev.remozio.phone.requests

import dev.remozio.phone.transport.NegotiatedTLSChannel
import dev.remozio.protocol.*
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal interface RequestMessageChannel : AutoCloseable {
    val scope: ChannelScope
    val commandSchemas: Set<ULong>
    val maximumPayloadBytes: Int
    suspend fun receive(): ByteArray?
    suspend fun send(bytes: ByteArray) { throw IOException("Sending is unsupported") }
}
private class NegotiatedRequestChannel(private val channel: NegotiatedTLSChannel) : RequestMessageChannel {
    override val scope get() = channel.negotiated.peer.scope
    override val maximumPayloadBytes get() = channel.maximumPayloadBytes
    override val commandSchemas: Set<ULong> get() = commandChannelSchemas(
        channel.localRequests, channel.localAuditVersions, channel.negotiated.peer.role, channel.negotiated.peer.requests)
    override suspend fun receive() = channel.receive()
    override suspend fun send(bytes: ByteArray) = channel.send(bytes)
    override fun close() = channel.close()
}

/** Only implemented local contracts can be advertised. Unknown peer contracts do not enable a handler. */
internal fun commandChannelSchemas(local: List<ChannelRequestCapability>, localAuditVersions: Set<ULong>,
                                  peerRole: ChannelRole, peer: List<ChannelRequestCapability>): Set<ULong> {
    fun ChannelRequestCapability.known() = kind == 0uL && wireVersion == 1uL &&
        schemaVersion in CommandCapturePayload.supportedSchemaVersions
    require(peerRole == ChannelRole.MAC && localAuditVersions.isEmpty() && local.all { it.known() && it.features.isEmpty() })
    val shared = local.map { it.schemaVersion }.toSet().intersect(peer.filter { it.known() }.map { it.schemaVersion }.toSet())
    require(shared.isNotEmpty())
    return shared
}

/** Delivers authenticated captures and statuses. It grants no freshness, reachability, or action authority. */
class CommandRequestReceiver private constructor(
    private val enrollment: CommandRequestEnrollment,
    private val channel: RequestMessageChannel,
    private val maximumBodyBytes: Int,
    private val commandSchemas: Set<ULong>,
    private val queryRetainedOnStart: Boolean,
    private val clock: () -> ElapsedInstant,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private val writing = Mutex()
    @Volatile internal var capacityOmitted = false
        private set

    /** Run once in the host's connection scope. EOF leaves retained request owners intact. */
    suspend fun run() {
        check(started.compareAndSet(false, true))
        try {
            val retained = if (queryRetainedOnStart) enrollment.sessions().map { it.identity.requestID.copyBytes() } else emptyList()
            coroutineScope {
                val queries = launch {
                    for (id in retained) send(RequestStatusQuery(id).encode())
                }
                try {
                    while (!closed.get()) {
                        kotlin.coroutines.coroutineContext.ensureActive()
                        val bytes = channel.receive() ?: return@coroutineScope
                        kotlin.coroutines.coroutineContext.ensureActive()
                        if (closed.get()) return@coroutineScope
                        val message = ApprovalMessage.decode(bytes, maximumBodyBytes)
                        require(message.type != ApprovalMessageType.DECISION)
                        capacityOmitted = enrollment.deliver(this@CommandRequestReceiver, message, clock(), commandSchemas) || capacityOmitted
                    }
                } finally { queries.cancelAndJoin() }
            }
        } catch (cancelled: CancellationException) {
            kotlin.coroutines.coroutineContext.ensureActive()
            if (!closed.get()) throw cancelled
        } catch (_: Exception) { if (!closed.get()) throw IOException("Request delivery stopped") }
        finally { close() }
    }

    /** Shares the writer with reconnect queries. This does not retry or authenticate a decision. */
    suspend fun sendDecision(bytes: ByteArray) {
        require(ApprovalMessage.decode(bytes, maximumBodyBytes).type == ApprovalMessageType.DECISION)
        send(bytes)
    }

    private suspend fun send(bytes: ByteArray) = writing.withLock {
        kotlin.coroutines.coroutineContext.ensureActive()
        check(!closed.get())
        channel.send(bytes)
        kotlin.coroutines.coroutineContext.ensureActive()
        check(!closed.get())
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { channel.close() } finally { enrollment.detach(this) }
        }
    }

    companion object {
        /** The phone ID and epoch come from trusted enrollment. Ownership transfers even if binding fails. */
        fun bind(enrollment: CommandRequestEnrollment, channel: NegotiatedTLSChannel,
                 phoneID: ByteArray, enrollmentEpoch: ByteArray, queryRetainedOnStart: Boolean = true,
                 clock: () -> ElapsedInstant): CommandRequestReceiver =
            bind(enrollment, NegotiatedRequestChannel(channel), phoneID, enrollmentEpoch, queryRetainedOnStart, clock = clock)

        internal fun bind(enrollment: CommandRequestEnrollment, channel: RequestMessageChannel,
                          phoneID: ByteArray, enrollmentEpoch: ByteArray, queryRetainedOnStart: Boolean = false,
                          replaceExisting: Boolean = true, clock: () -> ElapsedInstant): CommandRequestReceiver {
            try {
                val expected = ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(), phoneID, enrollmentEpoch)
                require(channel.scope == expected)
                val schemas = channel.commandSchemas.toSet()
                require(schemas.isNotEmpty() && CommandCapturePayload.supportedSchemaVersions.containsAll(schemas))
                val maximum = maxOf(enrollment.limits.body.maxBytes, enrollment.limits.status.maxBytes)
                require(maximum in 1..(16_777_216 - ApprovalMessage.OVERHEAD_BYTES))
                require(channel.maximumPayloadBytes >= maximum + ApprovalMessage.OVERHEAD_BYTES)
                val receiver = CommandRequestReceiver(enrollment, channel, maximum, schemas, queryRetainedOnStart, clock)
                if (replaceExisting) enrollment.attach(receiver)
                else if (!enrollment.attachIfIdle(receiver)) throw IOException("Request receiver already active")
                return receiver
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}
