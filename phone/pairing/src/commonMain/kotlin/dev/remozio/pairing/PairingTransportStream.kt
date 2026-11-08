@file:OptIn(ExperimentalAtomicApi::class)

package dev.remozio.pairing

import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.select
import kotlinx.io.IOException

/**
 * Adapts a callback [PairingTransport] to [PairingByteStream]. Frame rules stay in [PairingSetupChannel]; this class
 * only splits each delivery into chunks the channel accepts (1 to 32,768 bytes) and holds at most one delivery.
 */
internal class PairingTransportStream(private val transport: PairingTransport) : PairingByteStream {
    private sealed interface Delivery {
        class Bytes(val value: ByteArray) : Delivery
        class End(val error: String?) : Delivery
    }

    private val started = AtomicBoolean(false)
    private val cancelled = AtomicBoolean(false)
    private val ended = AtomicBoolean(false)
    // True from requestBytes() until its one answer. A delivery nobody asked for ends the stream.
    private val outstanding = AtomicBoolean(false)
    private val reading = AtomicBoolean(false)
    private val opened = CompletableDeferred<Unit>()
    private val closed = CompletableDeferred<Unit>()
    private val deliveries = Channel<Delivery>(Channel.UNLIMITED)

    // Only receive() touches these. The channel runs one operation at a time.
    private val chunks = ArrayDeque<ByteArray>()
    private var end: Delivery.End? = null

    private val events = object : PairingTransportEvents {
        override fun opened() { if (!ended.load()) opened.complete(Unit) }
        override fun received(bytes: ByteArray) {
            if (ended.load()) return
            if (!outstanding.compareAndSet(true, false)) { close(); finish("Unrequested pairing delivery"); return }
            deliveries.trySend(Delivery.Bytes(bytes))
        }
        override fun closed(error: String?) = finish(error)
    }

    override suspend fun awaitOpen() {
        check(started.compareAndSet(false, true)) { "Pairing transport already started" }
        if (cancelled.load()) { finish("Pairing transport cancelled"); throw IOException("Pairing transport cancelled") }
        transport.start(events)
        try { opened.await() } catch (stopped: CancellationException) { close(); throw stopped }
    }

    override suspend fun receive(): ByteArray? {
        check(reading.compareAndSet(false, true)) { "Concurrent pairing receive" }
        try { return next() }
        catch (stopped: CancellationException) { close(); throw stopped }
        finally { reading.store(false) }
    }

    private suspend fun next(): ByteArray? {
        while (true) {
            chunks.removeFirstOrNull()?.let { return it }
            end?.let { done -> done.error?.let { throw IOException("Pairing transport failed: $it") }; return null }
            // An answer or a close already queued is taken first, so no read is requested after the end.
            val next = deliveries.tryReceive().getOrNull() ?: run {
                if (!ended.load() && outstanding.compareAndSet(false, true)) transport.requestBytes()
                deliveries.receive()
            }
            when (next) {
                is Delivery.Bytes -> {
                    val size = next.value.size
                    if (size !in 1..PairingTransport.MAXIMUM_DELIVERY) {
                        close(); throw IOException("Pairing transport delivery out of bounds")
                    }
                    var position = 0
                    while (position < size) {
                        val stop = minOf(position + CHUNK, size)
                        chunks.addLast(next.value.copyOfRange(position, stop)); position = stop
                    }
                }
                is Delivery.End -> end = next
            }
        }
    }

    override suspend fun send(bytes: ByteArray) {
        if (ended.load()) throw IOException("Pairing transport closed")
        val done = CompletableDeferred<Unit>()
        transport.send(bytes.copyOf()) { error ->
            if (error == null) done.complete(Unit) else done.completeExceptionally(IOException("Pairing send failed: $error"))
        }
        try {
            select {
                done.onAwait { }
                closed.onAwait { if (!done.isCompleted) throw IOException("Pairing transport closed") }
            }
            done.await()
        } catch (stopped: CancellationException) { close(); throw stopped }
    }

    override fun close() {
        if (!cancelled.compareAndSet(false, true)) return
        if (started.load()) transport.cancel() else finish("Pairing transport cancelled")
    }

    override suspend fun awaitClosed() { close(); closed.await() }

    override fun toString() = "PairingTransportStream(redacted)"

    private fun finish(error: String?) {
        if (!ended.compareAndSet(false, true)) return
        opened.completeExceptionally(IOException(
            if (error == null) "Pairing transport closed before it opened" else "Pairing transport failed: $error"))
        deliveries.trySend(Delivery.End(error))
        closed.complete(Unit)
    }

    private companion object { const val CHUNK = 32_768 }
}
