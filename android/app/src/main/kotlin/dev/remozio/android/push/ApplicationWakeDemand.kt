package dev.remozio.android.push

import dev.remozio.phone.push.WakeDemandTicket
import dev.remozio.protocol.CborValue
import java.util.UUID

internal interface WakeDemandStore : AutoCloseable {
    fun selectGeneration(generation: UUID)
    fun mark(generation: UUID, tag: ByteArray): WakeDemandTicket
    fun pending(generation: UUID): List<WakeDemandTicket>
    fun complete(ticket: WakeDemandTicket): Boolean
}

/** Provider lock precedes this owner. An uncertain store is closed and reopened, never reset. */
internal class ApplicationWakeDemand(
    private val provider: PushClientOwner,
    private val open: () -> WakeDemandStore,
) : AutoCloseable {
    private var store: WakeDemandStore? = null
    private var closed = false

    fun admit(generation: UUID, tag: CborValue.Bytes, active: Set<CborValue.Bytes>) {
        require(tag in active)
        provider.withCurrent(generation) { access { journal ->
            prepare(journal, generation, active)
            journal.mark(generation, tag.copyBytes())
        } }
    }
    fun pending(generation: UUID, active: Set<CborValue.Bytes>): List<WakeDemandTicket> =
        provider.withCurrent(generation) { access { journal ->
            prepare(journal, generation, active)
            journal.pending(generation)
        } } ?: emptyList()

    /** The caller also holds enrollmentAccess and verifies the same enrollment incarnation. */
    fun complete(ticket: WakeDemandTicket): Boolean = provider.withCurrent(ticket.generation) {
        access { it.complete(ticket) }
    } ?: false

    private fun prepare(journal: WakeDemandStore, generation: UUID, active: Set<CborValue.Bytes>) {
        journal.selectGeneration(generation)
        journal.pending(generation).filter { it.tag !in active }.forEach { check(journal.complete(it)) }
    }
    @Synchronized private fun <T> access(body: (WakeDemandStore) -> T): T {
        check(!closed)
        try { return body(store ?: open().also { store = it }) }
        catch (failure: Exception) {
            val failed = store; store = null
            try { failed?.close() } catch (closing: Exception) { failure.addSuppressed(closing) }
            throw failure
        }
    }
    @Synchronized override fun close() {
        if (!closed) { closed = true; val old = store; store = null; old?.close() }
    }
}
