package dev.remozio.phone.push

import dev.remozio.protocol.*
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID

/** One application owner supplies bounded reads and atomic replacement in private storage excluded from backups. */
interface WakeDemandStorage {
    fun read(maximumBytes: Int): ByteArray?
    fun replace(bytes: ByteArray)
}

/** Opaque scheduling state. It contains no route, request content, authority key or decision. */
class WakeDemandTicket internal constructor(val generation: UUID, tag: ByteArray, revision: ByteArray) {
    val tag = CborValue.Bytes(tag)
    /** Opaque scheduling identity. It grants no authority. */
    val revision = CborValue.Bytes(revision)
    override fun toString() = "WakeDemandTicket(redacted)"
}

/** Durable hint demand only. Call generation selection under the current provider's configuration lock. */
class PendingWakeDemand(
    private val storage: WakeDemandStorage,
    private val maximumEntries: Int,
    private val revision: () -> ByteArray = { ByteArray(32).also { SecureRandom().nextBytes(it) } },
) {
    private var unavailable = false
    private var generation: UUID? = null
    private var entries = linkedMapOf<CborValue.Bytes, CborValue.Bytes>()

    init {
        require(maximumEntries in 1..1024)
        storage.read(MAXIMUM_BYTES)?.let { bytes ->
            require(bytes.size <= MAXIMUM_BYTES)
            val root = (DeterministicCbor.decode(bytes, LIMITS) as CborValue.Fields).values
            require(root.keys == setOf(0uL, 1uL, 2uL, 3uL))
            require(root[0u] == CborValue.Text(DOMAIN) && root[1u] == CborValue.Unsigned(1u))
            val selected = (root[2u] as CborValue.Bytes).copyBytes(); require(selected.size == 16)
            val buffer = ByteBuffer.wrap(selected); generation = UUID(buffer.long, buffer.long)
            val rows = (root[3u] as CborValue.ArrayValue).values; require(rows.size <= maximumEntries)
            for (row in rows) {
                val pair = (row as CborValue.ArrayValue).values; require(pair.size == 2)
                val tag = pair[0] as CborValue.Bytes; val stamp = pair[1] as CborValue.Bytes
                require(tag.copyBytes().size == 32 && stamp.copyBytes().size == 32)
                require(entries.put(tag, stamp) == null)
            }
        }
    }

    /** Trusted configuration selects a generation. An old worker must never select its own saved generation. */
    @Synchronized fun selectGeneration(selected: UUID) {
        check(!unavailable)
        if (generation == selected) return
        persist(selected, linkedMapOf())
    }

    /** Mark before scheduling work. Existing tags coalesce, including when the bounded index is full. */
    @Synchronized fun mark(selected: UUID, tag: ByteArray): WakeDemandTicket {
        check(!unavailable)
        check(generation == selected)
        require(tag.size == 32)
        val key = CborValue.Bytes(tag)
        check(key in entries || entries.size < maximumEntries)
        val next = revision(); require(next.size == 32)
        val stamp = CborValue.Bytes(next); check(entries[key] != stamp)
        val updated = LinkedHashMap(entries); updated[key] = stamp
        persist(selected, updated)
        return WakeDemandTicket(selected, tag, next)
    }

    @Synchronized fun pending(selected: UUID): List<WakeDemandTicket> {
        check(!unavailable)
        if (generation != selected) return emptyList()
        return entries.map { (tag, stamp) -> WakeDemandTicket(selected, tag.copyBytes(), stamp.copyBytes()) }
    }

    /** Clear only the exact completed demand. A wake that arrives during a fetch remains pending. */
    @Synchronized fun complete(ticket: WakeDemandTicket): Boolean {
        check(!unavailable)
        if (generation != ticket.generation || entries[ticket.tag] != ticket.revision) return false
        val updated = LinkedHashMap(entries); updated.remove(ticket.tag)
        persist(ticket.generation, updated)
        return true
    }

    private fun persist(selected: UUID, updated: LinkedHashMap<CborValue.Bytes, CborValue.Bytes>) {
        val id = ByteBuffer.allocate(16).putLong(selected.mostSignificantBits).putLong(selected.leastSignificantBits).array()
        val rows = updated.map { (tag, stamp) -> CborValue.ArrayValue(listOf(tag, stamp)) }
        val bytes = DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN),
            1uL to CborValue.Unsigned(1u), 2uL to CborValue.Bytes(id), 3uL to CborValue.ArrayValue(rows))), LIMITS)
        try { storage.replace(bytes) } catch (failure: Exception) { unavailable = true; throw failure }
        generation = selected; entries = updated
    }

    companion object {
        private const val DOMAIN = "dev.remozio.push.pending"
        private const val MAXIMUM_BYTES = 262_144
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 4, 8192)
    }
}
