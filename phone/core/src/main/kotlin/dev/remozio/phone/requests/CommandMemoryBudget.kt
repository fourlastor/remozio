package dev.remozio.phone.requests

/** Shared across all enrolled host connections. Bounds retained capture bytes and parsed collection elements. */
class CommandMemoryBudget(private val maximumBytes: Long, private val maximumItems: Long) {
    private val parsing = Any()
    private var bytes = 0L
    private var items = 0L
    init { require(maximumBytes > 0 && maximumItems > 0) }

    // Parsing has a separate monitor: releasing a session never waits for the parsing monitor.
    internal fun <T> parse(operation: () -> T): T = synchronized(parsing) { operation() }

    @Synchronized internal fun retain(captureBytes: Long, captureItems: Long, replacing: Reservation? = null, beforeCommit: () -> Unit = {}): Reservation {
        require(captureBytes >= 0 && captureItems >= 0)
        replacing?.let { require(it.owner === this && !it.closed && it.captureBytes == 0L && it.captureItems == 0L) }
        val creditBytes = if (replacing == null) 0L else METADATA_BYTES
        val creditItems = if (replacing == null) 0L else METADATA_ITEMS
        if (captureBytes > maximumBytes - bytes - METADATA_BYTES + creditBytes || captureItems > maximumItems - items - METADATA_ITEMS + creditItems)
            throw InboxException(InboxRejection.CAPACITY)
        beforeCommit()
        replacing?.close()
        bytes += captureBytes + METADATA_BYTES
        items += captureItems + METADATA_ITEMS
        return Reservation(captureBytes, captureItems)
    }

    inner class Reservation internal constructor(internal var captureBytes: Long, internal var captureItems: Long) : AutoCloseable {
        internal val owner get() = this@CommandMemoryBudget
        internal var closed = false
        internal fun releaseCapture() = synchronized(this@CommandMemoryBudget) {
            if (!closed) {
                bytes -= captureBytes; items -= captureItems
                captureBytes = 0; captureItems = 0
            }
        }
        override fun close() = synchronized(this@CommandMemoryBudget) {
            if (!closed) {
                releaseCapture(); closed = true
                bytes -= METADATA_BYTES; items -= METADATA_ITEMS
            }
        }
    }
    private companion object { const val METADATA_BYTES = 1024L; const val METADATA_ITEMS = 64L }
}
