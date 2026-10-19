package dev.remozio.protocol

/** Transfer bookkeeping only. Verify every returned frame before using its request or status claims. */
class PendingRequestSnapshotProgress(query: PendingRequestSnapshotFrame.Query) {
    private val nonce = query.nonce
    private val maximumFrames = query.maximumFrames
    private val maximumBytes = query.maximumBytes
    private var frames = 0uL
    private var bytes = 0uL
    private var failed = false
    private var completed = false
    val isComplete: Boolean @Synchronized get() = completed && !failed

    /** One channel owner consumes these values. Omitted requests never become expired or terminal here. */
    @Synchronized fun accept(encoded: ByteArray): ByteArray? {
        try {
            check(!failed && !completed)
            return when (val frame = PendingRequestSnapshotFrame.decode(encoded)) {
                is PendingRequestSnapshotFrame.Item -> {
                    require(frame.nonce == nonce && frame.ordinal == frames && frames < maximumFrames &&
                        frame.frame.size.toULong() <= maximumBytes - bytes)
                    frames++; bytes += frame.frame.size.toULong()
                    frame.frame.copyBytes()
                }
                is PendingRequestSnapshotFrame.Complete -> {
                    require(frame.nonce == nonce && frame.frames == frames && frame.bytes == bytes)
                    completed = true
                    null
                }
                is PendingRequestSnapshotFrame.Query -> error("Unexpected snapshot query")
            }
        } catch (failure: Exception) { failed = true; completed = false; throw failure }
    }
    /** EOF, cancellation and timeouts cannot complete a transfer without its exact marker. */
    @Synchronized fun requireComplete() {
        if (failed || !completed) { failed = true; error("Pending snapshot incomplete") }
    }
    override fun toString() = "PendingRequestSnapshotProgress(redacted)"
}
