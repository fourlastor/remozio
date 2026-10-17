package dev.remozio.protocol

import java.util.Collections

/** Bounded discovery over enrolled TLS. Completion gives no request outcome or decision authority. */
sealed class PendingRequestSnapshotFrame(nonce: ByteArray) {
    val nonce = CborValue.Bytes(nonce)
    init { require(this.nonce.size == 32) }
    class Query(nonce: ByteArray, val maximumFrames: ULong, val maximumBytes: ULong,
                retainedRequestIDs: List<ByteArray> = emptyList()) : PendingRequestSnapshotFrame(nonce) {
        init { require(retainedRequestIDs.size <= MAXIMUM_RETAINED_REQUESTS && retainedRequestIDs.all { it.size == 16 }) }
        val retainedRequestIDs: List<CborValue.Bytes> = Collections.unmodifiableList(retainedRequestIDs.map(CborValue::Bytes).sortedWith { a, b ->
            val left = a.copyBytes(); val right = b.copyBytes()
            var result = left.size.compareTo(right.size)
            if (result == 0) for (i in left.indices) {
                result = (left[i].toInt() and 255).compareTo(right[i].toInt() and 255)
                if (result != 0) break
            }
            result
        })
        init {
            require(maximumFrames in 1uL..MAXIMUM_FRAMES && maximumBytes in 1uL..MAXIMUM_SNAPSHOT_BYTES)
            require(this.retainedRequestIDs.size <= MAXIMUM_RETAINED_REQUESTS && this.retainedRequestIDs.all { it.size == 16 } &&
                this.retainedRequestIDs.toSet().size == this.retainedRequestIDs.size)
        }
    }
    class Item(nonce: ByteArray, val ordinal: ULong, frame: ByteArray) : PendingRequestSnapshotFrame(nonce) {
        val frame = CborValue.Bytes(frame)
        init { require(ordinal < MAXIMUM_FRAMES && this.frame.size in 1..MAXIMUM_FRAME_BYTES) }
    }
    class Complete(nonce: ByteArray, val frames: ULong, val bytes: ULong) : PendingRequestSnapshotFrame(nonce) {
        init { require(frames <= MAXIMUM_FRAMES && bytes <= MAXIMUM_SNAPSHOT_BYTES && (frames == 0uL) == (bytes == 0uL) && bytes >= frames) }
    }
    fun encode(): ByteArray {
        val (kind, a, b) = when (this) {
            is Query -> Triple(0uL, maximumFrames, CborValue.Unsigned(maximumBytes))
            is Item -> Triple(1uL, ordinal, frame)
            is Complete -> Triple(2uL, frames, CborValue.Unsigned(bytes))
        }
        val fields = mutableMapOf<ULong, CborValue>(
            0uL to CborValue.Text("dev.remozio.pending.snapshot"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(kind), 3uL to nonce, 4uL to CborValue.Unsigned(a), 5uL to b,
        )
        if (this is Query) fields[6u] = CborValue.ArrayValue(retainedRequestIDs)
        return DeterministicCbor.encode(CborValue.Fields(fields), LIMITS)
    }
    final override fun toString() = "PendingRequestSnapshotFrame(redacted)"
    companion object {
        const val APPLICATION_PROTOCOL = "remozio-pending/1"
        const val MAXIMUM_FRAMES: ULong = 4096u
        const val MAXIMUM_RETAINED_REQUESTS = 4096
        const val MAXIMUM_SNAPSHOT_BYTES: ULong = 67_108_864u
        const val MAXIMUM_FRAME_BYTES = 16_777_088
        const val MAXIMUM_BYTES = MAXIMUM_FRAME_BYTES + 128
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 2, MAXIMUM_RETAINED_REQUESTS + 15)
        fun decode(bytes: ByteArray): PendingRequestSnapshotFrame {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: error("Invalid pending snapshot frame")
            require(fields[0u] == CborValue.Text("dev.remozio.pending.snapshot") &&
                fields[1u] == CborValue.Unsigned(1u))
            val kind = (fields[2u] as? CborValue.Unsigned)?.value ?: error("Invalid pending snapshot frame")
            require(fields.keys == (0uL..(if (kind == 0uL) 6uL else 5uL)).toSet())
            val nonce = (fields[3u] as? CborValue.Bytes)?.copyBytes() ?: error("Invalid pending snapshot frame")
            val a = (fields[4u] as? CborValue.Unsigned)?.value ?: error("Invalid pending snapshot frame")
            val b = fields.getValue(5u)
            val result = when {
                kind == 0uL && b is CborValue.Unsigned -> {
                    val ids = (fields[6u] as? CborValue.ArrayValue)?.values ?: error("Invalid retained request list")
                    Query(nonce, a, b.value, ids.map { (it as? CborValue.Bytes)?.copyBytes() ?: error("Invalid retained request") })
                }
                kind == 1uL && b is CborValue.Bytes -> Item(nonce, a, b.copyBytes())
                kind == 2uL && b is CborValue.Unsigned -> Complete(nonce, a, b.value)
                else -> error("Invalid pending snapshot frame")
            }
            require(result.encode().contentEquals(bytes))
            return result
        }
    }
}
