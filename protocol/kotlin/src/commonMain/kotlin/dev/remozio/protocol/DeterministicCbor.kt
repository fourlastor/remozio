package dev.remozio.protocol

sealed interface CborValue {
    data class Unsigned(val value: ULong) : CborValue
    data class Text(val value: String) : CborValue
    data class BooleanValue(val value: Boolean) : CborValue
    data object Null : CborValue

    class Bytes(value: ByteArray) : CborValue {
        private val storage = value.copyOf()
        val size: Int get() = storage.size
        fun copyBytes(): ByteArray = storage.copyOf()
        override fun equals(other: Any?): Boolean = other is Bytes && storage.contentEquals(other.storage)
        override fun hashCode(): Int = storage.contentHashCode()
    }

    class ArrayValue(values: List<CborValue>) : CborValue {
        val values: List<CborValue> = readOnlySnapshot(values)
        override fun equals(other: Any?): Boolean = other is ArrayValue && values == other.values
        override fun hashCode(): Int = values.hashCode()
    }

    class Fields(values: Map<ULong, CborValue>) : CborValue {
        val values: Map<ULong, CborValue> = readOnlySnapshot(values)
        override fun equals(other: Any?): Boolean = other is Fields && values == other.values
        override fun hashCode(): Int = values.hashCode()
    }
}

data class CborLimits(val maxBytes: Int, val maxDepth: Int, val maxItems: Int) {
    init {
        if (maxBytes <= 0 || maxDepth !in 0..64 || maxItems <= 0) throw CborException(CborFailure.INVALID_LIMITS)
    }
}

enum class CborFailure {
    INVALID_LIMITS, BYTE_LIMIT, DEPTH_LIMIT, ITEM_LIMIT, TRUNCATED,
    NON_CANONICAL, UNSUPPORTED_TYPE, INVALID_TEXT, TRAILING_BYTES,
}

class CborException(val reason: CborFailure) : IllegalArgumentException(reason.name)

/** Deterministic encoding only. Successful parsing does not authenticate a message. */
object DeterministicCbor {
    fun encode(value: CborValue, limits: CborLimits): ByteArray = Writer(limits).run {
        write(value, 0)
        output.toByteArray()
    }

    /** Growable output; the writer checks every length against its limits before appending. */
    private class ByteBuffer {
        private var bytes = ByteArray(64)
        private var count = 0
        fun size(): Int = count
        fun append(value: Int) {
            reserve(1)
            bytes[count++] = value.toByte()
        }
        fun append(value: ByteArray) {
            reserve(value.size)
            value.copyInto(bytes, count)
            count += value.size
        }
        fun toByteArray(): ByteArray = bytes.copyOf(count)
        private fun reserve(extra: Int) {
            if (count + extra > bytes.size) bytes = bytes.copyOf(maxOf(bytes.size * 2, count + extra))
        }
    }

    fun decode(bytes: ByteArray, limits: CborLimits): CborValue {
        ensure(bytes.size <= limits.maxBytes, CborFailure.BYTE_LIMIT)
        return Reader(bytes.copyOf(), limits).run {
            val result = read(0)
            ensure(offset == input.size, CborFailure.TRAILING_BYTES)
            result
        }
    }

    private fun ensure(condition: Boolean, failure: CborFailure) {
        if (!condition) throw CborException(failure)
    }

    private class Writer(val limits: CborLimits) {
        val output = ByteBuffer()
        var items = 0

        fun byte(value: Int) {
            ensure(output.size() < limits.maxBytes, CborFailure.BYTE_LIMIT)
            output.append(value)
        }

        fun argument(value: ULong, major: Int) {
            if (value < 24uL) {
                byte(major shl 5 or value.toInt())
                return
            }
            val (width, additional) = when {
                value <= 0xffuL -> 1 to 24
                value <= 0xffffuL -> 2 to 25
                value <= 0xffff_ffffuL -> 4 to 26
                else -> 8 to 27
            }
            byte(major shl 5 or additional)
            for (shift in (width - 1) * 8 downTo 0 step 8) byte((value shr shift).toInt() and 255)
        }

        fun write(value: CborValue, depth: Int) {
            ensure(depth <= limits.maxDepth, CborFailure.DEPTH_LIMIT)
            ensure(items < limits.maxItems, CborFailure.ITEM_LIMIT)
            items++
            when (value) {
                is CborValue.Unsigned -> argument(value.value, 0)
                is CborValue.Bytes -> {
                    argument(value.size.toULong(), 2)
                    ensure(value.size <= limits.maxBytes - output.size(), CborFailure.BYTE_LIMIT)
                    output.append(value.copyBytes())
                }
                is CborValue.Text -> {
                    // Count and validate before allocating the encoded text.
                    val count = utf8Length(value.value)
                    argument(count.toULong(), 3)
                    ensure(count <= limits.maxBytes - output.size(), CborFailure.BYTE_LIMIT)
                    output.append(value.value.encodeToByteArray(throwOnInvalidSequence = true))
                }
                is CborValue.ArrayValue -> {
                    ensure(value.values.size <= limits.maxItems - items, CborFailure.ITEM_LIMIT)
                    argument(value.values.size.toULong(), 4)
                    value.values.forEach { write(it, depth + 1) }
                }
                is CborValue.Fields -> {
                    ensure(value.values.size <= (limits.maxItems - items) / 2, CborFailure.ITEM_LIMIT)
                    argument(value.values.size.toULong(), 5)
                    value.values.keys.sorted().forEach { key ->
                        write(CborValue.Unsigned(key), depth + 1)
                        write(value.values.getValue(key), depth + 1)
                    }
                }
                is CborValue.BooleanValue -> byte(if (value.value) 0xf5 else 0xf4)
                CborValue.Null -> byte(0xf6)
            }
        }

        fun utf8Length(text: String): Int {
            var count = 0
            var index = 0
            while (index < text.length) {
                val char = text[index++]
                val width = when {
                    char.code < 0x80 -> 1
                    char.code < 0x800 -> 2
                    char.isHighSurrogate() -> {
                        ensure(index < text.length && text[index].isLowSurrogate(), CborFailure.INVALID_TEXT)
                        index++
                        4
                    }
                    char.isLowSurrogate() -> throw CborException(CborFailure.INVALID_TEXT)
                    else -> 3
                }
                ensure(width <= limits.maxBytes - count, CborFailure.BYTE_LIMIT)
                count += width
            }
            return count
        }
    }

    private class Reader(val input: ByteArray, val limits: CborLimits) {
        var offset = 0
        var items = 0

        fun byte(): Int {
            ensure(offset < input.size, CborFailure.TRUNCATED)
            return input[offset++].toInt() and 255
        }

        fun argument(additional: Int): ULong {
            if (additional < 24) return additional.toULong()
            val (width, minimum) = when (additional) {
                24 -> 1 to 24uL
                25 -> 2 to 0x100uL
                26 -> 4 to 0x1_0000uL
                27 -> 8 to 0x1_0000_0000uL
                else -> throw CborException(CborFailure.UNSUPPORTED_TYPE)
            }
            var value = 0uL
            repeat(width) { value = (value shl 8) or byte().toULong() }
            ensure(value >= minimum, CborFailure.NON_CANONICAL)
            return value
        }

        fun read(depth: Int): CborValue {
            ensure(depth <= limits.maxDepth, CborFailure.DEPTH_LIMIT)
            ensure(items < limits.maxItems, CborFailure.ITEM_LIMIT)
            items++
            val head = byte()
            val major = head shr 5
            if (major == 7) return when (head) {
                0xf4 -> CborValue.BooleanValue(false)
                0xf5 -> CborValue.BooleanValue(true)
                0xf6 -> CborValue.Null
                else -> throw CborException(CborFailure.UNSUPPORTED_TYPE)
            }
            ensure(major == 0 || major in 2..5, CborFailure.UNSUPPORTED_TYPE)
            val value = argument(head and 31)
            if (major == 0) return CborValue.Unsigned(value)
            ensure(value <= (input.size - offset).toULong(), CborFailure.TRUNCATED)
            val count = value.toInt()
            return when (major) {
                2, 3 -> {
                    val start = offset
                    offset += count
                    if (major == 2) CborValue.Bytes(input.copyOfRange(start, offset))
                    else try {
                        CborValue.Text(input.decodeToString(start, offset, throwOnInvalidSequence = true))
                    } catch (_: CharacterCodingException) {
                        throw CborException(CborFailure.INVALID_TEXT)
                    }
                }
                4 -> {
                    ensure(count <= limits.maxItems - items, CborFailure.ITEM_LIMIT)
                    val values = ArrayList<CborValue>()
                    repeat(count) { values.add(read(depth + 1)) }
                    CborValue.ArrayValue(values)
                }
                5 -> {
                    ensure(count <= (limits.maxItems - items) / 2, CborFailure.ITEM_LIMIT)
                    val values = LinkedHashMap<ULong, CborValue>()
                    var previous: ULong? = null
                    repeat(count) {
                        val key = (read(depth + 1) as? CborValue.Unsigned)?.value
                            ?: throw CborException(CborFailure.UNSUPPORTED_TYPE)
                        ensure(previous == null || key > previous, CborFailure.NON_CANONICAL)
                        previous = key
                        values[key] = read(depth + 1)
                    }
                    CborValue.Fields(values)
                }
                else -> throw CborException(CborFailure.UNSUPPORTED_TYPE)
            }
        }
    }
}
