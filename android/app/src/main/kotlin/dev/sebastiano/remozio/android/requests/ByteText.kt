package dev.sebastiano.remozio.android.requests

/** Display notation, not shell syntax. Invalid UTF-8 stays visible as individual byte escapes. */
internal object ByteText {
    fun quoted(bytes: ByteArray): String = buildString {
        append('"')
        var index = 0
        while (index < bytes.size) {
            val first = bytes[index].toInt() and 255
            val length = when (first) {
                in 0..0x7f -> 1
                in 0xc2..0xdf -> 2
                in 0xe0..0xef -> 3
                in 0xf0..0xf4 -> 4
                else -> 0
            }
            var codePoint = first and when (length) { 2 -> 0x1f; 3 -> 0x0f; 4 -> 0x07; else -> 0x7f }
            var valid = length > 0 && length <= bytes.size - index
            if (valid) {
                for (offset in 1 until length) {
                    val next = bytes[index + offset].toInt() and 255
                    if (next !in 0x80..0xbf) { valid = false; break }
                    codePoint = (codePoint shl 6) or (next and 0x3f)
                }
                val minimum = when (length) { 2 -> 0x80; 3 -> 0x800; 4 -> 0x10000; else -> 0 }
                valid = valid && codePoint >= minimum && codePoint <= 0x10ffff && codePoint !in 0xd800..0xdfff
            }
            if (!valid) {
                append("\\x").append(first.toString(16).padStart(2, '0'))
                index++
                continue
            }
            when (codePoint) {
                0x22 -> append("\\\"")
                0x5c -> append("\\\\")
                0x0a -> append("\\n")
                0x0d -> append("\\r")
                0x09 -> append("\\t")
                else -> {
                    val category = Character.getType(codePoint)
                    if (category in escapedCategories && codePoint != 0x20) {
                        append("\\u{").append(codePoint.toString(16)).append('}')
                    } else appendCodePoint(codePoint)
                }
            }
            index += length
        }
        append('"')
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString(" ") { (it.toInt() and 255).toString(16).padStart(2, '0') }

    private val escapedCategories = setOf(
        Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.LINE_SEPARATOR.toInt(),
        Character.PARAGRAPH_SEPARATOR.toInt(), Character.SPACE_SEPARATOR.toInt(), Character.UNASSIGNED.toInt(),
    )
}
