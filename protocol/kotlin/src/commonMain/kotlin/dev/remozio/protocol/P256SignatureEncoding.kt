package dev.remozio.protocol

class P256SignatureEncodingException : IllegalArgumentException("Invalid P-256 signature encoding")

/** Strict conversion between provider DER signatures and wire-format unsigned R || S. No hashing or signing. */
object P256SignatureEncoding {
    private val order = byteArrayOf(
        -1, -1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1,
        -68, -26, -6, -83, -89, 23, -98, -124, -13, -71, -54, -62, -4, 99, 37, 81,
    )

    fun toDer(rawSignature: ByteArray): ByteArray {
        if (rawSignature.size != 64) invalid()
        val raw = rawSignature.copyOf()
        val r = derInteger(scalar(raw.copyOfRange(0, 32)))
        val s = derInteger(scalar(raw.copyOfRange(32, 64)))
        return byteArrayOf(0x30, (4 + r.size + s.size).toByte(), 0x02, r.size.toByte()) +
            r + byteArrayOf(0x02, s.size.toByte()) + s
    }

    fun fromDer(derSignature: ByteArray): ByteArray {
        if (derSignature.size !in 8..72) invalid()
        val der = derSignature.copyOf()
        // A P-256 signature always fits in the short DER length form.
        if (der[0] != 0x30.toByte() || (der[1].toInt() and 255) != der.size - 2) invalid()
        var offset = 2
        fun integer(): ByteArray {
            if (offset + 2 > der.size || der[offset++] != 0x02.toByte()) invalid()
            val length = der[offset++].toInt() and 255
            if (length !in 1..33 || offset + length > der.size) invalid()
            val first = der[offset].toInt() and 255
            if (first and 128 != 0) invalid()
            if (length > 1 && first == 0 && (der[offset + 1].toInt() and 128) == 0) invalid()
            val value = der.copyOfRange(offset, offset + length)
            offset += length
            return scalar(value)
        }
        val raw = integer() + integer()
        if (offset != der.size) invalid()
        return raw
    }

    /** Returns the 32-byte big-endian scalar when the value is non-zero and below the group order. */
    private fun scalar(bytes: ByteArray): ByteArray {
        val firstNonZero = bytes.indexOfFirst { it != 0.toByte() }
        if (firstNonZero < 0) invalid()
        val magnitude = bytes.copyOfRange(firstNonZero, bytes.size)
        if (magnitude.size > 32) invalid()
        val padded = ByteArray(32 - magnitude.size) + magnitude
        for (index in 0 until 32) {
            val difference = (padded[index].toInt() and 255) - (order[index].toInt() and 255)
            if (difference < 0) return padded
            if (difference > 0) invalid()
        }
        invalid() // Equal to the order.
    }

    /** Minimal positive DER integer: no redundant leading zero, one zero byte when the top bit is set. */
    private fun derInteger(scalar: ByteArray): ByteArray {
        val start = scalar.indexOfFirst { it != 0.toByte() }
        val magnitude = scalar.copyOfRange(start, scalar.size)
        return if (magnitude[0].toInt() and 128 != 0) byteArrayOf(0) + magnitude else magnitude
    }

    private fun invalid(): Nothing = throw P256SignatureEncodingException()
}
