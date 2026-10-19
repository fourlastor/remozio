package dev.remozio.protocol

import java.math.BigInteger

class P256SignatureEncodingException : IllegalArgumentException("Invalid P-256 signature encoding")

/** Strict conversion between provider DER signatures and wire-format unsigned R || S. No hashing or signing. */
object P256SignatureEncoding {
    private val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    fun toDer(rawSignature: ByteArray): ByteArray {
        if (rawSignature.size != 64) invalid()
        val raw = rawSignature.copyOf()
        val r = scalar(raw.copyOfRange(0, 32)).toByteArray()
        val s = scalar(raw.copyOfRange(32, 64)).toByteArray()
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
            val value = scalar(der.copyOfRange(offset, offset + length))
            offset += length
            val bytes = value.toByteArray()
            val magnitude = if (bytes.size == 33) bytes.copyOfRange(1, 33) else bytes
            return ByteArray(32 - magnitude.size) + magnitude
        }
        val raw = integer() + integer()
        if (offset != der.size) invalid()
        return raw
    }

    private fun scalar(bytes: ByteArray): BigInteger = BigInteger(1, bytes).also {
        if (it.signum() == 0 || it >= order) invalid()
    }

    private fun invalid(): Nothing = throw P256SignatureEncodingException()
}
