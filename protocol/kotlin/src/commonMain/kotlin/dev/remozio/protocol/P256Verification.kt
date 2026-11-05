package dev.remozio.protocol

internal object P256Verification {
    /** Both targets apply the same shape checks and the same strict DER conversion before the platform verifies. */
    fun verify(signature: ByteArray, publicKey: ByteArray, input: ByteArray): Boolean {
        if (signature.size != 64 || publicKey.size != 65) return false
        val pointBytes = publicKey.copyOf()
        val rawSignature = signature.copyOf()
        if (pointBytes[0] != 4.toByte()) return false
        val der = try { P256SignatureEncoding.toDer(rawSignature) }
            catch (_: P256SignatureEncodingException) { return false }
        return verifyP256Der(der, pointBytes, input)
    }
}

/**
 * ECDSA P-256 with SHA-256 over a DER signature and a 65-byte uncompressed point.
 * A point that is off the curve or has a coordinate at or above p must return false, never throw.
 */
internal expect fun verifyP256Der(derSignature: ByteArray, publicKey: ByteArray, input: ByteArray): Boolean
