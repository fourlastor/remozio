package dev.remozio.phone.transport

import dev.remozio.protocol.PairingKey

/**
 * The only accepted transport key encoding: P-256, a named curve and an uncompressed point on the curve. Returns a
 * copy. Every rejection is an [IllegalArgumentException], on every target.
 */
internal fun p256TransportPin(encoded: ByteArray): ByteArray {
    val copy = encoded.copyOf()
    val prefix = p256SpkiPrefix()
    require(copy.size == prefix.size + 65 && copy.copyOfRange(0, prefix.size).contentEquals(prefix)) { "P-256 transport key required" }
    // The constructor calls pairingPoint in :protocol-kotlin, which on every target requires the 0x04 marker and
    // rejects a point off the curve and a coordinate at or above p. The key ID is a placeholder; nothing keeps it.
    PairingKey(ByteArray(16), copy.copyOfRange(prefix.size, copy.size))
    return copy
}

/** The fixed DER prefix of a P-256 SubjectPublicKeyInfo. The whole encoding is this prefix and the 65-byte point. */
internal fun p256SpkiPrefix(): ByteArray = byteArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48,
    0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00)
