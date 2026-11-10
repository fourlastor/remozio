package dev.remozio.phone.transport

/** The only accepted transport key encoding: P-256, a named curve and an uncompressed point. Returns a copy. */
internal expect fun p256TransportPin(encoded: ByteArray): ByteArray

/** The fixed DER prefix of a P-256 SubjectPublicKeyInfo. The whole encoding is this prefix and the 65-byte point. */
internal fun p256SpkiPrefix(): ByteArray = byteArrayOf(0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48,
    0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00)
