package dev.remozio.pairing

/** Bytes from the platform's cryptographic random source. */
internal expect fun secureRandom(count: Int): ByteArray
