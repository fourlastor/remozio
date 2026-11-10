package dev.remozio.phone.transport

import dev.remozio.protocol.PairingKey

internal actual fun p256TransportPin(encoded: ByteArray): ByteArray {
    val copy = encoded.copyOf()
    val prefix = p256SpkiPrefix()
    require(copy.size == prefix.size + 65 && copy.copyOfRange(0, prefix.size).contentEquals(prefix)) { "P-256 transport key required" }
    // The constructor rejects an off-curve point and a coordinate at or above p, through Security.
    PairingKey(ByteArray(16), copy.copyOfRange(prefix.size, copy.size))
    return copy
}
