package dev.remozio.pairing

/**
 * A byte stream that already authenticated the peer. The JVM client wraps a pinned TLS 1.3 session
 * and the iOS client wraps a Network.framework connection. The channel never trusts the carrier.
 */
interface PairingByteStream : AutoCloseable {
    suspend fun awaitOpen()
    suspend fun send(bytes: ByteArray)
    suspend fun receive(): ByteArray?
    suspend fun awaitClosed()
}
