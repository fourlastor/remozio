package dev.remozio.pairing

/**
 * A pinned byte pipe that the platform supplies (Network.framework on iOS). Kotlin cannot see TLS, so the
 * implementation carries the whole authentication claim. The rules below are the contract.
 *
 * - [PairingTransportEvents.opened] fires at most once, and only after TLS 1.3 completed, the server's leaf SPKI
 *   equalled the pin byte for byte and the negotiated ALPN equalled the requested protocol. Any other outcome
 *   ends with [PairingTransportEvents.closed] and never with `opened`.
 * - After [start], [PairingTransportEvents.closed] fires exactly once: after a peer close, a failure, a failed open
 *   or [cancel], including a cancel that arrives before `opened`. Nothing fires after `closed`.
 * - [requestBytes] asks for one delivery. The implementation reads once and answers with exactly one
 *   [PairingTransportEvents.received] (1 to [MAXIMUM_DELIVERY] bytes) or with `closed`. It never reads ahead, so a
 *   fast peer cannot grow memory on the phone. Kotlin calls it again only after the previous answer.
 * - [send] answers its completion exactly once, with null on success or an error text. After `closed` it answers
 *   with an error.
 * - [cancel] may arrive at any time, from any thread, more than once and even before [start]. A [start] after a
 *   cancel reports `closed`.
 * - Byte arrays belong to the receiver after each call. Callbacks may arrive on any thread.
 */
interface PairingTransport {
    fun start(events: PairingTransportEvents)
    fun requestBytes()
    fun send(bytes: ByteArray, completion: PairingSendCompletion)
    fun cancel()

    companion object {
        /** The largest delivery the stream accepts. The platform reads at most this many bytes at a time. */
        const val MAXIMUM_DELIVERY: Int = 65_536
    }
}

interface PairingTransportEvents {
    fun opened()
    fun received(bytes: ByteArray)
    /** [error] is null for an orderly close by the peer. */
    fun closed(error: String?)
}

fun interface PairingSendCompletion {
    fun done(error: String?)
}
