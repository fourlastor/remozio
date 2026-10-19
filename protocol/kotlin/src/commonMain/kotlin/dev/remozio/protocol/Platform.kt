package dev.remozio.protocol

/** SHA-256 through the platform implementation: JCA on the JVM, CommonCrypto on iOS. */
internal expect fun sha256(input: ByteArray): ByteArray

/** Requires a 65-byte uncompressed P-256 point with coordinates below p that lies on the curve. */
internal expect fun pairingPoint(bytes: ByteArray)

/** A copy that callers cannot mutate, even through a MutableList or MutableMap cast. */
internal expect fun <T> readOnlySnapshot(values: List<T>): List<T>
internal expect fun <K, V> readOnlySnapshot(values: Map<K, V>): Map<K, V>
