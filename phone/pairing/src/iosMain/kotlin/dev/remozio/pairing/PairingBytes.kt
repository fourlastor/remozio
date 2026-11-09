package dev.remozio.pairing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

/** Copies for the Swift transport, which works in `Data`. Exported as `PairingBytesKt`. */
@OptIn(ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)
fun pairingData(bytes: ByteArray): NSData =
    if (bytes.isEmpty()) NSData() else bytes.usePinned { NSData.create(bytes = it.addressOf(0), length = bytes.size.toULong()) }

/** Refuses more than [PairingTransport.MAXIMUM_DELIVERY] bytes, so the length always fits the copy. */
@OptIn(ExperimentalForeignApi::class)
fun pairingBytes(data: NSData): ByteArray {
    require(data.length <= PairingTransport.MAXIMUM_DELIVERY.toULong()) { "Pairing data too large" }
    val size = data.length.toInt()
    val bytes = ByteArray(size)
    if (size > 0) bytes.usePinned { memcpy(it.addressOf(0), data.bytes, data.length) }
    return bytes
}
