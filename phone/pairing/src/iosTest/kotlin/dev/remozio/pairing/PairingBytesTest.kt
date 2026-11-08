package dev.remozio.pairing

import platform.Foundation.NSMutableData
import platform.Foundation.dataWithLength
import kotlin.test.*

class PairingBytesTest {
    @Test fun bytesSurviveTheRoundTrip() {
        val bytes = ByteArray(PairingTransport.MAXIMUM_DELIVERY) { (it * 7).toByte() }
        assertContentEquals(bytes, pairingBytes(pairingData(bytes)))
        assertContentEquals(ByteArray(0), pairingBytes(pairingData(ByteArray(0))))
    }

    @Test fun moreThanOneDeliveryIsRefused() {
        val large = NSMutableData.dataWithLength((PairingTransport.MAXIMUM_DELIVERY + 1).toULong())!!
        assertFailsWith<IllegalArgumentException> { pairingBytes(large) }
    }
}
