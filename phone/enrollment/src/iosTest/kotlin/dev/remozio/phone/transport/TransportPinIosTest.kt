package dev.remozio.phone.transport

import kotlin.test.*

/** The JVM validator does not check curve membership, so these rejections are specific to the Security path. */
class TransportPinIosTest {
    private val p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    private val x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    private val y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun spki(x: String = this.x, y: String = this.y) = p256SpkiPrefix() + byteArrayOf(4) + hex(x) + hex(y)

    @Test fun rejectsAPointOutsideTheCurve() {
        assertFails { p256TransportPin(spki(y = y.dropLast(1) + "4")) }
        assertFails { p256TransportPin(spki(x = p)) }
        assertFails { p256TransportPin(spki(y = p)) }
        assertFails { p256TransportPin(spki(x = "00".repeat(32), y = "00".repeat(32))) }
    }
}
