package dev.remozio.phone.transport

import kotlin.test.*

/** The same accept and reject list on every target. The P-256 generator is a valid key. */
class TransportPinTest {
    private val x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    private val y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun spki(x: String = this.x, y: String = this.y) = p256SpkiPrefix() + byteArrayOf(4) + hex(x) + hex(y)
    private fun changed(index: Int, value: Int) = spki().also { it[index] = value.toByte() }

    @Test fun acceptsTheCanonicalEncodingAndReturnsACopy() {
        val input = spki()
        val pin = p256TransportPin(input)
        assertContentEquals(input, pin)
        input[0] = 0
        assertEquals(0x30, pin[0].toInt())
    }

    @Test fun rejectsAWrongLength() {
        assertFails { p256TransportPin(ByteArray(0)) }
        assertFails { p256TransportPin(spki().copyOf(90)) }
        assertFails { p256TransportPin(spki() + 0) }
        assertFails { p256TransportPin(ByteArray(257)) }
    }

    @Test fun rejectsAnotherAlgorithmOrCurve() {
        assertFails { p256TransportPin(changed(12, 0x02)) }
        assertFails { p256TransportPin(changed(22, 0x06)) }
    }

    @Test fun rejectsAPointThatIsNotUncompressed() {
        val compressed = byteArrayOf(0x30, 0x39) + p256SpkiPrefix().copyOfRange(2, 23) + byteArrayOf(0x03, 0x22, 0x00, 0x02) + hex(x)
        assertFails { p256TransportPin(compressed) }
        assertFails { p256TransportPin(changed(26, 0x03)) }
    }
}
