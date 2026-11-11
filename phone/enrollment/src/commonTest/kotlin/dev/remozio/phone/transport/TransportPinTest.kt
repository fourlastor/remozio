package dev.remozio.phone.transport

import kotlin.test.*

/** The same accept and reject list on every target. The P-256 generator is a valid key. */
class TransportPinTest {
    private val p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    private val x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    private val y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun spki(x: String = this.x, y: String = this.y) = p256SpkiPrefix() + byteArrayOf(4) + hex(x) + hex(y)
    private fun changed(index: Int, value: Int) = spki().also { it[index] = value.toByte() }
    private fun rejects(encoded: ByteArray) { assertFailsWith<IllegalArgumentException> { p256TransportPin(encoded) } }

    @Test fun acceptsTheCanonicalEncodingAndReturnsACopy() {
        val input = spki()
        val pin = p256TransportPin(input)
        assertContentEquals(input, pin)
        input[0] = 0
        assertEquals(0x30, pin[0].toInt())
    }

    @Test fun acceptsAnotherPointOnTheCurve() {
        // 2G, so the check is the curve equation and not a comparison with the generator.
        val twice = spki(x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            y = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
        assertContentEquals(twice, p256TransportPin(twice))
    }

    @Test fun rejectsAWrongLength() {
        rejects(ByteArray(0))
        rejects(spki().copyOf(90))
        rejects(spki() + 0)
        rejects(ByteArray(257))
    }

    @Test fun rejectsAnotherAlgorithmOrCurve() {
        rejects(changed(12, 0x02))
        rejects(changed(22, 0x06))
    }

    @Test fun rejectsAPointThatIsNotUncompressed() {
        val compressed = byteArrayOf(0x30, 0x39) + p256SpkiPrefix().copyOfRange(2, 23) + byteArrayOf(0x03, 0x22, 0x00, 0x02) + hex(x)
        rejects(compressed)
        rejects(changed(26, 0x03))
    }

    @Test fun rejectsAPointOutsideTheCurve() {
        rejects(spki(y = y.dropLast(1) + "4"))
        rejects(spki(x = p))
        rejects(spki(y = p))
        rejects(spki(x = "00".repeat(32), y = "00".repeat(32)))
    }
}
