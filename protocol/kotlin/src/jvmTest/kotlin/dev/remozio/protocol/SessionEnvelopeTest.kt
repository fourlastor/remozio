package dev.remozio.protocol

import org.junit.Test
import kotlin.test.*

class SessionEnvelopeTest {
    @Test fun sharedCanonicalBytesAndUnsignedSequenceRoundTrip() {
        val value = SessionEnvelope(ByteArray(32) { 0xaa.toByte() }, ULong.MAX_VALUE, byteArrayOf(1, 2, 3))
        val expected = "a40001015820" + "aa".repeat(32) + "021bffffffffffffffff0343010203"
        val encoded = value.encode(3)
        assertEquals(expected, encoded.joinToString("") { "%02x".format(it) })
        val decoded = SessionEnvelope.decode(encoded, 3)
        assertEquals(ULong.MAX_VALUE, decoded.sequence); assertEquals(value.sessionID, decoded.sessionID)
        assertEquals(value.payload, decoded.payload)
    }
    @Test fun incompatibleAndOversizedEnvelopesFail() {
        val original = SessionEnvelope(ByteArray(32), 0u, byteArrayOf(1)).encode(1)
        val fields = (DeterministicCbor.decode(original, CborLimits(100, 2, 12)) as CborValue.Fields).values
        for (change in listOf(0uL to CborValue.Unsigned(2u), 1uL to CborValue.Bytes(ByteArray(31)),
            2uL to CborValue.Text("0"), 3uL to CborValue.Bytes(ByteArray(0)), 4uL to CborValue.Unsigned(1u))) {
            val bytes = DeterministicCbor.encode(CborValue.Fields(fields + change), CborLimits(100, 2, 12))
            assertFails { SessionEnvelope.decode(bytes, 1) }
        }
        assertFails { SessionEnvelope(ByteArray(32), 0u, byteArrayOf(1, 2)).encode(1) }
        assertFails { SessionEnvelope.decode(original, Int.MAX_VALUE) }
        assertFails { SessionEnvelope.decode(original + byteArrayOf(0), 1) }
    }
}
