package dev.sebastiano.remozio.android.requests

import dev.remozio.protocol.*
import java.io.File
import org.junit.Test
import kotlin.test.*

class CommandRequestLimitsTest {
    private val limits = commandRequestLimits()
    private val fields = (DeterministicCbor.decode(File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes(), limits.capture) as CborValue.Fields).values
    private fun capture(field: ULong, value: CborValue): CommandCapture = CommandCapture(
        DeterministicCbor.encode(CborValue.Fields(fields + (field to value)), limits.capture), limits.capture)

    @Test fun measuredLargeArgumentAndManyArgumentsRemainExact() {
        val large = ByteArray(1_044_480) { 'x'.code.toByte() }
        val parsed = capture(2u, CborValue.ArrayValue(listOf(CborValue.Bytes(large))))
        assertContentEquals(large, parsed.arguments.single().copyBytes())
        val many = capture(2u, CborValue.ArrayValue(List(65_536) { CborValue.Bytes(byteArrayOf(120)) }))
        assertEquals(65_536, many.arguments.size)
        assertTrue(many.arguments.all { it.copyBytes().contentEquals(byteArrayOf(120)) })
    }

    @Test fun measuredManyEnvironmentEntriesFitTheItemBound() {
        val entries = List(32_768) { index -> CborValue.Fields(mapOf(
            0uL to CborValue.Bytes("REMOZIO_%05d".format(index).encodeToByteArray()),
            1uL to CborValue.Bytes(byteArrayOf(120)), 2uL to CborValue.Unsigned(1u),
        )) }
        val parsed = capture(5u, CborValue.ArrayValue(entries))
        assertEquals(entries.size, parsed.environment.size)
        assertContentEquals("REMOZIO_32767".encodeToByteArray(), parsed.environment.last().name.copyBytes())
    }

    @Test fun excessiveTinyArgumentsAreRejectedByTheDecoderItemBound() {
        val wire = DeterministicCbor.encode(CborValue.Fields(fields +
            (2uL to CborValue.ArrayValue(List(262_144) { CborValue.Bytes(byteArrayOf()) }))),
            limits.capture.copy(maxItems = 1_048_576))
        assertTrue(wire.size < limits.capture.maxBytes)
        val failure = assertFailsWith<CborException> { CommandCapture(wire, limits.capture) }
        assertEquals(CborFailure.ITEM_LIMIT, failure.reason)
    }

    @Test fun captureLimitRejectsOversizeWithoutTruncationAndAllowsEnvelopeOverhead() {
        val error = assertFailsWith<CborException> {
            capture(2u, CborValue.ArrayValue(listOf(CborValue.Bytes(ByteArray(limits.capture.maxBytes) { 120 }))))
        }
        assertEquals(CborFailure.BYTE_LIMIT, error.reason)
        assertTrue(limits.body.maxBytes > limits.capture.maxBytes + 4096)
        assertTrue(limits.signing.maxBytes > limits.body.maxBytes + 4096)
    }
}
