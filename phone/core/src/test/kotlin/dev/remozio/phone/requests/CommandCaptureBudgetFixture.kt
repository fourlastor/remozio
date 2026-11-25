package dev.remozio.phone.requests

import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.DeterministicCbor

/** Uses ordinary captures and gives the receiver only enough items for the shorter one. */
internal class CommandCaptureBudgetFixture(capture: ByteArray, limits: CborLimits) {
    private val fields = DeterministicCbor.decode(capture, limits) as CborValue.Fields
    val shortCapture = capture.copyOf()
    val longCapture: ByteArray
    val receiverLimits = RequestLimits(limits, limits.copy(maxItems = itemCount(fields)), limits, limits)

    init {
        val arguments = fields.values.getValue(2uL) as CborValue.ArrayValue
        val extraArgument = CborValue.Bytes("fixture".encodeToByteArray())
        val longer = CborValue.Fields(fields.values + (2uL to CborValue.ArrayValue(arguments.values + extraArgument)))
        longCapture = DeterministicCbor.encode(longer, limits)
    }

    private fun itemCount(value: CborValue): Int = when (value) {
        is CborValue.Fields -> 1 + value.values.size + value.values.values.sumOf(::itemCount)
        is CborValue.ArrayValue -> 1 + value.values.sumOf(::itemCount)
        else -> 1
    }
}
