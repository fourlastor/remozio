package dev.remozio.android.requests

import dev.remozio.android.R
import dev.remozio.protocol.CapturedCommandStream
import dev.remozio.protocol.ChannelRequestCapability
import dev.remozio.protocol.CommandCapturePayload
import dev.remozio.protocol.AncestryCompleteness
import dev.remozio.protocol.AncestryReason

internal enum class InspectedStreamRole(val title: Int, val maskBit: UInt) {
    INPUT(R.string.stream_stdin, 1u), OUTPUT(R.string.stream_stdout, 2u), ERROR(R.string.stream_stderr, 4u),
}

internal data class InspectedCommandStream(
    val role: InspectedStreamRole,
    val stream: CapturedCommandStream,
    val routedToPrivateTerminal: Boolean,
)

internal fun inspectedCommandStreams(capture: CommandCapturePayload): List<InspectedCommandStream> {
    val layout = capture.stdioLayout ?: return emptyList()
    return listOf(
        InspectedStreamRole.INPUT to layout.input,
        InspectedStreamRole.OUTPUT to layout.output,
        InspectedStreamRole.ERROR to layout.error,
    ).map { (role, stream) -> InspectedCommandStream(role, stream, layout.ptyMask and role.maskBit != 0u) }
}

internal fun commandInspectionCapabilities(): List<ChannelRequestCapability> =
    listOf(1uL, 2uL, 3uL, 4uL).map { ChannelRequestCapability(0u, 1u, it, emptySet()) }

internal fun commandAncestryNotices(capture: CommandCapturePayload): List<Int> = buildList {
    add(when (capture.ancestry.completeness) {
        AncestryCompleteness.COMPLETE -> R.string.ancestry_complete
        AncestryCompleteness.PARTIAL -> R.string.ancestry_partial
        AncestryCompleteness.UNAVAILABLE -> R.string.ancestry_unavailable
    })
    when (capture.ancestry.reason) {
        AncestryReason.EXITED -> add(R.string.ancestry_exited)
        AncestryReason.PERMISSION -> add(R.string.ancestry_permission)
        AncestryReason.TRUNCATED -> add(R.string.ancestry_truncated)
        AncestryReason.UNSUPPORTED -> add(R.string.ancestry_unsupported)
        AncestryReason.NONE -> Unit
    }
}
