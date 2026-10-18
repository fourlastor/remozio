package dev.remozio.android.requests

import dev.remozio.android.R
import dev.remozio.protocol.CapturedFileIdentity
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.LinuxCommandCapture

/** Typed display values keep arbitrary host bytes on the existing escaped-byte rendering path. */
internal sealed interface LinuxInspectionField {
    val label: Int
    data class Bytes(override val label: Int, val value: CborValue.Bytes) : LinuxInspectionField
    data class Hex(override val label: Int, val value: CborValue.Bytes) : LinuxInspectionField
    data class Text(override val label: Int, val value: String) : LinuxInspectionField
    data class Number(override val label: Int, val value: String?) : LinuxInspectionField
    data class Identity(override val label: Int, val value: CapturedFileIdentity) : LinuxInspectionField
}

internal data class LinuxRequesterPresentation(
    val observations: List<LinuxInspectionField>,
    val policy: List<LinuxInspectionField>,
    val scope: List<LinuxInspectionField>,
)

/** Host assertions about the submitting frontend; never Apple signing or publisher observations. */
internal fun linuxRequesterPresentation(capture: LinuxCommandCapture): LinuxRequesterPresentation {
    val requester = capture.requester
    val credentials = requester.credentials
    return LinuxRequesterPresentation(
        observations = listOf(
            LinuxInspectionField.Bytes(R.string.linux_frontend_path, requester.executable.path),
            LinuxInspectionField.Number(R.string.pid_label, requester.pid.toString()),
            LinuxInspectionField.Number(R.string.real_uid, credentials.realUID.toString()),
            LinuxInspectionField.Number(R.string.effective_uid, credentials.effectiveUID.toString()),
            LinuxInspectionField.Number(R.string.saved_uid, credentials.savedUID.toString()),
            LinuxInspectionField.Number(R.string.filesystem_uid, credentials.filesystemUID.toString()),
            LinuxInspectionField.Number(R.string.real_gid, credentials.realGID.toString()),
            LinuxInspectionField.Number(R.string.effective_gid, credentials.effectiveGID.toString()),
            LinuxInspectionField.Number(R.string.saved_gid, credentials.savedGID.toString()),
            LinuxInspectionField.Number(R.string.filesystem_gid, credentials.filesystemGID.toString()),
            LinuxInspectionField.Number(R.string.groups_label, credentials.supplementaryGroups.joinToString(", ")),
            LinuxInspectionField.Number(R.string.session_id, requester.sessionID?.toString()),
        ),
        policy = listOf(
            LinuxInspectionField.Identity(R.string.linux_frontend_identity, requester.executable.identity),
            LinuxInspectionField.Hex(R.string.linux_frontend_sha256, requester.executable.sha256),
            LinuxInspectionField.Hex(R.string.linux_policy_digest, requester.codePolicyDigest),
        ),
        scope = listOf(
            LinuxInspectionField.Text(R.string.linux_requester_profile, requester.profile),
            LinuxInspectionField.Hex(R.string.linux_process_binding, requester.processBinding),
            LinuxInspectionField.Hex(R.string.linux_monitor_incarnation, requester.monitorIncarnation),
            LinuxInspectionField.Number(R.string.linux_exec_epoch, requester.execEpoch.toString()),
        ),
    )
}
