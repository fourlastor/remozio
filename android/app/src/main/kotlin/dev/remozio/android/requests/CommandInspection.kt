package dev.remozio.android.requests

import dev.remozio.phone.requests.TrackedRequestStatus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import dev.remozio.android.R
import dev.remozio.protocol.CapturedFileIdentity
import dev.remozio.protocol.CapturedSigningStatus
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.CommandCapture
import dev.remozio.protocol.CommandCapturePayload
import dev.remozio.protocol.LinuxCommandCapture
import dev.remozio.protocol.CommandIOMode
import dev.remozio.protocol.CommandInputKind
import dev.remozio.protocol.CapturedCommandStream
import dev.remozio.protocol.CommandStreamAccess
import dev.remozio.protocol.EnvironmentSource
import dev.remozio.protocol.StartedCommandDisconnect

/** Renders a retained capture. Only the authenticated session integration supplies decision controls. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun CommandInspection(
    capture: CommandCapturePayload?,
    macName: String,
    accountName: String,
    onDismiss: () -> Unit,
    sample: Boolean = false,
    status: TrackedRequestStatus? = null,
    requestKey: Any? = null,
    actions: (@Composable () -> Unit)? = null,
) {
    val pixels = LocalWindowInfo.current.containerSize
    val window = with(LocalDensity.current) { pixels.width.toDp() to pixels.height.toDp() }
    val identity = status?.status?.let { listOf(it.macID, it.accountID, it.requestID, it.requestDigest, it.challenge).map(CborValue::Bytes) }
    val visibleCapture = if (status?.status?.phase?.isTerminal == true) null else capture
    key(requestKey ?: identity ?: capture) {
        if (window.first < 600.dp) {
            ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberBottomSheetState(
                initialValue = SheetValue.Hidden, enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded),
            )) {
                InspectionContent(visibleCapture, macName, accountName, sample, onDismiss, status, Modifier.heightIn(max = window.second * 0.9f), actions = if (!sample && visibleCapture != null) actions else null)
            }
        } else {
            Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Surface(
                    modifier = Modifier.padding(24.dp).widthIn(max = 720.dp).fillMaxWidth().heightIn(max = window.second * 0.9f),
                    shape = MaterialTheme.shapes.extraLarge,
                ) { InspectionContent(visibleCapture, macName, accountName, sample, onDismiss, status, actions = if (!sample && visibleCapture != null) actions else null) }
            }
        }
    }
}

@Composable
private fun InspectionContent(
    capture: CommandCapturePayload?, macName: String, accountName: String, sample: Boolean, onDismiss: () -> Unit,
    status: TrackedRequestStatus?,
    modifier: Modifier = Modifier,
    actions: (@Composable () -> Unit)? = null,
) {
    var raw by remember { mutableStateOf(false) }
    val layout = capture?.stdioLayout
    val linuxRequester = (capture as? LinuxCommandCapture)?.let(::linuxRequesterPresentation)
    Column(modifier.fillMaxWidth()) {
        Column(Modifier.padding(horizontal = 24.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(when {
                sample && capture == null -> R.string.sample_status_title
                sample -> R.string.sample_command_title
                capture == null -> R.string.request_status_title
                else -> R.string.command_details
            }),
                style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
            if (sample) Text(stringResource(R.string.sample_command_notice), style = MaterialTheme.typography.bodyMedium)
            if (capture != null) TextButton(onClick = { raw = !raw }) {
                Text(stringResource(if (raw) R.string.hide_exact_bytes else R.string.show_exact_bytes))
            }
        }
        LazyColumn(Modifier.weight(1f, fill = false), contentPadding = PaddingValues(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (status != null) item { RequestStatusCard(status) }
            item {
                Section(R.string.request_context) {
                    TextValue(R.string.host_label, macName, raw)
                    TextValue(R.string.account_label, accountName, raw)
                }
            }
            if (capture == null) item {
                Text(stringResource(if (status?.status?.phase?.isTerminal == true) R.string.status_details_removed else R.string.status_details_unavailable))
            }
            else {
                item {
                    Section(if (capture is LinuxCommandCapture) R.string.requested_command else R.string.invocation) {
                        BytesValue(R.string.executable_label, capture.executable.path, raw)
                        BytesValue(R.string.directory_label, capture.directory.path, raw)
                        Text(stringResource(R.string.display_not_shell), style = MaterialTheme.typography.bodySmall)
                    }
                }
                itemsIndexed(capture.arguments) { index, argument ->
                    Card(Modifier.fillMaxWidth()) {
                        Value(stringResource(R.string.argument_index, index), argument.copyBytes(), raw, Modifier.padding(16.dp))
                    }
                }
                item {
                    Section(R.string.target_credentials) {
                        Numeric(R.string.uid_label, capture.target.uid.toString())
                        Numeric(R.string.gid_label, capture.target.gid.toString())
                        Numeric(R.string.groups_label, capture.target.supplementaryGroups.joinToString(", ").ifEmpty { stringResource(R.string.none_label) })
                        TextValue(R.string.user_name_label, capture.target.observedName, raw)
                    }
                }
                item { Heading(R.string.effective_environment) }
                if (capture.environment.isEmpty()) item { Text(stringResource(R.string.empty_environment)) }
                itemsIndexed(capture.environment) { index, entry ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(R.string.environment_index, index + 1), style = MaterialTheme.typography.titleSmall)
                            BytesValue(R.string.name_label, entry.name, raw)
                            BytesValue(R.string.value_label, entry.value, raw)
                            Text(stringResource(if (entry.source == EnvironmentSource.MINIMAL) R.string.minimal_environment else R.string.requested_environment),
                                style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }
                if (layout != null) {
                    item {
                        Section(R.string.command_streams) {
                            Text(stringResource(R.string.stream_observation_notice), style = MaterialTheme.typography.bodySmall)
                            if (capture.ioMode == CommandIOMode.PTY) Text(stringResource(R.string.private_terminal_routing))
                        }
                    }
                    inspectedCommandStreams(capture).forEach { inspected ->
                        item {
                            Section(inspected.role.title) {
                                Text(stringResource(if (inspected.routedToPrivateTerminal) R.string.stream_private_terminal else R.string.stream_original_source),
                                    style = MaterialTheme.typography.titleSmall)
                                StreamDetails(inspected.stream, raw)
                                if (inspected.role == InspectedStreamRole.INPUT && inspected.stream.source.kind != CommandInputKind.NULL) {
                                    Text(stringResource(R.string.input_not_captured), style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                    item {
                        Section(R.string.caller_control_terminal) {
                            val terminal = layout.terminal
                            if (terminal == null) Text(stringResource(if (capture.ioMode == CommandIOMode.PTY)
                                R.string.caller_terminal_absent_pty else R.string.caller_terminal_absent_pipes))
                            else {
                                Text(stringResource(R.string.caller_terminal_settings), style = MaterialTheme.typography.bodySmall)
                                StreamDetails(terminal.stream, raw)
                                Numeric(R.string.session_id, terminal.sessionID.toString())
                                Numeric(R.string.terminal_device, terminal.terminalDevice.toString())
                            }
                        }
                    }
                }
                item {
                    Section(R.string.input_and_lifetime) {
                        if (layout == null) {
                            Text(stringResource(when (capture.input.kind) {
                                CommandInputKind.NULL -> R.string.input_null
                                CommandInputKind.PIPE -> R.string.input_pipe
                                CommandInputKind.FILE -> R.string.input_file
                                CommandInputKind.TTY -> R.string.input_tty
                                CommandInputKind.PTY -> R.string.input_pty
                                CommandInputKind.SOCKET -> R.string.input_socket
                                CommandInputKind.DIRECTORY -> R.string.input_directory
                                CommandInputKind.DEVICE -> R.string.input_device
                                CommandInputKind.OTHER -> R.string.input_other
                            }))
                            if (capture.input.kind != CommandInputKind.NULL) Text(stringResource(R.string.input_not_captured))
                            BytesValue(R.string.input_path, capture.input.observedPath, raw)
                        }
                        Text(stringResource(if (capture.ioMode == CommandIOMode.PTY) R.string.io_pty else R.string.io_pipes))
                        Text(stringResource(if (capture.disconnectBehavior == StartedCommandDisconnect.TERMINATE) R.string.disconnect_terminate else R.string.disconnect_continue))
                    }
                }
                if (capture is CommandCapture) item {
                    Section(R.string.requester) {
                        BytesValue(R.string.requester_executable, capture.requester.executablePath, raw)
                        Numeric(R.string.real_uid, capture.requester.realUID.toString())
                        Numeric(R.string.effective_uid, capture.requester.effectiveUID.toString())
                        Numeric(R.string.pid_label, capture.requester.pid.toString())
                        Numeric(R.string.pid_version, capture.requester.pidVersion.toString())
                        Text(stringResource(when (capture.requester.signing.status) {
                            CapturedSigningStatus.UNSIGNED -> R.string.signing_unsigned
                            CapturedSigningStatus.AD_HOC -> R.string.signing_ad_hoc
                            CapturedSigningStatus.VALIDATED -> R.string.signing_validated
                            CapturedSigningStatus.INVALID -> R.string.signing_invalid
                            CapturedSigningStatus.UNAVAILABLE -> R.string.signing_unavailable
                        }), style = MaterialTheme.typography.titleSmall)
                        TextValue(R.string.signing_identifier, capture.requester.signing.identifier, raw)
                        TextValue(R.string.signing_team, capture.requester.signing.team, raw)
                        Numeric(R.string.session_id, capture.requester.sessionID?.toString())
                        BytesValue(R.string.tty_path, capture.requester.ttyPath, raw)
                    }
                }
                if (linuxRequester != null) {
                    item {
                        Section(R.string.linux_requester) {
                            Text(stringResource(R.string.linux_frontend_notice), style = MaterialTheme.typography.bodySmall)
                            LinuxFields(linuxRequester.observations, raw)
                        }
                    }
                    item {
                        Section(R.string.linux_frontend_policy) {
                            Text(stringResource(R.string.linux_policy_assertion_notice), style = MaterialTheme.typography.bodySmall)
                            LinuxFields(linuxRequester.policy, raw)
                        }
                    }
                    item {
                        Section(R.string.linux_scoped_identity) {
                            Text(stringResource(R.string.linux_scope_notice), style = MaterialTheme.typography.bodySmall)
                            LinuxFields(linuxRequester.scope, raw)
                        }
                    }
                }
                item {
                    Section(R.string.process_ancestry) {
                        commandAncestryNotices(capture).forEach { Text(stringResource(it)) }
                        Text(stringResource(R.string.ancestry_identity_limit), style = MaterialTheme.typography.bodySmall)
                    }
                }
                itemsIndexed(capture.ancestry.entries) { index, ancestor ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(R.string.ancestor_index, index + 1), style = MaterialTheme.typography.titleSmall)
                            BytesValue(R.string.requester_executable, ancestor.executablePath, raw)
                            Numeric(R.string.pid_label, ancestor.pid.toString())
                            Numeric(R.string.pid_version, ancestor.pidVersion.toString())
                            Numeric(R.string.uid_label, ancestor.uid.toString())
                        }
                    }
                }
                if (capture.unverifiedRationale != null) item {
                    Section(R.string.unverified_rationale) { TextValue(R.string.caller_explanation, capture.unverifiedRationale, raw) }
                }
                item {
                    Section(R.string.binding_details) {
                        Identity(R.string.executable_identity, capture.executable.identity)
                        Numeric(R.string.executable_sha256, ByteText.hex(capture.executable.sha256.copyBytes()))
                        Identity(R.string.directory_identity, capture.directory.identity)
                        if (layout == null) {
                            Identity(R.string.input_identity, capture.input.identity)
                            Numeric(R.string.input_binding, capture.input.streamBinding?.copyBytes()?.let(ByteText::hex))
                        } else Numeric(R.string.terminal_routing_mask, layout.ptyMask.toString())
                        if (capture is CommandCapture) Numeric(R.string.code_directory_hash, capture.requester.signing.cdHash?.copyBytes()?.let(ByteText::hex))
                        Numeric(R.string.submission_id, ByteText.hex(capture.submission.id.copyBytes()))
                        Numeric(R.string.submission_nonce, ByteText.hex(capture.submission.nonce.copyBytes()))
                        Numeric(R.string.caller_binding, ByteText.hex(capture.submission.callerBinding.copyBytes()))
                    }
                }
            }
        }
        actions?.invoke()
        TextButton(onClick = onDismiss, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text(stringResource(R.string.close_details))
        }
    }
}

@Composable
private fun LinuxFields(fields: List<LinuxInspectionField>, raw: Boolean) {
    fields.forEach { field ->
        when (field) {
            is LinuxInspectionField.Bytes -> BytesValue(field.label, field.value, raw)
            is LinuxInspectionField.Hex -> Numeric(field.label, ByteText.hex(field.value.copyBytes()))
            is LinuxInspectionField.Text -> TextValue(field.label, field.value, raw)
            is LinuxInspectionField.Number -> Numeric(field.label,
                if (field.label == R.string.groups_label && field.value.isNullOrEmpty()) stringResource(R.string.none_label) else field.value)
            is LinuxInspectionField.Identity -> Identity(field.label, field.value)
        }
    }
}

@Composable
private fun StreamDetails(stream: CapturedCommandStream, raw: Boolean) {
    Text(stringResource(when (stream.source.kind) {
        CommandInputKind.NULL -> R.string.stream_source_null
        CommandInputKind.PIPE -> R.string.stream_source_pipe
        CommandInputKind.FILE -> R.string.stream_source_file
        CommandInputKind.TTY -> R.string.stream_source_tty
        CommandInputKind.PTY -> R.string.stream_source_pty
        CommandInputKind.SOCKET -> R.string.stream_source_socket
        CommandInputKind.DIRECTORY -> R.string.stream_source_directory
        CommandInputKind.DEVICE -> R.string.stream_source_device
        CommandInputKind.OTHER -> R.string.stream_source_other
    }))
    Text(stringResource(when (stream.access) {
        CommandStreamAccess.READ_ONLY -> R.string.stream_access_read
        CommandStreamAccess.WRITE_ONLY -> R.string.stream_access_write
        CommandStreamAccess.READ_WRITE -> R.string.stream_access_read_write
    }))
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.stream_flags), style = MaterialTheme.typography.labelLarge)
        if (stream.flags.wireValue == 0uL) Text(stringResource(R.string.none_label))
        if (stream.flags.append) Text(stringResource(R.string.stream_flag_append))
        if (stream.flags.nonblocking) Text(stringResource(R.string.stream_flag_nonblocking))
        if (stream.flags.asynchronous) Text(stringResource(R.string.stream_flag_asynchronous))
        if (stream.flags.synchronous) Text(stringResource(R.string.stream_flag_synchronous))
    }
    BytesValue(R.string.stream_observed_path, stream.source.observedPath, raw)
    Identity(R.string.stream_identity, stream.source.identity)
    Numeric(R.string.stream_binding, stream.source.streamBinding?.copyBytes()?.let(ByteText::hex))
}

@Composable
private fun Heading(title: Int) {
    Text(stringResource(title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
}
@Composable
private fun Section(title: Int, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Heading(title)
            content()
        }
    }
}
@Composable
private fun BytesValue(label: Int, value: CborValue.Bytes?, raw: Boolean) = Value(stringResource(label), value?.copyBytes(), raw)
@Composable
private fun TextValue(label: Int, value: String?, raw: Boolean) = Value(stringResource(label), value?.encodeToByteArray(), raw)
@Composable
private fun Value(label: String, bytes: ByteArray?, raw: Boolean, modifier: Modifier = Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge)
        Text(bytes?.let(ByteText::quoted) ?: stringResource(R.string.not_available),
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.ContentOrLtr))
        if (raw && bytes != null) {
            Text(stringResource(R.string.exact_bytes_label), style = MaterialTheme.typography.labelSmall)
            Text(ByteText.hex(bytes).ifEmpty { stringResource(R.string.zero_bytes) },
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr))
        }
    }
}
@Composable
private fun Numeric(label: Int, value: String?) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(label), style = MaterialTheme.typography.labelLarge)
        Text(value ?: stringResource(R.string.not_available), style = MaterialTheme.typography.bodyMedium)
    }
}
@Composable
private fun Identity(label: Int, identity: CapturedFileIdentity?) {
    Numeric(label, identity?.let { stringResource(R.string.identity_value, it.device.toString(), it.inode.toString()) })
}
