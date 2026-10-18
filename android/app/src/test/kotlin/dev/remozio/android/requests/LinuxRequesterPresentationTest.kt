package dev.remozio.android.requests

import dev.remozio.android.R
import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CommandCapturePayload
import dev.remozio.protocol.CommandIOMode
import dev.remozio.protocol.LinuxCommandCapture
import dev.remozio.protocol.StartedCommandDisconnect
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class LinuxRequesterPresentationTest {
    private val limits = CborLimits(32768, 32, 4096)
    private fun rows() = Json.parseToJsonElement(File(requireNotNull(
        System.getProperty("remozio.test.linuxCommandCaptureVectors"))).readText())
        .jsonObject.getValue("valid").jsonArray.map { it.jsonObject }
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun String.bytes() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun capture(row: JsonObject) = assertIs<LinuxCommandCapture>(
        CommandCapturePayload.decode(row.text("hex").bytes(), limits, 4u))

    @Test fun everyRequesterCredentialAndScopedValueSurvivesInspectionWithoutAppleSigningFields() {
        val forbidden = setOf(R.string.pid_version, R.string.signing_identifier, R.string.signing_team,
            R.string.code_directory_hash, R.string.signing_validated, R.string.signing_unavailable)
        for (row in rows()) {
            val capture = capture(row)
            val presentation = linuxRequesterPresentation(capture)
            val observations = presentation.observations.associateBy { it.label }
            val scope = presentation.scope.associateBy { it.label }
            val policy = presentation.policy.associateBy { it.label }
            fun number(label: Int) = assertIs<LinuxInspectionField.Number>(observations.getValue(label)).value
            assertContentEquals(row.text("requesterExecutablePath").bytes(),
                assertIs<LinuxInspectionField.Bytes>(observations.getValue(R.string.linux_frontend_path)).value.copyBytes())
            assertEquals(row.text("requesterPID"), number(R.string.pid_label))
            val uids = listOf(R.string.real_uid, R.string.effective_uid, R.string.saved_uid, R.string.filesystem_uid)
            val gids = listOf(R.string.real_gid, R.string.effective_gid, R.string.saved_gid, R.string.filesystem_gid)
            assertEquals(row.getValue("credentialUIDs").jsonArray.map { it.jsonPrimitive.content }, uids.map(::number))
            assertEquals(row.getValue("credentialGIDs").jsonArray.map { it.jsonPrimitive.content }, gids.map(::number))
            assertEquals(row.getValue("supplementaryGroups").jsonArray.joinToString(", ") { it.jsonPrimitive.content }, number(R.string.groups_label))
            assertEquals(row.getValue("sessionID").jsonPrimitive.content.takeUnless { it == "null" }, number(R.string.session_id))
            assertEquals(setOf(R.string.linux_frontend_path, R.string.pid_label, R.string.groups_label, R.string.session_id) + uids + gids,
                observations.keys)
            assertEquals("linux-protected-single-thread-v1",
                assertIs<LinuxInspectionField.Text>(scope.getValue(R.string.linux_requester_profile)).value)
            assertEquals(row.text("execEpoch"), assertIs<LinuxInspectionField.Number>(scope.getValue(R.string.linux_exec_epoch)).value)
            for ((label, key) in listOf(R.string.linux_process_binding to "processBinding", R.string.linux_monitor_incarnation to "monitorIncarnation")) {
                assertContentEquals(row.text(key).bytes(), assertIs<LinuxInspectionField.Hex>(scope.getValue(label)).value.copyBytes())
            }
            assertContentEquals(row.text("codePolicyDigest").bytes(),
                assertIs<LinuxInspectionField.Hex>(policy.getValue(R.string.linux_policy_digest)).value.copyBytes())
            assertEquals(capture.requester.executable.identity,
                assertIs<LinuxInspectionField.Identity>(policy.getValue(R.string.linux_frontend_identity)).value)
            assertContentEquals(capture.requester.executable.sha256.copyBytes(),
                assertIs<LinuxInspectionField.Hex>(policy.getValue(R.string.linux_frontend_sha256)).value.copyBytes())
            assertTrue((presentation.observations + presentation.policy + presentation.scope).none { it.label in forbidden })
            // These remain independently captured paths, even when a fixture deliberately makes them equal.
            assertContentEquals(row.text("requestedExecutablePath").bytes(), capture.executable.path.copyBytes())
            assertEquals(listOf(R.string.ancestry_unavailable, R.string.ancestry_unsupported), commandAncestryNotices(capture))
            assertTrue(capture.ancestry.entries.isEmpty())
        }
    }

    @Test fun presentsFullUnsignedEpochRangeAndExplicitEmptyGroupAndAbsentSessionObservations() {
        val captures = rows().map(::capture)
        val epochs = captures.map { capture ->
            assertIs<LinuxInspectionField.Number>(linuxRequesterPresentation(capture).scope.single { it.label == R.string.linux_exec_epoch }).value
        }
        assertTrue(epochs.filterNotNull().map(String::toULong).any { it > Long.MAX_VALUE.toULong() && it != ULong.MAX_VALUE })
        assertTrue("18446744073709551615" in epochs)
        assertTrue(captures.any { it.requester.credentials.supplementaryGroups.isEmpty() })
        assertTrue(captures.any { it.requester.sessionID == null })
    }

    @Test fun schemaFourRetainsAllStreamObservationsWithoutInventingPrivateTerminalRouting() {
        for (row in rows()) {
            val capture = capture(row)
            val streams = inspectedCommandStreams(capture)
            assertEquals(listOf(InspectedStreamRole.INPUT, InspectedStreamRole.OUTPUT, InspectedStreamRole.ERROR), streams.map { it.role })
            assertEquals(row.getValue("streamKinds").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.stream.source.kind.wireValue })
            assertEquals(row.getValue("streamAccess").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.stream.access.wireValue })
            assertEquals(row.getValue("streamFlags").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.stream.flags.wireValue })
            assertEquals(row.text("inputKind").toULong(), capture.input.kind.wireValue)
            assertTrue(streams.none { it.routedToPrivateTerminal })
            assertEquals(0u, capture.stdioLayout?.ptyMask)
            assertEquals(null, capture.stdioLayout?.terminal)
            assertEquals(CommandIOMode.PIPES, capture.ioMode)
            assertEquals(StartedCommandDisconnect.TERMINATE, capture.disconnectBehavior)
        }
    }

    @Test fun frontendRawBytesControlsAndBidiUseTheExistingLosslessDisplayPath() {
        var escapedByte = false
        var escapedBidi = false
        var escapedControl = false
        for (row in rows()) {
            val field = assertIs<LinuxInspectionField.Bytes>(linuxRequesterPresentation(capture(row)).observations
                .single { it.label == R.string.linux_frontend_path })
            val bytes = field.value.copyBytes()
            val quoted = ByteText.quoted(bytes)
            assertContentEquals(bytes, ByteText.hex(bytes).split(' ').map { it.toInt(16).toByte() }.toByteArray())
            assertFalse(quoted.any { Character.getType(it) in setOf(Character.CONTROL.toInt(), Character.FORMAT.toInt()) })
            escapedByte = escapedByte || quoted.contains("\\x")
            escapedBidi = escapedBidi || quoted.contains("\\u{202d}") || quoted.contains("\\u{202e}") || quoted.contains("\\u{2066}")
            escapedControl = escapedControl || quoted.contains("\\n") || quoted.contains("\\r") || quoted.contains("\\t") || quoted.contains("\\u{1b}")
        }
        assertTrue(escapedByte, "Shared vectors must exercise invalid UTF-8 frontend bytes")
        assertTrue(escapedBidi, "Shared vectors must exercise a bidi frontend path")
        assertTrue(escapedControl, "Shared vectors must exercise a control in the frontend path")
    }
}
