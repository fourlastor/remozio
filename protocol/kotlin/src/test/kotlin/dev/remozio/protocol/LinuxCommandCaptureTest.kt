package dev.remozio.protocol

import java.io.File
import java.security.MessageDigest
import kotlinx.serialization.json.*
import kotlin.test.*

class LinuxCommandCaptureTest {
    private val limits = CborLimits(32768, 32, 4096)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.commandVectors4"))).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun base() = vectors().getValue("valid").jsonArray.first { it.jsonObject.getValue("name").jsonPrimitive.content == "schema4-base" }.jsonObject
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)

    @Test fun sharedValidCapturesExposeTypedLinuxClaimsAndCompleteStreams() {
        val rows = vectors().getValue("valid").jsonArray
        assertTrue(rows.isNotEmpty())
        val epochs = mutableSetOf<ULong>()
        for (row in rows) {
            val fields = row.jsonObject
            val name = fields.getValue("name").jsonPrimitive.content
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            val capture = assertIs<LinuxCommandCapture>(CommandCapturePayload.decode(bytes, limits, 4u), name)
            val requester = capture.requester
            val credentials = requester.credentials
            assertContentEquals(bytes, capture.canonicalBytes, name)
            assertContentEquals(hex(fields.getValue("captureSHA256").jsonPrimitive.content), sha256(bytes), name)
            assertEquals(4uL, capture.schemaVersion, name)
            assertEquals("linux-protected-single-thread-v1", requester.profile, name)
            assertEquals(fields.getValue("requesterPID").jsonPrimitive.content.toUInt(), requester.pid, name)
            assertEquals(fields.getValue("execEpoch").jsonPrimitive.content.toULong(), requester.execEpoch, name)
            epochs += requester.execEpoch
            assertEquals(fields.getValue("sessionID").jsonPrimitive.contentOrNull?.toUInt(), requester.sessionID, name)
            assertContentEquals(hex(fields.getValue("requesterExecutablePath").jsonPrimitive.content), requester.executable.path.copyBytes(), name)
            assertContentEquals(hex(fields.getValue("requestedExecutablePath").jsonPrimitive.content), capture.executable.path.copyBytes(), name)
            assertContentEquals(hex(fields.getValue("processBinding").jsonPrimitive.content), requester.processBinding.copyBytes(), name)
            assertContentEquals(hex(fields.getValue("monitorIncarnation").jsonPrimitive.content), requester.monitorIncarnation.copyBytes(), name)
            assertContentEquals(hex(fields.getValue("codePolicyDigest").jsonPrimitive.content), requester.codePolicyDigest.copyBytes(), name)
            assertEquals(fields.getValue("credentialUIDs").jsonArray.map { it.jsonPrimitive.content.toUInt() },
                listOf(credentials.realUID, credentials.effectiveUID, credentials.savedUID, credentials.filesystemUID), name)
            assertEquals(fields.getValue("credentialGIDs").jsonArray.map { it.jsonPrimitive.content.toUInt() },
                listOf(credentials.realGID, credentials.effectiveGID, credentials.savedGID, credentials.filesystemGID), name)
            assertEquals(fields.getValue("supplementaryGroups").jsonArray.map { it.jsonPrimitive.content.toUInt() }, credentials.supplementaryGroups, name)
            assertEquals(fields.getValue("arguments").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.arguments, name)
            assertEquals(fields.getValue("environmentNames").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.environment.map { it.name }, name)
            assertEquals(fields.getValue("rationale").jsonPrimitive.contentOrNull, capture.unverifiedRationale, name)
            assertEquals(CommandIOMode.PIPES, capture.ioMode, name)
            assertEquals(StartedCommandDisconnect.TERMINATE, capture.disconnectBehavior, name)
            assertEquals(CapturedAncestry(AncestryCompleteness.UNAVAILABLE, emptyList(), AncestryReason.UNSUPPORTED), capture.ancestry, name)
            val layout = assertNotNull(capture.stdioLayout, name)
            assertEquals(capture.input, layout.input.source, name)
            assertNull(layout.terminal, name)
            assertEquals(0u, layout.ptyMask, name)
            val streams = listOf(layout.input, layout.output, layout.error)
            assertEquals(fields.getValue("streamKinds").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.source.kind.wireValue }, name)
            assertEquals(fields.getValue("streamAccess").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.access.wireValue }, name)
            assertEquals(fields.getValue("streamFlags").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.flags.wireValue }, name)
        }
        assertTrue(epochs.any { it > Long.MAX_VALUE.toULong() })
        assertTrue(ULong.MAX_VALUE in epochs)
    }

    @Test fun everyMalformedProfileFailsClosedUnderItsDeclaredBudget() {
        val rows = vectors().getValue("invalid").jsonArray
        assertTrue(rows.isNotEmpty())
        for (row in rows) {
            val fields = row.jsonObject
            val custom = fields["limits"]?.jsonObject
            val bound = if (custom == null) limits else CborLimits(custom.getValue("maxBytes").jsonPrimitive.int,
                custom.getValue("maxDepth").jsonPrimitive.int, custom.getValue("maxItems").jsonPrimitive.int)
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                CommandCapturePayload.decode(hex(fields.getValue("hex").jsonPrimitive.content), bound, 4u)
            }
        }
    }

    @Test fun explicitSchemaAndTypedVariantsCannotFallback() {
        val bytes = hex(base().getValue("hex").jsonPrimitive.content)
        assertEquals(setOf(1uL, 2uL, 3uL), CommandCapture.supportedSchemaVersions)
        assertEquals(setOf(1uL, 2uL, 3uL, 4uL), CommandCapturePayload.supportedSchemaVersions)
        assertFailsWith<CommandCaptureException> { CommandCapture(bytes, limits) }
        assertFailsWith<CommandCaptureException> { CommandCapture(bytes, limits, 4u) }
        for (schema in listOf(1uL, 2uL, 3uL, 5uL)) {
            assertFailsWith<CommandCaptureException> { CommandCapturePayload.decode(bytes, limits, schema) }
            assertFailsWith<CommandCaptureException> { LinuxCommandCapture(bytes, limits, schema) }
        }
    }

    @Test fun linuxSnapshotsAndCredentialCollectionsAreDefensive() {
        val bytes = hex(base().getValue("hex").jsonPrimitive.content)
        val original = bytes.copyOf()
        val capture = LinuxCommandCapture(bytes, limits, 4u)
        val binding = capture.requester.processBinding.copyBytes()
        bytes.fill(0)
        capture.canonicalBytes.fill(0)
        capture.requester.processBinding.copyBytes().fill(0)
        capture.requester.monitorIncarnation.copyBytes().fill(0)
        capture.requester.codePolicyDigest.copyBytes().fill(0)
        capture.requester.executable.path.copyBytes().fill(0)
        assertContentEquals(original, capture.canonicalBytes)
        assertContentEquals(binding, capture.requester.processBinding.copyBytes())
        assertFailsWith<UnsupportedOperationException> { (capture.requester.credentials.supplementaryGroups as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.arguments as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.environment as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.target.supplementaryGroups as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.ancestry.entries as MutableList).clear() }
        for (bound in listOf(CborLimits(original.size - 1, 32, 4096), CborLimits(32768, 1, 4096), CborLimits(32768, 32, 2))) {
            assertFailsWith<CborException> { CommandCapturePayload.decode(original, bound, 4u) }
        }
    }

    @Test fun everyRequesterAndStreamMutationChangesTheApprovalDigest() {
        val corpus = vectors()
        val captures = corpus.getValue("valid").jsonArray.associate {
            val row = it.jsonObject
            row.getValue("name").jsonPrimitive.content to hex(row.getValue("hex").jsonPrimitive.content)
        }
        fun issued(bytes: ByteArray) = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 4u),
            ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(32) { 4 }, emptySet(), 10u, 20u, bytes,
            listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
        val mutations = corpus.getValue("digestMutations").jsonArray
        assertTrue(mutations.isNotEmpty())
        for (entry in mutations) {
            val row = entry.jsonObject
            val name = row.getValue("name").jsonPrimitive.content
            val bytes = hex(row.getValue("hex").jsonPrimitive.content)
            val base = checkNotNull(captures[row.getValue("base").jsonPrimitive.content])
            assertContentEquals(hex(row.getValue("captureSHA256").jsonPrimitive.content), sha256(bytes), name)
            assertFalse(sha256(base).contentEquals(sha256(bytes)), name)
            assertFalse(issued(base).requestDigest(limits, limits).contentEquals(issued(bytes).requestDigest(limits, limits)), name)
            if (row.getValue("validCapture").jsonPrimitive.boolean) CommandCapturePayload.decode(bytes, limits, 4u)
            else assertFailsWith<IllegalArgumentException>(name) { CommandCapturePayload.decode(bytes, limits, 4u) }
        }
    }

    @Test fun sharedOuterSelectedAndInnerSchemaBindingsNeverFallback() {
        val corpus = vectors()
        val captures = corpus.getValue("valid").jsonArray.associate {
            val row = it.jsonObject
            row.getValue("name").jsonPrimitive.content to hex(row.getValue("hex").jsonPrimitive.content)
        }
        for (entry in corpus.getValue("contractBindings").jsonArray) {
            val row = entry.jsonObject
            val name = row.getValue("name").jsonPrimitive.content
            val outer = row.getValue("outerSchema").jsonPrimitive.content.toULong()
            val selected = row.getValue("selectedSchema").jsonPrimitive.content.toULong()
            val issued = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, outer),
                ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(32) { 4 }, emptySet(), 10u, 20u,
                checkNotNull(captures[row.getValue("capture").jsonPrimitive.content]),
                listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
            val decode = {
                val request = IssuedRequestPayload.decode(issued.encode(limits), limits, limits,
                    ContractCapabilities(mapOf(RequestContract(RequestKind.COMMAND, 1u, selected) to emptySet())))
                CommandCapturePayload.decode(request.canonicalCapture, limits, request.contract.schemaVersion)
            }
            if (row.getValue("accepted").jsonPrimitive.boolean) assertIs<LinuxCommandCapture>(decode(), name)
            else assertFailsWith<IllegalArgumentException>(name) { decode() }
        }
    }
}
