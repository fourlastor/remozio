package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class CommandCaptureTest {
    private val limits = CborLimits(8192, 16, 1024)
    private fun vectors(version: Int = 1) = Json.parseToJsonElement(File(checkNotNull(System.getProperty(if (version == 1) "remozio.commandVectors" else "remozio.commandVectors$version"))).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun first() = hex(vectors().getValue("valid").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
    @Test fun sharedCapturesPreserveExactBytesAndProvenance() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(9, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            val capture = CommandCapture(bytes, limits)
            assertContentEquals(bytes, capture.canonicalBytes)
            assertEquals(fields.getValue("arguments").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.arguments)
            assertEquals(fields.getValue("environmentNames").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.environment.map { it.name })
            assertEquals(fields.getValue("inputKind").jsonPrimitive.content.toULong(), capture.input.kind.wireValue)
            assertEquals(fields.getValue("signingStatus").jsonPrimitive.content.toULong(), capture.requester.signing.status.wireValue)
            assertEquals(fields.getValue("ancestry").jsonPrimitive.content.toULong(), capture.ancestry.completeness.wireValue)
            assertEquals(fields.getValue("rationale").jsonPrimitive.contentOrNull, capture.unverifiedRationale)
        }
        val capture = CommandCapture(first(), limits)
        assertContentEquals("/usr/bin/printf".encodeToByteArray(), capture.executable.path.copyBytes())
        assertEquals(100uL, capture.executable.identity.inode)
        assertContentEquals(ByteArray(32) { it.toByte() }, capture.executable.sha256.copyBytes())
        assertEquals(101uL, capture.directory.identity.inode)
        assertEquals(listOf(0u, 80u), capture.target.supplementaryGroups)
        assertEquals("root", capture.target.observedName)
        assertEquals(EnvironmentSource.REQUESTED, capture.environment.last().source)
        assertContentEquals(byteArrayOf(0xff.toByte(), 0x0a), capture.environment.last().value.copyBytes())
        assertEquals(4321u, capture.requester.pid)
        assertEquals(7u, capture.requester.pidVersion)
        assertEquals(501u, capture.requester.realUID)
        assertEquals("EXAMPLE", capture.requester.signing.team)
        assertEquals(AncestryReason.EXITED, capture.ancestry.reason)
        assertContentEquals("/bin/zsh".encodeToByteArray(), capture.ancestry.entries[0].executablePath!!.copyBytes())
        assertContentEquals(ByteArray(32) { 2 }, capture.submission.nonce.copyBytes())
        assertContentEquals(ByteArray(16) { 3 }, capture.submission.callerBinding.copyBytes())
    }
    @Test fun sharedInvalidCapturesFail() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(86, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                CommandCapture(hex(fields.getValue("hex").jsonPrimitive.content), limits)
            }
        }
    }
    @Test fun schemaTwoAndExplicitVersionBinding() {
        val rows = vectors(2)
        assertEquals(13, rows.getValue("valid").jsonArray.size)
        for (row in rows.getValue("valid").jsonArray) {
            val fields = row.jsonObject
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            val capture = CommandCapture(bytes, limits, expectedSchemaVersion = 2u)
            assertEquals(2uL, capture.schemaVersion)
            assertEquals(fields.getValue("inputKind").jsonPrimitive.content.toULong(), capture.input.kind.wireValue)
            assertContentEquals(bytes, capture.canonicalBytes)
            assertFailsWith<CommandCaptureException> { CommandCapture(bytes, limits) }
        }
        for (row in rows.getValue("invalid").jsonArray) {
            val fields = row.jsonObject
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                CommandCapture(hex(fields.getValue("hex").jsonPrimitive.content), limits,
                    expectedSchemaVersion = if (fields.getValue("name").jsonPrimitive.content.startsWith("schema1-")) 1u else 2u)
            }
        }
        assertFailsWith<CommandCaptureException> { CommandCapture(first(), limits, expectedSchemaVersion = 2u) }
        assertFailsWith<CommandCaptureException> { CommandCapture(first(), limits, expectedSchemaVersion = 3u) }
        assertEquals(setOf(1uL, 2uL, 3uL), CommandCapture.supportedSchemaVersions)
    }

    @Test fun boundsAndImmutableSnapshots() {
        val bytes = first()
        val original = bytes.copyOf()
        val capture = CommandCapture(bytes, limits)
        bytes[0] = 0
        capture.canonicalBytes[0] = 0
        capture.arguments[0].copyBytes()[0] = 0
        assertContentEquals(original, capture.canonicalBytes)
        assertContentEquals("printf".encodeToByteArray(), capture.arguments[0].copyBytes())
        assertFailsWith<UnsupportedOperationException> { (capture.arguments as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.environment as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.target.supplementaryGroups as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.ancestry.entries as MutableList).clear() }
        for (bound in listOf(CborLimits(original.size - 1, 16, 1024), CborLimits(8192, 1, 1024), CborLimits(8192, 16, 2))) {
            assertFailsWith<CborException> { CommandCapture(original, bound) }
        }
    }
    @Test fun schemaThreeStreamLayoutAndMalformedBindings() {
        val rows = vectors(3)
        assertEquals(39, rows.getValue("valid").jsonArray.size)
        assertEquals(75, rows.getValue("invalid").jsonArray.size)
        for (row in rows.getValue("valid").jsonArray) {
            val fields = row.jsonObject
            val name = fields.getValue("name").jsonPrimitive.content
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            val capture = CommandCapture(bytes, limits, 3u)
            val layout = checkNotNull(capture.stdioLayout)
            assertContentEquals(bytes, capture.canonicalBytes, name)
            assertEquals(capture.input, layout.input.source, name)
            assertEquals(fields.getValue("ptyMask").jsonPrimitive.content.toUInt(), layout.ptyMask, name)
            val streams = listOf(layout.input, layout.output, layout.error)
            assertEquals(fields.getValue("streamKinds").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.source.kind.wireValue }, name)
            assertEquals(fields.getValue("streamAccess").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.access.wireValue }, name)
            assertEquals(fields.getValue("streamFlags").jsonArray.map { it.jsonPrimitive.content.toULong() }, streams.map { it.flags.wireValue }, name)
            assertEquals(fields.getValue("terminalSession").jsonPrimitive.contentOrNull?.toUInt(), layout.terminal?.sessionID, name)
            assertEquals(fields.getValue("arguments").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.arguments, name)
            assertEquals(fields.getValue("environmentNames").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.environment.map { it.name }, name)
            assertFailsWith<CommandCaptureException>(name) { CommandCapture(bytes, limits) }
            assertFailsWith<CommandCaptureException>(name) { CommandCapture(bytes, limits, 2u) }
        }
        for (row in rows.getValue("invalid").jsonArray) {
            val fields = row.jsonObject
            assertFailsWith<CommandCaptureException>(fields.getValue("name").jsonPrimitive.content) {
                CommandCapture(hex(fields.getValue("hex").jsonPrimitive.content), limits, 3u)
            }
        }
        assertEquals(null, CommandCapture(first(), limits).stdioLayout)
    }

    @Test fun approvedDigestBindsStreamRoutingAndFlags() {
        val rows = vectors(3).getValue("valid").jsonArray
        val contract = RequestContract(RequestKind.COMMAND, 1u, 3u)
        fun issued(name: String): IssuedRequestPayload {
            val row = rows.first { it.jsonObject.getValue("name").jsonPrimitive.content == name }.jsonObject
            return IssuedRequestPayload(contract, ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
                ByteArray(32) { 4 }, emptySet(), 10u, 20u, hex(row.getValue("hex").jsonPrimitive.content),
                listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
        }
        val first = issued("schema3-terminal-mask-0")
        val decoded = IssuedRequestPayload.decode(first.encode(limits), limits, limits, ContractCapabilities(mapOf(contract to emptySet())))
        assertContentEquals(first.canonicalCapture, decoded.canonicalCapture)
        assertEquals(0u, CommandCapture(decoded.canonicalCapture, limits, decoded.contract.schemaVersion).stdioLayout?.ptyMask)
        kotlin.test.assertFalse(first.requestDigest(limits, limits).contentEquals(issued("schema3-terminal-mask-1").requestDigest(limits, limits)))
        kotlin.test.assertFalse(issued("schema3-semantic-flags-0").requestDigest(limits, limits).contentEquals(issued("schema3-semantic-flags-1").requestDigest(limits, limits)))
    }

    @Test fun issuedRequestPreservesCompleteCapture() {
        val bytes = first()
        val contract = RequestContract(RequestKind.COMMAND, 1u, 1u)
        val issued = IssuedRequestPayload(contract, ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
            ByteArray(32) { 4 }, emptySet(), 10u, 20u, bytes,
            listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
        val decoded = IssuedRequestPayload.decode(issued.encode(limits), limits, limits, ContractCapabilities(mapOf(contract to emptySet())))
        assertContentEquals(bytes, CommandCapture(decoded.canonicalCapture, limits).canonicalBytes)
        assertContentEquals(issued.requestDigest(limits, limits), decoded.requestDigest(limits, limits))
    }
}
