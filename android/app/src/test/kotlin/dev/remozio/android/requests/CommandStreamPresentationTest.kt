package dev.remozio.android.requests

import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CommandCapture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class CommandStreamPresentationTest {
    private val limits = CborLimits(8192, 16, 1024)

    @Test fun retainsDistinctRolesAndEveryCapturedObservationInTheSharedSchemaThreeFixtures() {
        val vectors = Json.parseToJsonElement(File(requireNotNull(System.getProperty("remozio.test.commandStreamVectors"))).readText())
            .jsonObject.getValue("valid").jsonArray
        assertEquals(39, vectors.size)
        for (value in vectors) {
            val vector = value.jsonObject
            val name = vector.getValue("name").jsonPrimitive.content
            val bytes = vector.getValue("hex").jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val capture = CommandCapture(bytes, limits, expectedSchemaVersion = 3u)
            val streams = inspectedCommandStreams(capture)
            assertEquals(listOf(InspectedStreamRole.INPUT, InspectedStreamRole.OUTPUT, InspectedStreamRole.ERROR), streams.map { it.role }, name)
            assertEquals(vector.getValue("streamKinds").jsonArray.map { it.jsonPrimitive.int.toULong() },
                streams.map { it.stream.source.kind.wireValue }, name)
            assertEquals(vector.getValue("streamAccess").jsonArray.map { it.jsonPrimitive.int.toULong() },
                streams.map { it.stream.access.wireValue }, name)
            assertEquals(vector.getValue("streamFlags").jsonArray.map { it.jsonPrimitive.int.toULong() },
                streams.map { it.stream.flags.wireValue }, name)
            val mask = vector.getValue("ptyMask").jsonPrimitive.int
            assertEquals(listOf(mask and 1 != 0, mask and 2 != 0, mask and 4 != 0), streams.map { it.routedToPrivateTerminal }, name)
            val layout = requireNotNull(capture.stdioLayout)
            assertSame(layout.input, streams[0].stream, name)
            assertSame(layout.output, streams[1].stream, name)
            assertSame(layout.error, streams[2].stream, name)
            assertEquals(bytes.toList(), capture.canonicalBytes.toList(), name)
        }
    }

    @Test fun legacyCaptureCannotInventOutputSourcesOrRouting() {
        val capture = CommandCapture(File(requireNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes(), limits)
        assertTrue(inspectedCommandStreams(capture).isEmpty())
    }

    @Test fun advertisesMacAndLinuxInspectableCommandContractsWithoutExtraFeatures() {
        val offers = commandInspectionCapabilities()
        assertEquals(listOf(1uL, 2uL, 3uL, 4uL), offers.map { it.schemaVersion })
        assertTrue(offers.all { it.kind == 0uL && it.wireVersion == 1uL && it.features.isEmpty() })
    }
}
