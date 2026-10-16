package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

class PairingReceiptFrameTest {
    private fun vectors() = Json.parseToJsonElement(File(System.getProperty("remozio.pairingReceiptVectors")).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun sharedRecoveryVectorsAndMessageRoles() {
        val values = vectors()
        assertEquals(values.getValue("applicationProtocol").jsonPrimitive.content, PairingReceiptFrame.APPLICATION_PROTOCOL)
        for (value in values.getValue("valid").jsonArray) {
            val row = value.jsonObject
            val bytes = hex(row.getValue("hex").jsonPrimitive.content)
            val frame = PairingReceiptFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode())
            assertEquals("PairingReceiptFrame(redacted)", frame.toString())
            when (row.getValue("name").jsonPrimitive.content) {
                "query" -> assertContentEquals(ByteArray(16) { it.toByte() }, assertIs<PairingReceiptFrame.Query>(frame).setupID.copyBytes())
                "receipt" -> {
                    val reply = assertIs<PairingReceiptFrame.Response>(frame)
                    assertContentEquals(ByteArray(16) { it.toByte() }, reply.setupID.copyBytes())
                    assertContentEquals(ByteArray(64) { it.toByte() }, assertNotNull(reply.signature).copyBytes())
                }
                "unavailable" -> {
                    val reply = assertIs<PairingReceiptFrame.Response>(frame)
                    assertContentEquals(ByteArray(16) { it.toByte() }, reply.setupID.copyBytes())
                    assertNull(reply.signature)
                }
                else -> fail("Unknown vector")
            }
        }
    }
    @Test fun malformedAndConfusedRecoveryMessagesFail() {
        for (value in vectors().getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) {
                PairingReceiptFrame.decode(hex(row.getValue("hex").jsonPrimitive.content))
            }
        }
        assertFails { PairingReceiptFrame.decode(ByteArray(PairingReceiptFrame.MAXIMUM_BYTES + 1)) }
        assertFails { PairingReceiptFrame.Query(ByteArray(15)) }
        assertFails { PairingReceiptFrame.Response(ByteArray(16), ByteArray(63)) }
    }
}
