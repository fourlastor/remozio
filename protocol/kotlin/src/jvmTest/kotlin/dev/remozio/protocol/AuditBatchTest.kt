package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class AuditBatchTest {
    private val limits = CborLimits(16384, 8, 256)
    private val recordLimits = CborLimits(1024, 4, 64)
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.auditBatchVectors"))).readText()).jsonObject
    private fun JsonObject.bytes(key: String) = hex(getValue(key).jsonPrimitive.content)
    private fun decode(body: ByteArray) = AuditBatch.decode(body, limits, recordLimits, 2)

    @Test fun sharedPagesHaveExactBytesAndExplicitBoundaries() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(8, rows.size)
        for (value in rows) {
            val row = value.jsonObject; val body = row.bytes("hex"); val batch = decode(body)
            assertContentEquals(body, batch.encode(limits))
            assertEquals(row.getValue("nextAfter").jsonPrimitive.content.toULong(), batch.nextAfter)
            assertEquals(row.getValue("hasMore").jsonPrimitive.boolean, batch.hasMore)
            assertEquals(row.getValue("retentionGap").jsonPrimitive.boolean, batch.retentionGap)
            assertContentEquals(row.bytes("input"), AuditBatchSigningInput.make(1u, body, limits, limits))
            batch.macID.fill(0); batch.accountID.fill(0); batch.journalEpoch.fill(0); batch.queryNonce.fill(0); body.fill(0)
            assertContentEquals(row.bytes("hex"), batch.encode(limits))
        }
    }

    @Test fun malformedPagesAndIndependentBoundsFail() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(39, rows.size)
        for (row in rows) assertFailsWith<IllegalArgumentException>(row.jsonObject.getValue("name").toString()) {
            decode(row.jsonObject.bytes("hex"))
        }
        val body = vectors().getValue("valid").jsonArray.first().jsonObject.bytes("hex")
        assertFails { AuditBatch.decode(body, limits, recordLimits, 1) }
        assertFails { AuditBatch.decode(body, limits, recordLimits, 0) }
        assertFails { AuditBatch.decode(body, CborLimits(body.size - 1, 8, 256), recordLimits, 2) }
        assertFails { AuditBatch.decode(body, limits, CborLimits(1, 4, 64), 2) }
        assertFails { decode(body + byteArrayOf(0)) }
        assertFails { decode(body).encode(CborLimits(body.size - 1, 8, 256)) }
    }

    @Test fun signaturesBindEveryByteAndCannotCrossApprovalDomain() {
        val fixture = vectors(); val key = fixture.bytes("publicKey")
        for (rowValue in fixture.getValue("valid").jsonArray) {
            val row = rowValue.jsonObject; val body = row.bytes("hex"); val signature = row.bytes("signature")
            assertTrue(AuditBatchSignature.verify(signature, key, 1u, body, limits, limits))
            assertFalse(ApprovalSignature.verify(signature, key, 1u, ApprovalMessageType.REQUEST,
                SigningPurpose.ISSUED_REQUEST, body, limits, limits))
            val fields = (DeterministicCbor.decode(body, limits) as CborValue.Fields).values
            for (field in 1uL..8uL) {
                val changed = when (val old = fields.getValue(field)) {
                    is CborValue.Bytes -> CborValue.Bytes(old.copyBytes().apply { this[0] = (this[0].toInt() xor 1).toByte() })
                    is CborValue.Unsigned -> CborValue.Unsigned(old.value xor 1uL)
                    else -> error("Unexpected field")
                }
                val altered = DeterministicCbor.encode(CborValue.Fields(fields + (field to changed)), limits)
                assertFalse(AuditBatchSignature.verify(signature, key, 1u, altered, limits, limits))
            }
            assertFalse(AuditBatchSignature.verify(signature.copyOf(63), key, 1u, body, limits, limits))
            assertFalse(AuditBatchSignature.verify(signature, ByteArray(65), 1u, body, limits, limits))
            assertFails { AuditBatchSignature.verify(signature, key, 2u, body, limits, limits) }
            assertFails { AuditBatchSigningInput.make(1u, body, limits, CborLimits(1, 8, 256)) }
        }
    }
}
