package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class AuditHistoryStatusTest {
    private val limits = CborLimits(16384, 8, 256)
    private val descriptorLimits = CborLimits(1024, 4, 64)
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.auditHistoryVectors"))).readText()).jsonObject
    private fun JsonObject.bytes(key: String) = hex(getValue(key).jsonPrimitive.content)
    private fun decode(body: ByteArray) = AuditHistoryStatus.decode(body, limits, descriptorLimits)

    @Test fun sharedResponsesRoundTripAndKeepExplicitReconciliationStates() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(15, rows.size)
        for (value in rows) {
            val row = value.jsonObject; val body = row.bytes("hex"); val status = decode(body)
            assertContentEquals(body, status.encode(limits))
            assertEquals(row.getValue("disposition").jsonPrimitive.content.toULong(), status.disposition.tag)
            assertContentEquals(row.bytes("input"), AuditHistoryStatusSigningInput.make(1u, body, limits, limits))
            status.macID.fill(0); status.accountID.fill(0); status.queryNonce.fill(0); status.requestedEpoch?.fill(0)
            status.current.epoch.fill(0); status.current.previousEpoch?.fill(0); status.current.previousEventDigest?.fill(0); body.fill(0)
            assertContentEquals(row.bytes("hex"), status.encode(limits))
        }
    }
    @Test fun impossibleStatesMalformedDescriptorsAndBoundsFail() {
        val fixture = vectors(); val rows = fixture.getValue("invalid").jsonArray
        assertEquals(61, rows.size)
        for (row in rows) assertFailsWith<IllegalArgumentException>(row.jsonObject.getValue("name").toString()) {
            decode(row.jsonObject.bytes("hex"))
        }
        val body = fixture.getValue("valid").jsonArray.first().jsonObject.bytes("hex")
        assertFails { AuditHistoryStatus.decode(body, CborLimits(body.size - 1, 8, 256), descriptorLimits) }
        assertFails { AuditHistoryStatus.decode(body, limits, CborLimits(1, 4, 64)) }
        assertFails { decode(body + byteArrayOf(0)) }
        assertFails { decode(body).encode(CborLimits(1, 8, 256)) }
    }
    @Test fun signaturesBindStatusAndCannotBeUsedAsBatchOrApproval() {
        val fixture = vectors(); val key = fixture.bytes("publicKey")
        for (value in fixture.getValue("valid").jsonArray) {
            val row = value.jsonObject; val body = row.bytes("hex"); val signature = row.bytes("signature")
            assertTrue(AuditHistoryStatusSignature.verify(signature, key, 1u, body, limits, limits))
            assertFalse(AuditBatchSignature.verify(signature, key, 1u, body, limits, limits))
            assertFalse(ApprovalSignature.verify(signature, key, 1u, ApprovalMessageType.STATUS,
                SigningPurpose.STATUS, body, limits, limits))
            val f = (DeterministicCbor.decode(body, limits) as CborValue.Fields).values
            for (field in 1uL..12uL) {
                val altered = DeterministicCbor.encode(CborValue.Fields(f + (field to CborValue.Text("altered"))), limits)
                assertFalse(AuditHistoryStatusSignature.verify(signature, key, 1u, altered, limits, limits))
            }
            assertFails { AuditHistoryStatusSignature.verify(signature, key, 2u, body, limits, limits) }
            assertFails { AuditHistoryStatusSigningInput.make(1u, body, limits, CborLimits(1, 8, 256)) }
        }
    }
}
