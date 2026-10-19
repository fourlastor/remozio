package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class AuditEventMetadataTest {
    private val limits = CborLimits(4096, 8, 128)
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.auditVectors"))).readText()).jsonObject

    @Test fun sharedMetadataVectorsRoundTripWithoutTextOrNestedPayloads() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(87, rows.size)
        for (row in rows) {
            val name = row.jsonObject.getValue("name").jsonPrimitive.content
            val body = hex(row.jsonObject.getValue("hex").jsonPrimitive.content)
            val event = AuditEventMetadata.decode(body, limits)
            assertContentEquals(body, event.encode(limits), name)
            val fields = (DeterministicCbor.decode(body, limits) as CborValue.Fields).values
            assertEquals((0uL..19uL).toSet(), fields.keys)
            assertTrue(fields.values.all { it is CborValue.Unsigned || it is CborValue.Bytes || it == CborValue.Null })
            assertTrue(fields.values.filterIsInstance<CborValue.Bytes>().all { it.size == 16 })
        }
    }

    @Test fun malformedMetadataAndIndependentLimitsFail() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(78, rows.size)
        for (row in rows) {
            assertFailsWith<AuditEventException>(row.jsonObject.getValue("name").jsonPrimitive.content) {
                AuditEventMetadata.decode(hex(row.jsonObject.getValue("hex").jsonPrimitive.content), limits)
            }
        }
        val bytes = hex(vectors().getValue("valid").jsonArray.first().jsonObject.getValue("hex").jsonPrimitive.content)
        assertFailsWith<CborException> { AuditEventMetadata.decode(bytes, CborLimits(bytes.size - 1, 8, 128)) }
        assertFailsWith<CborException> { AuditEventMetadata.decode(bytes + byteArrayOf(0), limits) }
        val record = AuditEventMetadata.decode(bytes, limits)
        assertFailsWith<CborException> { record.encode(CborLimits(bytes.size - 1, 8, 128)) }
    }

    @Test fun actionProjectionKeepsClassesWithoutDurationOrTargetValues() {
        val expected = listOf(AuditActionKind.DECLINE, AuditActionKind.CANCEL_TARGET, AuditActionKind.EXECUTE,
            AuditActionKind.APPROVE_ACCESS, AuditActionKind.UNLOCK_VAULT, AuditActionKind.ALLOW, AuditActionKind.DENY,
            AuditActionKind.ALLOW, AuditActionKind.DENY, AuditActionKind.REMOVE_RULE)
        ActionChoice.entries.zip(expected).forEach { (choice, kind) ->
            assertEquals(kind, AuditActionMetadata.from(CapturedAction(choice, ActionScope.CurrentRequest)).kind)
        }
        val scopes = listOf(ActionScope.CurrentRequest, ActionScope.Session, ActionScope.Timed(1u), ActionScope.Forever)
        val classes = listOf(AuditLifetime.CURRENT_REQUEST, AuditLifetime.SESSION, AuditLifetime.TIMED, AuditLifetime.FOREVER)
        scopes.zip(classes).forEach { (scope, lifetime) ->
            assertEquals(AuditActionMetadata(AuditActionKind.ALLOW, lifetime, AuditTargetScope.DOMAIN),
                AuditActionMetadata.from(CapturedAction(ActionChoice.ALLOW_RULE, scope), AuditTargetScope.DOMAIN))
        }
        assertEquals(AuditActionMetadata.from(CapturedAction(ActionChoice.ALLOW_RULE, ActionScope.Timed(1u))),
            AuditActionMetadata.from(CapturedAction(ActionChoice.ALLOW_RULE, ActionScope.Timed(ULong.MAX_VALUE))))
    }

    @Test fun constructorCopiesAllOpaqueIDsAndReturnsCopies() {
        val id = ByteArray(16) { 1 }
        val event = AuditEventMetadata(id, id, id, id, 1u, id, null, null, AuditEventKind.PHONE_DECISION,
            AuditCategory.COMMAND, null, id, AuditAuthentication.UNKNOWN, AuditOutcome.UNKNOWN,
            AuditReason.UNKNOWN, null, id)
        val before = event.encode(limits)
        id.fill(0)
        listOf(event.eventID, event.macID, event.accountID, event.journalEpoch, event.requestID!!,
            event.decisionPhoneID!!, event.peerDeviceID!!).forEach { it.fill(0) }
        assertContentEquals(before, event.encode(limits))
        assertNotEquals(AuditEventKind.BIOMETRIC_CANCELLED, AuditEventKind.DECISION_REJECTED)
        assertNotEquals(AuditEventKind.DISMISSED, AuditEventKind.CANCELLED)
        assertNotEquals(AuditOutcome.ATTEMPTED, AuditOutcome.VERIFIED_SUCCESS)
    }
}
