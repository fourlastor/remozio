package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class DecisionPayloadTest {
    private val limits = CborLimits(1024, 8, 64)
    private val choices = listOf(ActionChoice.DECLINE, ActionChoice.CANCEL_TARGET, ActionChoice.EXECUTE,
        ActionChoice.APPROVE_ACCESS, ActionChoice.UNLOCK_VAULT, ActionChoice.ALLOW_ONCE, ActionChoice.DENY_ONCE,
        ActionChoice.ALLOW_RULE, ActionChoice.DENY_RULE, ActionChoice.REMOVE_RULE)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.decisionVectors"))).readText()).jsonObject

    @Test
    fun sharedCanonicalDecisionsAndExactBindings() {
        val vectors = vectors()
        val rows = vectors.getValue("valid").jsonArray
        assertEquals(13, rows.size)
        assertEquals(ActionChoice.entries.toSet(), choices.toSet())
        for (row in rows) {
            val fields = row.jsonObject
            val encoded = hex(fields.getValue("hex").jsonPrimitive.content)
            val payload = DecisionPayload.decode(encoded, limits)
            val actual = listOf(payload.macID, payload.accountID, payload.requestID, payload.requestDigest,
                payload.challenge, payload.phoneID, payload.keyID)
            actual.forEachIndexed { index, bytes ->
                assertContentEquals(hex(vectors.getValue("bindings").jsonObject.getValue((index + 1).toString()).jsonPrimitive.content), bytes)
            }
            assertEquals(choices[fields.getValue("choice").jsonPrimitive.content.toInt()], payload.action.choice)
            val scope = when (fields.getValue("scope").jsonPrimitive.content.toInt()) {
                0 -> ActionScope.CurrentRequest
                1 -> ActionScope.Session
                2 -> ActionScope.Timed(fields.getValue("seconds").jsonPrimitive.content.toULong())
                else -> ActionScope.Forever
            }
            assertEquals(scope, payload.action.scope)
            assertContentEquals(encoded, payload.encode(limits))
        }
    }

    @Test
    fun rejectsMalformedAndUnknownFields() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(48, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                DecisionPayload.decode(hex(fields.getValue("hex").jsonPrimitive.content), limits)
            }
        }
    }

    @Test
    fun limitsApplyToPayloadInBothDirections() {
        val bytes = hex(vectors().getValue("valid").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
        val payload = DecisionPayload.decode(bytes, limits)
        assertContentEquals(bytes, payload.encode(CborLimits(bytes.size, 8, 64)))
        val small = CborLimits(bytes.size - 1, 8, 64)
        assertFailsWith<CborException> { payload.encode(small) }
        assertFailsWith<CborException> { DecisionPayload.decode(bytes, small) }
    }

    @Test
    fun constructionCopiesByteArraysAndRejectsInvalidLengths() {
        val id = ByteArray(16) { 1 }
        val digest = ByteArray(32) { 2 }
        val action = CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)
        val payload = DecisionPayload(id, id, id, digest, digest, id, id, action)
        id[0] = 9
        digest[0] = 9
        payload.macID[0] = 9
        payload.requestDigest[0] = 9
        assertEquals(1.toByte(), payload.macID[0])
        assertEquals(2.toByte(), payload.requestDigest[0])
        assertFailsWith<DecisionPayloadException> { DecisionPayload(byteArrayOf(), id, id, digest, digest, id, id, action) }
        assertFailsWith<DecisionPayloadException> {
            DecisionPayload(id, id, id, digest, digest, id, id, CapturedAction(ActionChoice.ALLOW_RULE, ActionScope.Timed(0u)))
        }
    }

    @Test
    fun parsingDoesNotReplaceRetainedActionPolicy() {
        val id = ByteArray(16) { 1 }
        val digest = ByteArray(32) { 2 }
        val action = CapturedAction(ActionChoice.ALLOW_RULE, ActionScope.CurrentRequest)
        val payload = DecisionPayload(id, id, id, digest, digest, id, id, action)
        val decoded = DecisionPayload.decode(payload.encode(limits), limits)
        assertFailsWith<ActionPolicyException> { ActionPolicy.requirement(decoded.action, RequestKind.LITTLE_SNITCH, setOf(action)) }
    }

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
