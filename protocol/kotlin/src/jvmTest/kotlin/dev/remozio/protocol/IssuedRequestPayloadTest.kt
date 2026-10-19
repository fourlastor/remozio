package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class IssuedRequestPayloadTest {
    private val limits = CborLimits(2048, 8, 128)
    private val kinds = listOf(RequestKind.COMMAND, RequestKind.ONE_PASSWORD_ACCESS, RequestKind.ONE_PASSWORD_UNLOCK, RequestKind.LITTLE_SNITCH)
    private val choices = listOf(ActionChoice.DECLINE, ActionChoice.CANCEL_TARGET, ActionChoice.EXECUTE,
        ActionChoice.APPROVE_ACCESS, ActionChoice.UNLOCK_VAULT, ActionChoice.ALLOW_ONCE, ActionChoice.DENY_ONCE,
        ActionChoice.ALLOW_RULE, ActionChoice.DENY_RULE, ActionChoice.REMOVE_RULE)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.requestVectors"))).readText()).jsonObject
    private fun capabilities(features: Set<ULong> = setOf(1u, 2u)) = ContractCapabilities(kinds.associate { RequestContract(it, 1u, 1u) to features })
    private fun decode(bytes: ByteArray, features: Set<ULong> = setOf(1u, 2u)) = IssuedRequestPayload.decode(bytes, limits, limits, capabilities(features))

    @Test
    fun sharedBodiesDigestsAndChoiceOrder() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(9, rows.size)
        assertEquals(RequestKind.entries.toSet(), kinds.toSet())
        for (row in rows) {
            val fields = row.jsonObject
            fun text(name: String) = fields.getValue(name).jsonPrimitive.content
            val bytes = hex(text("hex"))
            val payload = decode(bytes)
            assertEquals(kinds[text("kind").toInt()], payload.contract.requestKind)
            assertContentEquals(ByteArray(16) { it.toByte() }, payload.macID)
            assertContentEquals(ByteArray(16) { (it + 16).toByte() }, payload.accountID)
            assertContentEquals(ByteArray(16) { (it + 32).toByte() }, payload.requestID)
            assertContentEquals(ByteArray(32) { it.toByte() }, payload.challenge)
            assertContentEquals(hex(text("capture")), payload.canonicalCapture)
            assertContentEquals(hex(text("captureDigest")), payload.captureDigest)
            assertEquals(fields.getValue("choices").jsonArray.map { choices[it.jsonPrimitive.content.toInt()] }, payload.permittedActions.map { it.choice })
            assertContentEquals(bytes, payload.encode(limits))
            assertContentEquals(hex(text("requestDigest")), payload.requestDigest(limits, limits))
        }
    }

    @Test
    fun rejectsMalformedUnsupportedAndDigestMismatch() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(58, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                decode(hex(fields.getValue("hex").jsonPrimitive.content))
            }
        }
        val bytes = hex(vectors().getValue("valid").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
        assertEquals(IssuedRequestFailure.UNSUPPORTED_FEATURES, assertFailsWith<IssuedRequestException> { decode(bytes, setOf(1u)) }.reason)
        assertEquals(IssuedRequestFailure.UNSUPPORTED_CONTRACT, assertFailsWith<IssuedRequestException> {
            IssuedRequestPayload.decode(bytes, limits, limits, ContractCapabilities(emptyMap()))
        }.reason)
    }

    @Test
    fun bodyCaptureAndSigningBudgetsStayIndependent() {
        val bytes = hex(vectors().getValue("valid").jsonArray[1].jsonObject.getValue("hex").jsonPrimitive.content)
        val payload = decode(bytes)
        val smallBody = CborLimits(bytes.size - 1, 8, 128)
        val smallCapture = CborLimits(payload.canonicalCapture.size - 1, 8, 128)
        val smallSignature = CborLimits(bytes.size, 8, 128)
        assertFailsWith<CborException> { payload.encode(smallBody) }
        assertFailsWith<CborException> { IssuedRequestPayload.decode(bytes, smallBody, limits, capabilities()) }
        assertFailsWith<CborException> { IssuedRequestPayload.decode(bytes, limits, smallCapture, capabilities()) }
        assertFailsWith<CborException> { payload.requestDigest(limits, smallSignature) }
        assertContentEquals(bytes, payload.encode(CborLimits(bytes.size, 8, 128)))
    }

    @Test
    fun constructionPreservesSnapshotsAndValidatesActions() {
        val id = ByteArray(16) { 1 }
        val capture = hex("a0")
        val features = mutableSetOf(2uL, 1uL)
        val actions = mutableListOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest), CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest))
        val payload = make(id, capture, features, actions)
        id[0] = 9; capture[0] = 0x80.toByte(); features.remove(1u); actions.reverse()
        payload.macID[0] = 9; payload.canonicalCapture[0] = 0x80.toByte()
        assertEquals(1.toByte(), payload.macID[0])
        assertContentEquals(hex("a0"), payload.canonicalCapture)
        assertEquals(setOf(1uL, 2uL), payload.requiredFeatures)
        assertEquals(ActionChoice.EXECUTE, payload.permittedActions.first().choice)
        assertFailsWith<IssuedRequestException> { make(capture = capture) }
        assertFailsWith<IssuedRequestException> { make(actions = emptyList()) }
        assertFailsWith<IssuedRequestException> { make(actions = listOf(actions[0], actions[0])) }
        assertFailsWith<IssuedRequestException> { make(actions = listOf(CapturedAction(ActionChoice.ALLOW_ONCE, ActionScope.CurrentRequest))) }
        assertFailsWith<IssuedRequestException> { make(wire = 2u) }
    }

    @Test
    fun completeDigestChangesWithRequestBindings() {
        val vector = vectors().getValue("valid").jsonArray[1].jsonObject
        val bytes = hex(vector.getValue("hex").jsonPrimitive.content)
        val baseline = hex(vector.getValue("requestDigest").jsonPrimitive.content).toList()
        val fields = (DeterministicCbor.decode(bytes, limits) as CborValue.Fields).values
        fun changed(values: Map<ULong, CborValue>) = decode(DeterministicCbor.encode(CborValue.Fields(values), limits)).requestDigest(limits, limits).toList()
        for (key in 1uL..4uL) {
            val value = (fields.getValue(key) as CborValue.Bytes).copyBytes()
            value[0] = (value[0].toInt() xor 1).toByte()
            assertNotEquals(baseline, changed(fields + (key to CborValue.Bytes(value))))
        }
        for (key in listOf(8uL, 9uL)) {
            val value = (fields.getValue(key) as CborValue.Unsigned).value
            assertNotEquals(baseline, changed(fields + (key to CborValue.Unsigned(value + 1u))))
        }
        assertNotEquals(baseline, changed(fields + (7uL to CborValue.ArrayValue(listOf(CborValue.Unsigned(1u))))))
        val actions = (fields.getValue(12u) as CborValue.ArrayValue).values
        assertNotEquals(baseline, changed(fields + (12uL to CborValue.ArrayValue(actions.reversed()))))
    }

    private fun make(id: ByteArray = ByteArray(16) { 1 }, capture: ByteArray = hex("a0"), features: Set<ULong> = setOf(1u, 2u),
                     actions: List<CapturedAction> = listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), wire: ULong = 1u) =
        IssuedRequestPayload(RequestContract(RequestKind.COMMAND, wire, 1u), id, id, id, ByteArray(32) { 2 }, features,
            1000u, 61000u, capture, actions, limits, limits)
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
