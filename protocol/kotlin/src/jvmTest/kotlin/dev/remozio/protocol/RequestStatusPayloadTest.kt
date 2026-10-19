package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class RequestStatusPayloadTest {
    private val limits = CborLimits(2048, 8, 64)
    private val phases = listOf(RequestPhase.QUEUED, RequestPhase.PRESENTED, RequestPhase.AUTHORIZED,
        RequestPhase.EXECUTING, RequestPhase.SUCCEEDED, RequestPhase.FAILED, RequestPhase.UNKNOWN,
        RequestPhase.DECLINED, RequestPhase.CANCELLED, RequestPhase.EXPIRED)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.statusVectors"))).readText()).jsonObject

    @Test fun sharedStatusFieldsAndExactRoundTrips() {
        val vectors = vectors()
        assertEquals(19, vectors.getValue("valid").jsonArray.size)
        assertEquals(RequestPhase.entries.toSet(), phases.toSet())
        for (row in vectors.getValue("valid").jsonArray) {
            val fields = row.jsonObject
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            val status = RequestStatusPayload.decode(bytes, limits)
            val bindings = mapOf(1 to status.macID, 2 to status.accountID, 3 to status.requestID,
                4 to status.requestDigest, 5 to status.challenge, 9 to status.observationID)
            bindings.forEach { (key, value) -> assertContentEquals(hex(vectors.getValue("bindings").jsonObject.getValue(key.toString()).jsonPrimitive.content), value) }
            fun number(key: String): ULong? = fields.getValue(key).let { if (it == JsonNull) null else it.jsonPrimitive.content.toULong() }
            assertEquals(phases[fields.getValue("phase").jsonPrimitive.content.toInt()], status.phase)
            assertEquals(number("reason"), status.reason.tag)
            assertEquals(number("revision"), status.revision)
            assertEquals(number("age"), status.observedAgeMs)
            assertEquals(number("remaining"), status.authorizationRemainingMs)
            assertEquals(number("estimate"), status.estimatedLifetimeMs)
            assertEquals(number("terminal"), status.terminalAgeMs)
            assertEquals(fields.getValue("late").jsonPrimitive.content.toBooleanStrict(), status.lateObservation)
            if (fields.getValue("phone").jsonPrimitive.content.toBooleanStrict()) {
                assertContentEquals(hex(vectors.getValue("bindings").jsonObject.getValue("15").jsonPrimitive.content), status.decisionPhoneID)
            } else assertEquals(null, status.decisionPhoneID)
            assertContentEquals(bytes, status.encode(limits), fields.getValue("name").jsonPrimitive.content)
        }
    }

    @Test fun rejectsUnknownFieldsAndInconsistentStateOrTiming() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(174, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                RequestStatusPayload.decode(hex(fields.getValue("hex").jsonPrimitive.content), limits)
            }
        }
    }

    @Test fun elapsedEstimateAndZeroRemainingDoNotProveExpiry() {
        val row = vectors().getValue("valid").jsonArray.first { it.jsonObject.getValue("name").jsonPrimitive.content == "elapsed-estimate-is-still-pending" }.jsonObject
        val status = RequestStatusPayload.decode(hex(row.getValue("hex").jsonPrimitive.content), limits)
        assertEquals(70_000uL, status.observedAgeMs)
        assertEquals(60_000uL, status.estimatedLifetimeMs)
        assertEquals(0uL, status.authorizationRemainingMs)
        assertFalse(status.phase.isTerminal)
    }

    @Test fun limitsApplyInBothDirections() {
        val bytes = hex(vectors().getValue("valid").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
        val status = RequestStatusPayload.decode(bytes, limits)
        assertContentEquals(bytes, status.encode(CborLimits(bytes.size, 8, 64)))
        val small = CborLimits(bytes.size - 1, 8, 64)
        assertFailsWith<CborException> { status.encode(small) }
        assertFailsWith<CborException> { RequestStatusPayload.decode(bytes, small) }
        assertFailsWith<CborException> { RequestStatusPayload.decode(bytes, CborLimits(2048, 8, 1)) }
    }

    @Test fun constructorCopiesBindingsAndEnforcesInvariants() {
        val id = ByteArray(16) { 1 }; val digest = ByteArray(32) { 2 }
        fun construct(revision: ULong = 1u, phase: RequestPhase = RequestPhase.AUTHORIZED,
            reason: RequestStatusReason = RequestStatusReason.NONE, remaining: ULong? = null,
            estimate: ULong? = 60_000u, terminal: ULong? = null, phone: ByteArray? = id) =
            RequestStatusPayload(id, id, id, digest, digest, revision, phase, reason, id, 1000u,
                remaining, estimate, false, terminal, phone)
        val status = construct()
        val encoded = status.encode(limits)
        id[0] = 9; digest[0] = 9
        listOf(status.macID, status.accountID, status.requestID, status.requestDigest, status.challenge,
            status.observationID, status.decisionPhoneID!!).forEach { it[0] = 8 }
        assertContentEquals(encoded, status.encode(limits))
        assertFailsWith<RequestStatusException> { construct(revision = 0u) }
        assertFailsWith<RequestStatusException> { construct(phase = RequestPhase.QUEUED, remaining = 1u) }
        assertFailsWith<RequestStatusException> { construct(estimate = 0u) }
        assertFailsWith<RequestStatusException> { construct(phase = RequestPhase.EXPIRED, reason = RequestStatusReason.TARGET_TIMED_OUT, terminal = 1001u) }
        assertFailsWith<RequestStatusException> { construct(phone = byteArrayOf()) }
    }

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
