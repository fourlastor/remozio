package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class SigningInputTest {
    private val limits = CborLimits(1024, 8, 64)

    @Test
    fun sharedVectorsPreserveExactPayloadBytes() {
        val rows = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.signingVectors"))).readText()).jsonArray
        assertEquals(10, rows.size)
        val transcripts = mutableSetOf<List<Byte>>()
        for (row in rows) {
            val fields = row.jsonObject
            fun text(key: String) = fields.getValue(key).jsonPrimitive.content
            val payload = hex(text("payload"))
            val input = SigningInput.make(1u,
                ApprovalMessageType.entries.single { it.tag == text("type").toULong() },
                SigningPurpose.entries.single { it.tag == text("purpose").toULong() },
                payload, limits, limits)
            assertContentEquals(hex(text("input")), input)
            assertTrue(transcripts.add(input.toList()))
            val decoded = DeterministicCbor.decode(input, limits) as CborValue.Fields
            assertContentEquals(payload, (decoded.values.getValue(4u) as CborValue.Bytes).copyBytes())
        }
    }

    @Test
    fun unsupportedVersionsAndCrossPurposeSubstitution() {
        for (version in listOf(0uL, 2uL, ULong.MAX_VALUE)) {
            assertEquals(SigningInputFailure.UNSUPPORTED_VERSION, assertFailsWith<SigningInputException> { make(version = version) }.reason)
        }
        for (type in ApprovalMessageType.entries) {
            for (purpose in SigningPurpose.entries) {
                val allowed = type == ApprovalMessageType.REQUEST && purpose == SigningPurpose.ISSUED_REQUEST ||
                    type == ApprovalMessageType.STATUS && purpose == SigningPurpose.STATUS ||
                    type == ApprovalMessageType.DECISION && purpose in setOf(SigningPurpose.CANCELLATION, SigningPurpose.ONE_TIME_UI, SigningPurpose.BIOMETRIC_AUTHORIZATION)
                if (allowed) continue
                assertEquals(SigningInputFailure.INCOMPATIBLE_PURPOSE,
                    assertFailsWith<SigningInputException> { make(type = type, purpose = purpose) }.reason)
            }
        }
    }

    @Test
    fun invalidPayloadAndIndependentBudgets() {
        for (bytes in listOf("", "a1001800", "a100", "a0a0", "a200000001")) {
            assertFailsWith<CborException> { make(body = hex(bytes)) }
        }
        assertEquals(SigningInputFailure.PAYLOAD_MUST_BE_MAP,
            assertFailsWith<SigningInputException> { make(body = hex("80")) }.reason)
        val tiny = CborLimits(1, 8, 64)
        assertFailsWith<CborException> {
            SigningInput.make(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, hex("a10000"), tiny, limits)
        }
        assertFailsWith<CborException> {
            SigningInput.make(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, hex("a0"), limits, tiny)
        }
    }

    private fun make(version: ULong = 1u, type: ApprovalMessageType = ApprovalMessageType.REQUEST,
                     purpose: SigningPurpose = SigningPurpose.ISSUED_REQUEST, body: ByteArray = hex("a0")) =
        SigningInput.make(version, type, purpose, body, limits, limits)
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
