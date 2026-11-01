package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class PhoneAuditTest {
    private val input = File(checkNotNull(System.getProperty("remozio.phoneAuditVectors")))
    private val limits = CborLimits(16384, 8, 256)
    private fun vectors() = Json.parseToJsonElement(input.readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content

    @Test fun sharedFramesKeepExactBytesAndRoles() {
        val rows = vectors().getValue("valid").jsonArray; assertEquals(32, rows.size)
        for (row in rows) {
            val value = row.jsonObject; val bytes = hex(value.text("hex")); val frame = PhoneAuditFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode(), value.text("name"))
            assertEquals(value.getValue("query").jsonPrimitive.boolean, frame.isQuery)
            assertEquals("PhoneAuditFrame(redacted)", frame.toString())
            if (frame.isQuery) assertTrue(bytes.size <= PhoneAuditFrame.MAXIMUM_QUERY_BYTES)
        }
    }
    @Test fun malformedOuterFramesFailClosed() {
        val rows = vectors().getValue("invalid").jsonArray; assertEquals(89, rows.size)
        for (row in rows) { val value = row.jsonObject; assertFails(value.text("name")) { PhoneAuditFrame.decode(hex(value.text("hex"))) } }
    }
    @Test fun existingSignedPayloadsAreUnchangedAndKeepTheirOwnPurposes() {
        val history = Json.parseToJsonElement(File(input.parentFile, "audit-history-status-v1.json").readText()).jsonObject
        val pages = Json.parseToJsonElement(File(input.parentFile, "audit-batches-v1.json").readText()).jsonObject
        val rows = vectors().getValue("valid").jsonArray.map { it.jsonObject }.filter { "payloadHex" in it }; assertEquals(23, rows.size)
        for (row in rows) {
            val body = hex(row.text("payloadHex")); val signature = hex(row.text("signature")); val key = hex(row.text("publicKey"))
            val original = if (row.text("innerKind") == "history") history else pages
            val source = original.getValue("valid").jsonArray.map { it.jsonObject }.single { it.text("name") == row.text("sourceName") }
            assertEquals(source.text("hex"), row.text("payloadHex")); assertEquals(source.text("signature"), row.text("signature"))
            assertEquals(original.text("publicKey"), row.text("publicKey"))
            val frame = PhoneAuditFrame.decode(hex(row.text("hex"))) as PhoneAuditFrame.Response
            assertContentEquals(body, frame.canonicalPayload.copyBytes()); assertContentEquals(signature, frame.signature.copyBytes())
            if (frame is PhoneAuditFrame.HistoryResponse) {
                assertContentEquals(AuditHistoryStatus.decode(body, limits, limits).queryNonce, frame.queryNonce.copyBytes())
                assertTrue(AuditHistoryStatusSignature.verify(signature, key, 1u, body, limits, limits))
                assertFalse(runCatching { AuditBatchSignature.verify(signature, key, 1u, body, limits, limits) }.getOrDefault(false))
            } else {
                assertContentEquals(AuditBatch.decode(body, limits, limits, 2).queryNonce, frame.queryNonce.copyBytes())
                assertTrue(AuditBatchSignature.verify(signature, key, 1u, body, limits, limits))
                assertFalse(runCatching { AuditHistoryStatusSignature.verify(signature, key, 1u, body, limits, limits) }.getOrDefault(false))
            }
        }
    }
    @Test fun constructorsRejectPartialHistoryAndInvalidIdentifiers() {
        val nonce = ByteArray(32) { 9 }; val epoch = ByteArray(16) { 3 }
        assertFails { PhoneAuditFrame.HistoryQuery(nonce, null, 0u) }
        assertFails { PhoneAuditFrame.HistoryQuery(nonce, epoch, null) }
        assertFails { PhoneAuditFrame.HistoryQuery(byteArrayOf(), null, null) }
        assertFails { PhoneAuditFrame.PageQuery(nonce, ByteArray(15), 0u, 0u) }
        assertFails { PhoneAuditFrame.HistoryResponse(nonce, byteArrayOf(0), ByteArray(63)) }
    }
    @Test fun replyPayloadAndCarrierResourceBounds() {
        val nonce = ByteArray(32) { 9 }; val signature = ByteArray(64)
        val body = ByteArray(PhoneAuditFrame.MAXIMUM_PAYLOAD_BYTES) { 7 }
        val bytes = PhoneAuditFrame.PageResponse(nonce, body, signature).encode()
        assertTrue(bytes.size <= body.size + PhoneAuditFrame.OVERHEAD_BYTES)
        assertContentEquals(bytes, PhoneAuditFrame.decode(bytes).encode())
        assertFails { PhoneAuditFrame.PageResponse(nonce, body + byteArrayOf(7), signature) }
        assertFails { PhoneAuditFrame.decode(ByteArray(PhoneAuditFrame.MAXIMUM_BYTES + 1)) }
        assertFails { PhoneAuditFrame.HistoryResponse(nonce, byteArrayOf(), signature) }
    }
    @Test fun constructorsAndGettersCopyMutableArraysAndRedactDescriptions() {
        val nonce = ByteArray(32) { 9 }; val epoch = ByteArray(16) { 3 }; val body = byteArrayOf(0); val signature = ByteArray(64)
        val frame = PhoneAuditFrame.HistoryResponse(nonce, body, signature); val before = frame.encode()
        val query = PhoneAuditFrame.HistoryQuery(nonce, epoch, 0u); val queryBefore = query.encode()
        nonce.fill(1); epoch.fill(1); body.fill(1); signature.fill(1)
        frame.queryNonce.copyBytes().fill(1); frame.canonicalPayload.copyBytes().fill(1); frame.signature.copyBytes().fill(1)
        query.requestedEpoch!!.copyBytes().fill(1)
        assertContentEquals(before, frame.encode()); assertContentEquals(queryBefore, query.encode())
        assertEquals("PhoneAuditFrame(redacted)", frame.toString()); assertEquals("PhoneAuditFrame(redacted)", query.toString())
    }
    @Test fun opaqueReplyParsingDoesNotEstablishAuditValidity() {
        val bytes = PhoneAuditFrame.HistoryResponse(ByteArray(32) { 9 }, byteArrayOf(0), ByteArray(64)).encode()
        val frame = PhoneAuditFrame.decode(bytes) as PhoneAuditFrame.HistoryResponse
        assertContentEquals(byteArrayOf(0), frame.canonicalPayload.copyBytes())
        assertFails { AuditHistoryStatus.decode(frame.canonicalPayload.copyBytes(), limits, limits) }
    }
}
