package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

class PendingRequestSnapshotFrameTest {
    private fun vectors() = Json.parseToJsonElement(File(System.getProperty("remozio.pendingSnapshotVectors")).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun sharedSnapshotVectorsAndRoles() {
        val values = vectors()
        assertEquals(values.getValue("applicationProtocol").jsonPrimitive.content, PendingRequestSnapshotFrame.APPLICATION_PROTOCOL)
        for (value in values.getValue("valid").jsonArray) {
            val row = value.jsonObject
            val bytes = hex(row.getValue("hex").jsonPrimitive.content)
            val frame = PendingRequestSnapshotFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode())
            assertEquals("PendingRequestSnapshotFrame(redacted)", frame.toString())
            assertContentEquals(ByteArray(32) { it.toByte() }, frame.nonce.copyBytes())
            when (row.getValue("name").jsonPrimitive.content) {
                "query" -> assertIs<PendingRequestSnapshotFrame.Query>(frame).let {
                    assertEquals(128uL, it.maximumFrames); assertEquals(1_048_576uL, it.maximumBytes)
                }
                "item" -> assertIs<PendingRequestSnapshotFrame.Item>(frame).let {
                    assertEquals(0uL, it.ordinal); assertContentEquals(byteArrayOf(1, 2, 3), it.frame.copyBytes())
                }
                "complete" -> assertIs<PendingRequestSnapshotFrame.Complete>(frame).let {
                    assertEquals(1uL, it.frames); assertEquals(3uL, it.bytes)
                }
                "empty" -> assertIs<PendingRequestSnapshotFrame.Complete>(frame).let {
                    assertEquals(0uL, it.frames); assertEquals(0uL, it.bytes)
                }
                "query-retained" -> assertIs<PendingRequestSnapshotFrame.Query>(frame).let {
                    assertEquals(listOf(CborValue.Bytes(ByteArray(16) { 1 }), CborValue.Bytes(ByteArray(16) { 2 })), it.retainedRequestIDs)
                }
                "maximum-query" -> assertIs<PendingRequestSnapshotFrame.Query>(frame)
                "maximum-completion" -> assertIs<PendingRequestSnapshotFrame.Complete>(frame)
                "last-ordinal" -> assertIs<PendingRequestSnapshotFrame.Item>(frame)
                else -> fail("Unknown vector")
            }
        }
    }
    @Test fun malformedOrConfusedSnapshotsFail() {
        for (value in vectors().getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) {
                PendingRequestSnapshotFrame.decode(hex(row.getValue("hex").jsonPrimitive.content))
            }
        }
        assertFails { PendingRequestSnapshotFrame.Query(ByteArray(31), 1u, 1u) }
        assertFails { PendingRequestSnapshotFrame.Item(ByteArray(32), 0u, ByteArray(PendingRequestSnapshotFrame.MAXIMUM_FRAME_BYTES + 1)) }
        assertFails { PendingRequestSnapshotFrame.decode(ByteArray(PendingRequestSnapshotFrame.MAXIMUM_BYTES + 1)) }
    }
    @Test fun byteOwnershipIsDefensive() {
        val nonce = ByteArray(32) { 1 }
        val bytes = byteArrayOf(2)
        val frame = PendingRequestSnapshotFrame.Item(nonce, 0u, bytes)
        nonce[0] = 3; bytes[0] = 4
        assertEquals(1, frame.nonce.copyBytes()[0].toInt())
        assertContentEquals(byteArrayOf(2), frame.frame.copyBytes())
        frame.frame.copyBytes()[0] = 5
        assertContentEquals(byteArrayOf(2), frame.frame.copyBytes())
    }
    @Test fun sharedTransferBoundariesAndPermanentFailure() {
        for (value in vectors().getValue("transfers").jsonArray) {
            val row = value.jsonObject
            val query = assertIs<PendingRequestSnapshotFrame.Query>(PendingRequestSnapshotFrame.decode(hex(row.getValue("query").jsonPrimitive.content)))
            val owner = PendingRequestSnapshotProgress(query)
            val input = row.getValue("incoming").jsonArray.map { hex(it.jsonPrimitive.content) }
            val name = row.getValue("name").jsonPrimitive.content
            if (row.getValue("valid").jsonPrimitive.boolean) {
                input.forEach { owner.accept(it) }
                owner.requireComplete()
                assertTrue(owner.isComplete, name)
            } else {
                assertFails(name) {
                    input.forEach { owner.accept(it) }
                    owner.requireComplete()
                }
                assertFalse(owner.isComplete, name)
                assertFails(name) { owner.accept(PendingRequestSnapshotFrame.Complete(ByteArray(32) { it.toByte() }, 0u, 0u).encode()) }
                assertFails(name) { owner.requireComplete() }
            }
        }
    }
    @Test fun itemsRemainOpaqueUntilTheCallerVerifiesThem() {
        val nonce = ByteArray(32)
        val owner = PendingRequestSnapshotProgress(PendingRequestSnapshotFrame.Query(nonce, 1u, 3u))
        val bytes = byteArrayOf(1, 2, 3)
        assertContentEquals(bytes, owner.accept(PendingRequestSnapshotFrame.Item(nonce, 0u, bytes).encode()))
        assertFalse(owner.isComplete)
    }
    @Test fun retainedRequestLimitCanonicalOrderAndOwnership() {
        fun id(value: Int) = ByteArray(16) { index -> when (index) { 0 -> (value shr 8).toByte(); 1 -> value.toByte(); else -> 0 } }
        val ids = (0 until PendingRequestSnapshotFrame.MAXIMUM_RETAINED_REQUESTS).map(::id)
        val query = PendingRequestSnapshotFrame.Query(ByteArray(32), 4096u, 67_108_864u, ids.reversed())
        val decoded = assertIs<PendingRequestSnapshotFrame.Query>(PendingRequestSnapshotFrame.decode(query.encode()))
        assertEquals(ids.map(CborValue::Bytes), decoded.retainedRequestIDs)
        assertFails { PendingRequestSnapshotFrame.Query(ByteArray(32), 1u, 1u, ids + listOf(id(4096))) }
        ids[0][0] = 9
        assertEquals(0, query.retainedRequestIDs[0].copyBytes()[0].toInt())
        assertFails { (query.retainedRequestIDs as MutableList).clear() }
    }
}
