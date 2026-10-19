package dev.remozio.protocol

import org.junit.Test
import kotlin.test.*

class RequestStatusQueryTest {
    @Test fun sharedCanonicalQueryAndDefensiveCopy() {
        val id = ByteArray(16) { 0xaa.toByte() }
        val query = RequestStatusQuery(id)
        id[0] = 0
        val bytes = query.encode()
        assertEquals("a30001016d726571756573742d73746174650250" + "aa".repeat(16), bytes.joinToString("") { "%02x".format(it) })
        assertEquals(query.requestID, RequestStatusQuery.decode(bytes).requestID)
        assertTrue(bytes.size <= RequestStatusQuery.MAXIMUM_BYTES)
        assertEquals("RequestStatusQuery(redacted)", query.toString())
    }
    @Test fun versionShapeAndBoundsAreStrict() {
        val original = RequestStatusQuery(ByteArray(16)).encode()
        val limits = CborLimits(256, 3, 16)
        val fields = (DeterministicCbor.decode(original, limits) as CborValue.Fields).values
        for (change in listOf(0uL to CborValue.Unsigned(2u), 1uL to CborValue.Text("decision"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(ByteArray(15)), 2uL to CborValue.Bytes(ByteArray(17)), 2uL to CborValue.ArrayValue(emptyList()), 3uL to CborValue.Null)) {
            assertFails { RequestStatusQuery.decode(DeterministicCbor.encode(CborValue.Fields(fields + change), limits)) }
        }
        for (bytes in listOf(byteArrayOf(), original + byteArrayOf(0), ByteArray(65), byteArrayOf(0xa0.toByte()))) {
            assertFails { RequestStatusQuery.decode(bytes) }
        }
        assertFails { RequestStatusQuery(ByteArray(15)) }
    }
}
