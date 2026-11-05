package dev.remozio.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

// Runs on every target, so the iOS Security verifier and the JVM provider see the same positive and negative cases.
class CommonP256Test {
    private val orderHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    private val fieldHex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun scalar(vararg tail: Int) = ByteArray(32).also { bytes ->
        tail.reversed().forEachIndexed { index, value -> bytes[31 - index] = value.toByte() }
    }
    private val one = scalar(1)
    private val vectors = Json.parseToJsonElement(TestVectors.approvalSignatures).jsonArray.map { it.jsonObject }

    @Test fun canonicalIntegersHaveMinimalPositiveEncoding() {
        val cases = mapOf(
            scalar(1) to "3006020101020101",
            scalar(127) to "300602017f020101",
            scalar(128) to "300702020080020101",
            scalar(1, 0) to "300702020100020101",
        )
        for ((value, derHex) in cases) {
            val raw = value + one
            assertContentEquals(hex(derHex), P256SignatureEncoding.toDer(raw))
            assertContentEquals(raw, P256SignatureEncoding.fromDer(hex(derHex)))
        }
        val high = ByteArray(32).also { it[0] = 0x80.toByte() }
        val orderMinusOne = hex(orderHex).also { it[31] = (it[31] - 1).toByte() }
        for (value in listOf(ByteArray(32).also { it[1] = 1 }, ByteArray(32).also { it[0] = 1 }, high, orderMinusOne)) {
            val raw = value + value
            assertContentEquals(raw, P256SignatureEncoding.fromDer(P256SignatureEncoding.toDer(raw)))
        }
    }

    @Test fun malformedDerNeverBecomesWireAuthority() {
        val malformed = listOf(
            "3106020101020101", "3005020101020101", "3007020101020101", "308106020101020101",
            "30800201010201010000", "3006030101020101", "3006020101030101", "3006020180020101",
            "300702020001020101", "3006020100020101", "3006020101020100", "30050200020101",
            "300702810101020101", "3006022101020101", "300702010102010100", "300602010102010100",
            "3026022100" + orderHex + "020101",
        )
        for (value in malformed) {
            assertFailsWith<P256SignatureEncodingException>(value) { P256SignatureEncoding.fromDer(hex(value)) }
        }
        for (size in listOf(0, 1, 7, 73, 4096)) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.fromDer(ByteArray(size)) }
        }
        val valid = hex("3006020101020101")
        for (size in valid.indices) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.fromDer(valid.copyOf(size)) }
        }
    }

    @Test fun invalidRawWidthsAndScalarBoundsAreRejected() {
        for (size in listOf(0, 1, 63, 65, 4096)) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.toDer(ByteArray(size)) }
        }
        for (bad in listOf(ByteArray(32), hex(orderHex), ByteArray(32) { 255.toByte() })) {
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.toDer(bad + one) }
            assertFailsWith<P256SignatureEncodingException> { P256SignatureEncoding.toDer(one + bad) }
        }
    }

    @Test fun everyVectorSignatureVerifiesAndEveryChangeFails() {
        assertTrue(vectors.size >= 10)
        for (row in vectors) {
            val signature = hex(row.getValue("signature").jsonPrimitive.content)
            val key = hex(row.getValue("publicKey").jsonPrimitive.content)
            val input = hex(row.getValue("input").jsonPrimitive.content)
            assertContentEquals(signature, P256SignatureEncoding.fromDer(hex(row.getValue("derSignature").jsonPrimitive.content)))
            assertTrue(P256Verification.verify(signature, key, input))
            assertFalse(P256Verification.verify(signature, key, input + byteArrayOf(0)))
            assertFalse(P256Verification.verify(signature.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }, key, input))
            assertFalse(P256Verification.verify(signature, key.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }, input))
            assertFalse(P256Verification.verify(signature, key.copyOf().also { it[0] = 2 }, input))
            assertFalse(P256Verification.verify(signature, key.copyOf(64), input))
            assertFalse(P256Verification.verify(signature.copyOf(63), key, input))
            assertFalse(P256Verification.verify(hex(orderHex) + signature.copyOfRange(32, 64), key, input))
            assertFalse(P256Verification.verify(signature.copyOfRange(0, 32) + ByteArray(32), key, input))
            // A coordinate at or above p is rejected before any curve arithmetic.
            assertFalse(P256Verification.verify(signature, byteArrayOf(4) + hex(fieldHex) + key.copyOfRange(33, 65), input))
            assertFalse(P256Verification.verify(signature, byteArrayOf(4) + key.copyOfRange(1, 33) + hex(fieldHex), input))
        }
        val first = hex(vectors[0].getValue("publicKey").jsonPrimitive.content)
        val other = hex(vectors.map { it.getValue("publicKey").jsonPrimitive.content }.first { hex(it).contentEquals(first).not() })
                assertFalse(P256Verification.verify(hex(vectors[0].getValue("signature").jsonPrimitive.content), other,
            hex(vectors[0].getValue("input").jsonPrimitive.content)))
        assertEquals(65, hex(vectors[0].getValue("publicKey").jsonPrimitive.content).size)
    }
}
