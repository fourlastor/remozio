package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ApprovalSignatureTest {
    private data class Vector(val type: ApprovalMessageType, val purpose: SigningPurpose, val payload: ByteArray,
                              val publicKey: ByteArray, val signature: ByteArray, val derSignature: ByteArray, val producer: String)

    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.signatureVectors"))).readText()).jsonArray.map {
        val row = it.jsonObject
        fun text(key: String) = row.getValue(key).jsonPrimitive.content
        Vector(ApprovalMessageType.entries.single { type -> type.tag == text("type").toULong() },
            SigningPurpose.entries.single { purpose -> purpose.tag == text("purpose").toULong() },
            hex(text("payload")), hex(text("publicKey")), hex(text("signature")), hex(text("derSignature")), text("producer"))
    }

    private fun verify(row: Vector, signature: ByteArray = row.signature, key: ByteArray = row.publicKey,
                       payload: ByteArray = row.payload, type: ApprovalMessageType = row.type, purpose: SigningPurpose = row.purpose): Boolean {
        val limits = CborLimits(1024, 8, 64)
        return ApprovalSignature.verify(signature, key, 1u, type, purpose, payload, limits, limits)
    }

    @Test
    fun bothNativeProducersVerifyAndChangedContextFails() {
        val rows = vectors()
        assertEquals(20, rows.size)
        assertEquals(setOf("CryptoKit", "Java 21 SunEC"), rows.map { it.producer }.toSet())
        for (row in rows) {
            kotlin.test.assertContentEquals(row.signature, P256SignatureEncoding.fromDer(row.derSignature))
            kotlin.test.assertContentEquals(row.derSignature, P256SignatureEncoding.toDer(row.signature))
            assertTrue(verify(row), row.producer)
            assertFalse(verify(row, payload = hex("a10002")))
            val type = if (row.type == ApprovalMessageType.STATUS) ApprovalMessageType.REQUEST else ApprovalMessageType.STATUS
            val purpose = if (row.type == ApprovalMessageType.STATUS) SigningPurpose.ISSUED_REQUEST else SigningPurpose.STATUS
            assertFalse(verify(row, type = type, purpose = purpose))
            val changed = row.signature.copyOf()
            changed[0] = (changed[0].toInt() xor 1).toByte()
            assertFalse(verify(row, signature = changed))
        }
        assertFalse(verify(rows[0], key = rows[10].publicKey))
        assertFalse(verify(rows[2], purpose = SigningPurpose.ONE_TIME_UI))
    }

    @Test
    fun malformedSignaturesAndPointsFail() {
        val row = vectors().first()
        for (count in listOf(0, 1, 63, 65, 128)) assertFalse(verify(row, signature = ByteArray(count)))
        val order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        for (scalar in listOf(ByteArray(32), order, ByteArray(32) { 0xff.toByte() })) {
            assertFalse(verify(row, signature = scalar + row.signature.copyOfRange(32, 64)))
            assertFalse(verify(row, signature = row.signature.copyOfRange(0, 32) + scalar))
        }
        for (count in listOf(0, 1, 33, 64, 66, 128)) assertFalse(verify(row, key = ByteArray(count) { 4 }))
        val wrongPrefix = row.publicKey.copyOf().apply { this[0] = 2 }
        assertFalse(verify(row, key = wrongPrefix))
        assertFalse(verify(row, key = byteArrayOf(4) + ByteArray(64)))
        assertFalse(verify(row, key = byteArrayOf(4) + ByteArray(64) { 0xff.toByte() }))
    }

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
