package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class RoutingAwayTest {
    private val limits = CborLimits(1024, 8, 64)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.routingVectors"))).readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun verify(signature: ByteArray, key: ByteArray, payload: ByteArray) = RoutingAwaySignature.verify(signature, key, 1u, payload, limits, limits)

    @Test fun sharedFieldsRoundTripAndRetainUnsignedBoundaries() {
        val rows = vectors().getValue("valid").jsonArray; assertEquals(3, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val value = RoutingAwayControl.decode(bytes, limits)
            assertContentEquals(bytes, value.encode(limits)); assertEquals(f.text("revision").toULong(), value.expectedRevision)
            assertEquals(f.text("issued").toULong(), value.issuedAtUnixMillis); assertEquals(f.text("expires").toULong(), value.expiresAtUnixMillis)
            listOf(value.macID, value.accountID, value.phoneID, value.enrollmentEpoch, value.operationID, value.challenge, value.keyID)
                .forEachIndexed { i, field -> assertContentEquals(ByteArray(if (i == 5) 32 else 16) { (i + 16).toByte() }, field) }
        }
    }

    @Test fun malformedAndSignedForbiddenModesAreRejected() {
        val vectors = vectors(); val rows = vectors.getValue("invalid").jsonArray; assertEquals(87, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex"))
            assertFailsWith<IllegalArgumentException>(f.text("name")) { RoutingAwayControl.decode(bytes, limits) }
            assertFailsWith<IllegalArgumentException>(f.text("name")) { RoutingAwaySigningInput.make(1u, bytes, limits, limits) }
            if ("signature" in f) {
                val signature = hex(f.text("signature")); val key = hex(vectors.text("publicKey"))
                assertTrue(P256Verification.verify(signature, key, hex(f.text("signingInput"))))
                assertFailsWith<RoutingControlException> { verify(signature, key, bytes) }
            }
        }
    }

    @Test fun sharedSignaturesSeparateKeysPurposesTypesVersionsAndDomains() {
        val vectors = vectors()
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val signature = hex(f.text("signature")); val key = hex(vectors.text("publicKey"))
            assertContentEquals(hex(f.text("signingInput")), RoutingAwaySigningInput.make(1u, bytes, limits, limits))
            assertTrue(verify(signature, key, bytes)); assertFalse(verify(signature, hex(vectors.text("otherPublicKey")), bytes))
            for (wrong in listOf("wrongPurposeSignature", "wrongTypeSignature", "wrongVersionSignature", "approvalSignature", "gatewaySignature")) {
                assertFalse(verify(hex(f.text(wrong)), key, bytes))
            }
            assertFalse(verify(byteArrayOf(0), key, bytes)); assertFalse(verify(signature, byteArrayOf(0), bytes))
        }
    }

    @Test fun signatureBindsEveryMutableControlField() {
        val vectors = vectors(); val row = vectors.getValue("valid").jsonArray[0].jsonObject
        val original = (DeterministicCbor.decode(hex(row.text("hex")), limits) as CborValue.Fields).values
        for (key in 1uL..10uL) {
            val changed = when (val value = original.getValue(key)) {
                is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() })
                is CborValue.Unsigned -> CborValue.Unsigned(value.value + 1u)
                else -> error("Unexpected fixture")
            }
            val bytes = DeterministicCbor.encode(CborValue.Fields(original + (key to changed)), limits)
            assertFalse(verify(hex(row.text("signature")), hex(vectors.text("publicKey")), bytes))
        }
    }

    @Test fun resourceAndVersionBounds() {
        val row = vectors().getValue("valid").jsonArray[0].jsonObject; val bytes = hex(row.text("hex"))
        assertContentEquals(bytes, RoutingAwayControl.decode(bytes, CborLimits(bytes.size, 8, 64)).encode(limits))
        for (bounds in listOf(CborLimits(bytes.size - 1, 8, 64), CborLimits(1024, 1, 2))) {
            assertFailsWith<CborException> { RoutingAwayControl.decode(bytes, bounds) }
            assertFailsWith<CborException> { RoutingAwaySigningInput.make(1u, bytes, bounds, limits) }
        }
        for (version in listOf(0uL, 2uL, ULong.MAX_VALUE)) {
            assertFailsWith<SigningInputException> { RoutingAwaySigningInput.make(version, bytes, limits, limits) }
        }
        val short = CborLimits(hex(row.text("signingInput")).size - 1, 8, 64)
        assertFailsWith<CborException> { RoutingAwaySigningInput.make(1u, bytes, limits, short) }
    }

    @Test fun constructorsAndGettersCopyArraysAndDescriptionsRedact() {
        val row = vectors().getValue("valid").jsonArray[0].jsonObject
        val original = RoutingAwayControl.decode(hex(row.text("hex")), limits)
        val fields = listOf(original.macID, original.accountID, original.phoneID, original.enrollmentEpoch,
            original.operationID, original.challenge, original.keyID)
        fun copy(values: List<ByteArray>) = RoutingAwayControl(values[0], values[1], values[2], values[3], values[4], values[5], values[6],
            original.expectedRevision, original.issuedAtUnixMillis, original.expiresAtUnixMillis)
        val value = copy(fields)
        fields.forEach { it[0] = 0 }
        listOf(value.macID, value.accountID, value.phoneID, value.enrollmentEpoch, value.operationID, value.challenge, value.keyID).forEach { it[0] = 0 }
        assertContentEquals(original.encode(limits), value.encode(limits))
        for (index in fields.indices) {
            val invalid = fields.toMutableList(); invalid[index] = byteArrayOf()
            assertFailsWith<RoutingControlException> { copy(invalid) }
        }
        assertEquals("RoutingAwayControl(redacted)", value.toString())
    }
}
