package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class GatewayRecipientTest {
    private val limits = CborLimits(2048, 8, 128)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.gatewayRecipientVectors"))).readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun kind(row: JsonObject) = if (row.text("kind") == "2") GatewayRecipientKind.ACTIVATION else GatewayRecipientKind.PHONE_REVOCATION
    private fun roundTrip(bytes: ByteArray, kind: GatewayRecipientKind, bounds: CborLimits): ByteArray = when (kind) {
        GatewayRecipientKind.ACTIVATION -> GatewayMappingActivation.decode(bytes, bounds).encode(bounds)
        GatewayRecipientKind.PHONE_REVOCATION -> GatewayPhoneRevocation.decode(bytes, bounds).encode(bounds)
    }

    @Test fun sharedControlsRetainEveryBindingAndUnsignedBoundary() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(4, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex"))
            assertContentEquals(bytes, roundTrip(bytes, kind(f), limits))
            val revision: ULong; val issued: ULong; val expires: ULong; val operation: ByteArray; val fields: List<ByteArray>
            if (kind(f) == GatewayRecipientKind.ACTIVATION) {
                val value = GatewayMappingActivation.decode(bytes, limits); val b = value.binding
                revision = value.revision; issued = value.issuedAtUnixMillis; expires = value.expiresAtUnixMillis; operation = value.operationID
                fields = listOf(b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch, b.phoneID, b.enrollmentEpoch,
                    b.candidateID, b.tokenDigest, b.challenge, b.enrollmentTag)
            } else {
                val value = GatewayPhoneRevocation.decode(bytes, limits); val b = value.binding
                revision = value.revision; issued = value.issuedAtUnixMillis; expires = value.expiresAtUnixMillis; operation = value.operationID
                fields = listOf(b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch, b.phoneID, b.enrollmentEpoch)
            }
            assertEquals(f.text("revision").toULong(), revision); assertEquals(f.text("issued").toULong(), issued)
            assertEquals(f.text("expires").toULong(), expires); assertContentEquals(ByteArray(16) { 0x56 }, operation)
            fields.forEachIndexed { i, field -> assertContentEquals(ByteArray(if (i < 8) 16 else 32) { (i + 16).toByte() }, field) }
        }
    }

    @Test fun sharedMalformedControlsFailClosed() {
        val rows = vectors().getValue("invalid").jsonArray; assertEquals(134, rows.size)
        for (row in rows) {
            val f = row.jsonObject
            assertFailsWith<IllegalArgumentException>(f.text("name")) { roundTrip(hex(f.text("hex")), kind(f), limits) }
        }
    }

    @Test fun sharedSignaturesSeparateKeysKindsPurposesAndDomains() {
        val vectors = vectors()
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val kind = kind(f)
            assertContentEquals(hex(f.text("signingInput")), GatewayRecipientSigningInput.make(1u, kind, bytes, limits, limits))
            fun verify(signature: ByteArray, key: ByteArray = hex(vectors.text("publicKey"))) =
                GatewayRecipientSignature.verify(signature, key, 1u, kind, bytes, limits, limits)
            assertTrue(verify(hex(f.text("signature"))))
            assertFalse(verify(hex(f.text("signature")), hex(vectors.text("otherPublicKey"))))
            for (signature in listOf("wrongPurposeSignature", "wrongTypeSignature", "probeSignature", "approvalSignature")) {
                assertFalse(verify(hex(f.text(signature))))
            }
            assertFalse(verify(byteArrayOf(0))); assertFalse(verify(hex(f.text("signature")), byteArrayOf(0)))
        }
    }

    @Test fun signaturesBindEveryIdentityAndControlField() {
        val vectors = vectors()
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; if (!f.text("name").endsWith("ordinary")) continue
            val original = (DeterministicCbor.decode(hex(f.text("hex")), limits) as CborValue.Fields).values
            val binding = (original.getValue(1u) as CborValue.Fields).values
            val mutations = mutableListOf<Map<ULong, CborValue>>()
            for (key in binding.keys) {
                val bytes = (binding.getValue(key) as CborValue.Bytes).copyBytes()
                bytes[0] = (bytes[0].toInt() xor 1).toByte()
                mutations += original + (1uL to CborValue.Fields(binding + (key to CborValue.Bytes(bytes))))
            }
            for (key in 2uL..5uL) {
                val changed = when (val value = original.getValue(key)) {
                    is CborValue.Unsigned -> CborValue.Unsigned(value.value + 1u)
                    is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() })
                    else -> error("Unexpected fixture")
                }
                mutations += original + (key to changed)
            }
            for (changed in mutations) {
                assertFalse(GatewayRecipientSignature.verify(hex(f.text("signature")), hex(vectors.text("publicKey")), 1u,
                    kind(f), DeterministicCbor.encode(CborValue.Fields(changed), limits), limits, limits))
            }
        }
    }

    @Test fun boundsVersionsAndOtherMessageShapesFail() {
        for (row in vectors().getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val kind = kind(f)
            assertContentEquals(bytes, roundTrip(bytes, kind, CborLimits(bytes.size, 8, 128)))
            for (bounds in listOf(CborLimits(bytes.size - 1, 8, 128), CborLimits(2048, 1, 128), CborLimits(2048, 8, 2))) {
                assertFailsWith<CborException> { roundTrip(bytes, kind, bounds) }
                assertFailsWith<CborException> { GatewayRecipientSigningInput.make(1u, kind, bytes, bounds, limits) }
            }
            val short = CborLimits(hex(f.text("signingInput")).size - 1, 8, 128)
            assertFailsWith<CborException> { GatewayRecipientSigningInput.make(1u, kind, bytes, limits, short) }
            for (version in listOf(0uL, 2uL, ULong.MAX_VALUE)) {
                assertFailsWith<SigningInputException> { GatewayRecipientSigningInput.make(version, kind, bytes, limits, limits) }
            }
            val other = if (kind == GatewayRecipientKind.ACTIVATION) GatewayRecipientKind.PHONE_REVOCATION else GatewayRecipientKind.ACTIVATION
            assertFailsWith<GatewayTokenException> { GatewayRecipientSigningInput.make(1u, other, bytes, limits, limits) }
            assertFailsWith<GatewayTokenException> { GatewayTokenCandidate.decode(bytes, limits) }
            assertFailsWith<GatewayTokenException> { GatewayTokenProof.decode(bytes, limits) }
            val fields = (DeterministicCbor.decode(bytes, limits) as CborValue.Fields).values - 6uL
            val untyped = DeterministicCbor.encode(CborValue.Fields(fields), limits)
            assertFailsWith<GatewayTokenException> { GatewayRecipientSigningInput.make(1u, kind, untyped, limits, limits) }
        }
    }

    @Test fun constructorsAndGettersCopyArraysAndDescriptionsRedact() {
        val rows = vectors().getValue("valid").jsonArray
        val activation = GatewayMappingActivation.decode(hex(rows[0].jsonObject.text("hex")), limits)
        val revocation = GatewayPhoneRevocation.decode(hex(rows[2].jsonObject.text("hex")), limits)
        val b = revocation.binding
        val fields = listOf(b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch, b.phoneID, b.enrollmentEpoch)
        fun binding(v: List<ByteArray>) = GatewayPhoneEpochBinding(v[0], v[1], v[2], v[3], v[4], v[5], v[6])
        val copy = binding(fields); val hash = copy.hashCode()
        fields.forEach { it[0] = 0 }; copy.ownerID[0] = 0
        assertEquals(b, copy); assertEquals(hash, copy.hashCode()); assertNotEquals(b, binding(fields))
        for (i in fields.indices) {
            val invalid = fields.toMutableList(); invalid[i] = byteArrayOf()
            assertFailsWith<GatewayTokenException> { binding(invalid) }
        }
        val operation = activation.operationID
        val activationCopy = GatewayMappingActivation(activation.binding, activation.revision, operation, activation.issuedAtUnixMillis, activation.expiresAtUnixMillis)
        val revocationCopy = GatewayPhoneRevocation(b, revocation.revision, operation, revocation.issuedAtUnixMillis, revocation.expiresAtUnixMillis)
        operation[0] = 0; activationCopy.operationID[0] = 0; revocationCopy.operationID[0] = 0
        assertContentEquals(activation.encode(limits), activationCopy.encode(limits))
        assertContentEquals(revocation.encode(limits), revocationCopy.encode(limits))
        assertEquals("GatewayMappingActivation(redacted)", activation.toString())
        assertEquals("GatewayPhoneRevocation(redacted)", revocation.toString())
        assertEquals("GatewayPhoneEpochBinding(redacted)", b.toString())
    }
}
