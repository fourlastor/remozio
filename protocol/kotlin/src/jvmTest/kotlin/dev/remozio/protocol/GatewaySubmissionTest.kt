package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class GatewaySubmissionTest {
    private val limits = CborLimits(2048, 8, 128)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.gatewaySubmissionVectors"))).readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun kind(row: JsonObject) = GatewaySubmissionKind.entries.single { it.wireValue == row.text("kind").toULong() }

    @Test fun sharedFieldsAndUnsignedBoundaries() {
        val vectors = vectors(); val rows = vectors.getValue("valid").jsonArray; assertEquals(4, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val value = GatewaySubmissionControl.decode(bytes, limits)
            assertContentEquals(bytes, value.encode(limits)); assertEquals(kind(f), value.kind)
            assertEquals(f.text("revision").toULong(), value.revision)
            assertEquals(f.text("issued").toULong(), value.issuedAtUnixMillis); assertEquals(f.text("expires").toULong(), value.expiresAtUnixMillis)
            assertContentEquals(ByteArray(16) { 0x56 }, value.operationID); assertContentEquals(ByteArray(16) { 0x57 }, value.credentialID)
            val b = value.binding
            listOf(b.ownerID,b.macID,b.accountID,b.gatewayID,b.lifecycleEpoch).forEachIndexed { i, data ->
                assertContentEquals(ByteArray(16) { (i+16).toByte() }, data)
            }
            assertContentEquals(if (value.kind == GatewaySubmissionKind.ROTATION) hex(vectors.text("credentialPublicKey")) else null, value.publicKey)
        }
    }
    @Test fun malformedSharedControlsFail() {
        val rows = vectors().getValue("invalid").jsonArray; assertEquals(124, rows.size)
        for (row in rows) {
            val f = row.jsonObject
            assertFailsWith<IllegalArgumentException>(f.text("name")) { GatewaySubmissionControl.decode(hex(f.text("hex")), limits) }
            assertFailsWith<IllegalArgumentException>(f.text("name")) {
                GatewaySubmissionSigningInput.make(1u, kind(f), hex(f.text("hex")), limits, limits)
            }
        }
    }
    @Test fun sharedRootSignaturesSeparateKindsKeysAndPurposes() {
        val vectors = vectors()
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val kind = kind(f)
            assertContentEquals(hex(f.text("signingInput")), GatewaySubmissionSigningInput.make(1u, kind, bytes, limits, limits))
            fun verify(signature: String, key: String = vectors.text("publicKey")) =
                GatewaySubmissionSignature.verify(hex(signature), hex(key), 1u, kind, bytes, limits, limits)
            assertTrue(verify(f.text("signature")))
            assertFalse(verify(f.text("signature"), vectors.text("otherPublicKey")))
            assertFalse(verify(f.text("signature"), vectors.text("credentialPublicKey")))
            for (field in listOf("wrongPurposeSignature","wrongTypeSignature","approvalSignature","credentialSignature")) {
                assertFalse(verify(f.text(field)))
            }
            assertFalse(verify("00"))
        }
    }
    @Test fun signaturesBindEveryIdentityAndControlField() {
        val vectors = vectors()
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; if (!f.text("name").endsWith("ordinary")) continue
            val original = (DeterministicCbor.decode(hex(f.text("hex")), limits) as CborValue.Fields).values
            val binding = (original.getValue(1u) as CborValue.Fields).values
            val mutations = mutableListOf<Map<ULong,CborValue>>()
            for (key in binding.keys) {
                val data = (binding.getValue(key) as CborValue.Bytes).copyBytes(); data[0] = (data[0].toInt() xor 1).toByte()
                mutations += original + (1uL to CborValue.Fields(binding + (key to CborValue.Bytes(data))))
            }
            for (key in listOf(2uL,3uL,4uL,5uL,7uL,8uL)) {
                val changed = when (val value = original.getValue(key)) {
                    is CborValue.Unsigned -> CborValue.Unsigned(value.value+1u)
                    is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
                    CborValue.Null -> continue
                    else -> error("Unexpected fixture")
                }
                mutations += original + (key to changed)
            }
            for (changed in mutations) {
                assertFalse(GatewaySubmissionSignature.verify(hex(f.text("signature")), hex(vectors.text("publicKey")), 1u, kind(f),
                    DeterministicCbor.encode(CborValue.Fields(changed), limits), limits, limits))
            }
        }
    }
    @Test fun versionsBoundsAndOtherControlTypesFail() {
        for (row in vectors().getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val kind = kind(f)
            assertContentEquals(bytes, GatewaySubmissionControl.decode(bytes, CborLimits(bytes.size,8,128)).encode(limits))
            assertFailsWith<CborException> {
                GatewaySubmissionSigningInput.make(1u,kind,bytes,limits,CborLimits(hex(f.text("signingInput")).size-1,8,128))
            }
            for (version in listOf(0uL,2uL,ULong.MAX_VALUE)) {
                assertFailsWith<SigningInputException> { GatewaySubmissionSigningInput.make(version, kind, bytes, limits, limits) }
            }
            for (bounded in listOf(CborLimits(bytes.size-1,8,128), CborLimits(2048,1,128), CborLimits(2048,8,2))) {
                assertFailsWith<CborException> { GatewaySubmissionControl.decode(bytes, bounded) }
            }
            val other = if (kind == GatewaySubmissionKind.ROTATION) GatewaySubmissionKind.REVOCATION else GatewaySubmissionKind.ROTATION
            assertFailsWith<GatewayTokenException> { GatewaySubmissionSigningInput.make(1u, other, bytes, limits, limits) }
            assertFailsWith<GatewayTokenException> { GatewayTokenCandidate.decode(bytes, limits) }
            assertFailsWith<GatewayTokenException> { GatewayMappingActivation.decode(bytes, limits) }
            assertFailsWith<GatewayTokenException> { GatewayPhoneRevocation.decode(bytes, limits) }
        }
    }
    @Test fun constructorAndGetterCopiesKeepAuthenticatedFieldsStable() {
        val vectors = vectors(); val f = vectors.getValue("valid").jsonArray[0].jsonObject
        val original = GatewaySubmissionControl.decode(hex(f.text("hex")), limits); val b = original.binding
        val ids = listOf(b.ownerID,b.macID,b.accountID,b.gatewayID,b.lifecycleEpoch)
        val binding = GatewaySubmissionBinding(ids[0],ids[1],ids[2],ids[3],ids[4]); val hash = binding.hashCode()
        val operation = original.operationID; val credential = original.credentialID; val key = original.publicKey!!
        val value = GatewaySubmissionControl(original.kind,binding,original.revision,operation,original.issuedAtUnixMillis,
            original.expiresAtUnixMillis,credential,key)
        ids.forEach { it.fill(0) }; operation.fill(0); credential.fill(0); key.fill(0)
        value.operationID.fill(0); value.credentialID.fill(0); value.publicKey!!.fill(0); binding.ownerID.fill(0)
        assertEquals(b,binding); assertEquals(hash,binding.hashCode()); assertContentEquals(original.encode(limits),value.encode(limits))
        assertEquals("GatewaySubmissionControl(redacted)",value.toString()); assertEquals("GatewaySubmissionBinding(redacted)",binding.toString())
    }
}
