package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GatewayTokenTest {
    private val limits = CborLimits(2048, 8, 128)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.gatewayTokenVectors"))).readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun values(b: GatewayTokenBinding) = listOf(b.ownerID, b.macID, b.accountID, b.gatewayID, b.lifecycleEpoch,
        b.phoneID, b.enrollmentEpoch, b.candidateID, b.tokenDigest, b.challenge, b.enrollmentTag)
    private fun binding(v: List<ByteArray>) = GatewayTokenBinding(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10])

    @Test
    fun sharedCandidatesAndProofsRetainEveryBinding() {
        val vectors = vectors()
        val candidates = vectors.getValue("validCandidates").jsonArray
        val proofs = vectors.getValue("validProofs").jsonArray
        assertEquals(2, candidates.size); assertEquals(1, proofs.size)
        for (row in candidates) {
            val f = row.jsonObject
            val encoded = hex(f.getValue("hex").jsonPrimitive.content)
            val candidate = GatewayTokenCandidate.decode(encoded, limits)
            assertContentEquals(encoded, candidate.encode(limits))
            assertEquals(f.getValue("revision").jsonPrimitive.content.toULong(), candidate.revision)
            assertEquals(f.getValue("issued").jsonPrimitive.content.toULong(), candidate.issuedAtUnixMillis)
            assertEquals(f.getValue("expires").jsonPrimitive.content.toULong(), candidate.expiresAtUnixMillis)
            assertContentEquals(hex(vectors.getValue("operationID").jsonPrimitive.content), candidate.operationID)
            values(candidate.binding).forEachIndexed { index, bytes ->
                assertContentEquals(hex(vectors.getValue("bindings").jsonObject.getValue(index.toString()).jsonPrimitive.content), bytes)
            }
            for (proofRow in proofs) {
                val bytes = hex(proofRow.jsonObject.getValue("hex").jsonPrimitive.content)
                val proof = GatewayTokenProof.decode(bytes, limits)
                assertEquals(candidate.binding, proof.binding)
                assertContentEquals(bytes, proof.encode(limits))
            }
        }
    }

    @Test
    fun sharedMalformedCandidatesAndProofsFail() {
        val vectors = vectors()
        val candidates = vectors.getValue("invalidCandidates").jsonArray
        val proofs = vectors.getValue("invalidProofs").jsonArray
        assertEquals(69, candidates.size); assertEquals(57, proofs.size)
        for (row in candidates) {
            val f = row.jsonObject
            assertFailsWith<IllegalArgumentException>(f.getValue("name").jsonPrimitive.content) {
                GatewayTokenCandidate.decode(hex(f.getValue("hex").jsonPrimitive.content), limits)
            }
        }
        for (row in proofs) {
            val f = row.jsonObject
            assertFailsWith<IllegalArgumentException>(f.getValue("name").jsonPrimitive.content) {
                GatewayTokenProof.decode(hex(f.getValue("hex").jsonPrimitive.content), limits)
            }
        }
    }

    @Test
    fun sharedSignaturesRejectOtherKeysPurposesAndApprovalDomain() {
        val vectors = vectors()
        for (row in vectors.getValue("validCandidates").jsonArray) {
            val f = row.jsonObject
            val payload = hex(f.getValue("hex").jsonPrimitive.content)
            val input = GatewayTokenCandidateSigningInput.make(1u, payload, limits, limits)
            assertContentEquals(hex(f.getValue("signingInput").jsonPrimitive.content), input)
            fun verify(signature: String, key: String = "publicKey") = GatewayTokenCandidateSignature.verify(
                hex(f.getValue(signature).jsonPrimitive.content), hex(vectors.getValue(key).jsonPrimitive.content), 1u, payload, limits, limits)
            assertTrue(verify("signature")); assertFalse(verify("signature", "otherPublicKey"))
            assertFalse(verify("wrongPurposeSignature")); assertFalse(verify("approvalSignature"))
        }
    }

    @Test
    fun signatureBindsEveryControlFieldAndNestedIdentity() {
        val vectors = vectors()
        val row = vectors.getValue("validCandidates").jsonArray[0].jsonObject
        val original = (DeterministicCbor.decode(hex(row.getValue("hex").jsonPrimitive.content), limits) as CborValue.Fields).values
        val originalBinding = (original.getValue(1u) as CborValue.Fields).values
        val mutations = mutableListOf<Map<ULong, CborValue>>()
        for (key in 0uL..10uL) {
            val nested = originalBinding.toMutableMap()
            val bytes = (nested.getValue(key) as CborValue.Bytes).copyBytes()
            bytes[0] = (bytes[0].toInt() xor 1).toByte(); nested[key] = CborValue.Bytes(bytes)
            mutations += original + (1uL to CborValue.Fields(nested))
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
            assertFalse(GatewayTokenCandidateSignature.verify(hex(row.getValue("signature").jsonPrimitive.content),
                hex(vectors.getValue("publicKey").jsonPrimitive.content), 1u,
                DeterministicCbor.encode(CborValue.Fields(changed), limits), limits, limits))
        }
    }

    @Test
    fun boundsApplyToPayloadAndSigningInput() {
        val vectors = vectors()
        val row = vectors.getValue("validCandidates").jsonArray[0].jsonObject
        val bytes = hex(row.getValue("hex").jsonPrimitive.content)
        val candidate = GatewayTokenCandidate.decode(bytes, limits)
        assertContentEquals(bytes, candidate.encode(CborLimits(bytes.size, 8, 128)))
        val short = CborLimits(bytes.size - 1, 8, 128)
        assertFailsWith<CborException> { candidate.encode(short) }
        assertFailsWith<CborException> { GatewayTokenCandidate.decode(bytes, short) }
        val inputShort = CborLimits(hex(row.getValue("signingInput").jsonPrimitive.content).size - 1, 8, 128)
        assertFailsWith<CborException> { GatewayTokenCandidateSigningInput.make(1u, bytes, limits, inputShort) }
        val proofBytes = hex(vectors.getValue("validProofs").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
        val proof = GatewayTokenProof.decode(proofBytes, limits)
        val proofShort = CborLimits(proofBytes.size - 1, 8, 128)
        assertFailsWith<CborException> { proof.encode(proofShort) }
        assertFailsWith<CborException> { GatewayTokenProof.decode(proofBytes, proofShort) }
    }

    @Test
    fun versionAndMessageShapeCannotFallBack() {
        val vectors = vectors()
        val bytes = hex(vectors.getValue("validCandidates").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
        for (version in listOf(0uL, 2uL, ULong.MAX_VALUE)) {
            assertFailsWith<SigningInputException> { GatewayTokenCandidateSigningInput.make(version, bytes, limits, limits) }
        }
        val proof = hex(vectors.getValue("validProofs").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
        assertFailsWith<GatewayTokenException> { GatewayTokenCandidateSigningInput.make(1u, proof, limits, limits) }
    }

    @Test
    fun bindingsCopyArraysAndDescriptionsAreRedacted() {
        val candidate = GatewayTokenCandidate.decode(hex(vectors().getValue("validCandidates").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content), limits)
        val copied = values(candidate.binding)
        val reconstructed = binding(copied)
        copied[0][0] = (copied[0][0].toInt() xor 1).toByte()
        reconstructed.ownerID[0] = 0
        candidate.operationID[0] = 0
        assertEquals(candidate.binding, reconstructed); assertNotEquals(candidate.binding, binding(copied))
        for (i in copied.indices) {
            val invalid = copied.toMutableList(); invalid[i] = byteArrayOf()
            assertFailsWith<GatewayTokenException> { binding(invalid) }
        }
        assertEquals("GatewayTokenCandidate(redacted)", candidate.toString())
        assertEquals("GatewayTokenBinding(redacted)", candidate.binding.toString())
        assertEquals("GatewayTokenProof(redacted)", GatewayTokenProof(candidate.binding).toString())
    }
}
