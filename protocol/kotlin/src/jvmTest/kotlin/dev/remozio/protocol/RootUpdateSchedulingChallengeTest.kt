package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class RootUpdateSchedulingChallengeTest {
    private val limits = CborLimits(2048, 8, 64)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(
        System.getProperty("remozio.updateSchedulingChallengeVectors"))).readText()).jsonObject
    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.content
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun verify(signature: ByteArray, key: ByteArray, payload: ByteArray) =
        RootUpdateSchedulingChallengeSignature.verify(signature, key, 1u, payload, limits, limits)

    @Test fun sharedChallengesPreserveTheQueryAndExactControl() {
        val vectors = vectors(); val rows = vectors.getValue("valid").jsonArray
        assertEquals(5, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex"))
            val challenge = RootUpdateSchedulingChallenge.decode(bytes, limits)
            assertContentEquals(hex(f.text("queryNonce")), challenge.queryNonce)
            assertContentEquals(hex(f.text("controlHex")), challenge.canonicalControl)
            assertContentEquals(bytes, challenge.encode(limits))
            assertContentEquals(hex(f.text("signingInput")), RootUpdateSchedulingChallengeSigningInput.make(1u, bytes, limits, limits))
            assertTrue(verify(hex(f.text("signature")), hex(vectors.text("publicKey")), bytes))
        }
    }

    @Test fun malformedFramesAndNestedControlsRejectBeforeVerification() {
        val vectors = vectors(); val rows = vectors.getValue("invalid").jsonArray
        assertEquals(118, rows.size); var signed = 0
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex"))
            assertFailsWith<IllegalArgumentException>(f.text("name")) { RootUpdateSchedulingChallenge.decode(bytes, limits) }
            assertFailsWith<IllegalArgumentException>(f.text("name")) {
                RootUpdateSchedulingChallengeSigningInput.make(1u, bytes, limits, limits)
            }
            if ("signature" in f) {
                signed++
                assertTrue(P256Verification.verify(hex(f.text("signature")), hex(vectors.text("publicKey")), hex(f.text("signingInput"))))
                assertFailsWith<IllegalArgumentException> { verify(hex(f.text("signature")), hex(vectors.text("publicKey")), bytes) }
            }
        }
        assertEquals(6, signed)
    }

    @Test fun signaturesBindTheNonceControlKeyAndPurpose() {
        val vectors = vectors(); val key = hex(vectors.text("publicKey"))
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val signature = hex(f.text("signature"))
            assertFalse(verify(signature, hex(vectors.text("otherPublicKey")), bytes))
            for (name in listOf("wrongVersionSignature", "wrongTypeSignature", "wrongPurposeSignature", "phoneControlDomainSignature"))
                assertFalse(verify(hex(f.text(name)), key, bytes))
            val challenge = RootUpdateSchedulingChallenge.decode(bytes, limits)
            val changedNonce = challenge.queryNonce.also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertFalse(verify(signature, key, RootUpdateSchedulingChallenge(changedNonce, challenge.canonicalControl, limits).encode(limits)))
            assertFalse(UpdateSchedulingSignature.verify(signature, key, 1u, challenge.canonicalControl, limits, limits))
        }
        val f = vectors.getValue("valid").jsonArray[0].jsonObject
        val challenge = RootUpdateSchedulingChallenge.decode(hex(f.text("hex")), limits)
        val original = (DeterministicCbor.decode(challenge.canonicalControl, limits) as CborValue.Fields).values
        for (field in 1uL..13uL) {
            val changed = when (val value = original.getValue(field)) {
                is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() })
                is CborValue.Unsigned -> CborValue.Unsigned(value.value + 1u)
                else -> error("Unexpected fixture")
            }
            val control = DeterministicCbor.encode(CborValue.Fields(original + (field to changed)), limits)
            val bytes = RootUpdateSchedulingChallenge(challenge.queryNonce, control, limits).encode(limits)
            assertFalse(verify(hex(f.text("signature")), key, bytes))
        }
    }

    @Test fun resourceLimitsAndWireVersionRemainStrict() {
        val f = vectors().getValue("valid").jsonArray[0].jsonObject; val bytes = hex(f.text("hex"))
        val challenge = RootUpdateSchedulingChallenge.decode(bytes, limits)
        for (nonce in listOf(ByteArray(31), ByteArray(33)))
            assertFailsWith<RootUpdateSchedulingChallengeException> { RootUpdateSchedulingChallenge(nonce, challenge.canonicalControl, limits) }
        for (bounds in listOf(CborLimits(bytes.size - 1, 8, 64), CborLimits(2048, 1, 2))) {
            assertFailsWith<IllegalArgumentException> { RootUpdateSchedulingChallenge.decode(bytes, bounds) }
            assertFailsWith<IllegalArgumentException> { challenge.encode(bounds) }
        }
        for (version in listOf(0uL, 2uL, ULong.MAX_VALUE))
            assertFailsWith<SigningInputException> { RootUpdateSchedulingChallengeSigningInput.make(version, bytes, limits, limits) }
        val short = CborLimits(hex(f.text("signingInput")).size - 1, 8, 64)
        assertFailsWith<CborException> { RootUpdateSchedulingChallengeSigningInput.make(1u, bytes, limits, short) }
    }

    @Test fun arraysAreCopiedAndDescriptionsAreRedacted() {
        val f = vectors().getValue("valid").jsonArray[0].jsonObject
        val nonce = hex(f.text("queryNonce")); val control = hex(f.text("controlHex"))
        val challenge = RootUpdateSchedulingChallenge(nonce, control, limits)
        nonce.fill(0); control.fill(0); challenge.queryNonce.fill(0); challenge.canonicalControl.fill(0)
        assertContentEquals(hex(f.text("hex")), challenge.encode(limits))
        assertEquals("RootUpdateSchedulingChallenge(redacted)", challenge.toString())
    }
}
