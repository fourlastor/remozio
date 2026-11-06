package dev.remozio.protocol

import kotlinx.serialization.json.*
import kotlin.test.*

class PairingTranscriptTest {
    private val vectors get() = Json.parseToJsonElement(TestVectors.pairing).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun bytes(row: JsonObject, name: String) = hex(row.getValue(name).jsonPrimitive.content)
    @Test fun sharedAddAndReplacementTranscriptsAgree() {
        for (value in vectors.getValue("valid").jsonArray) {
            val row = value.jsonObject; val encoded = bytes(row, "hex")
            val transcript = PairingTranscript.decode(encoded)
            assertContentEquals(encoded, transcript.encode())
            assertContentEquals(bytes(row, "phoneInput"), transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC))
            assertContentEquals(bytes(row, "macInput"), transcript.signingInput(PairingProofPurpose.MAC_COMMIT))
            assertContentEquals(bytes(row, "digest"), transcript.digest())
            assertEquals(row.getValue("verificationCode").jsonPrimitive.content, transcript.verificationCode())
            encoded.fill(0)
            assertContentEquals(bytes(row, "hex"), transcript.encode())
            assertEquals("PairingTranscript(redacted)", transcript.toString())
        }
    }
    @Test fun malformedAndIncompatibleTranscriptsFail() {
        for (value in vectors.getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) { PairingTranscript.decode(bytes(row, "hex")) }
        }
        assertFails { PairingTranscript.decode(ByteArray(132001)) }
    }
}
