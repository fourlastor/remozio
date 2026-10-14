package dev.remozio.protocol

import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.serialization.json.*
import kotlin.test.*

class PairingTranscriptTest {
    private val vectors get() = Json.parseToJsonElement(File(System.getProperty("remozio.pairingVectors")).readText()).jsonObject
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
    @Test fun signaturesBindPurposeAndEveryTranscriptByte() {
        val transcript = PairingTranscript.decode(bytes(vectors.getValue("valid").jsonArray.first().jsonObject, "hex"))
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val point = (key.public as ECPublicKey).w
        fun scalar(n: java.math.BigInteger) = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        val publicKey = byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private); update(transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC)); sign()
        })
        assertTrue(transcript.verify(signature, publicKey, PairingProofPurpose.PHONE_BIOMETRIC))
        assertFalse(transcript.verify(signature, publicKey, PairingProofPurpose.MAC_COMMIT))
        val limits = CborLimits(132000, 4, 80)
        val fields = (DeterministicCbor.decode(transcript.encode(), limits) as CborValue.Fields).values
        for (field in listOf(1uL, 2uL, 10uL, 12uL)) {
            val changed = (fields.getValue(field) as CborValue.Bytes).copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() }
            val altered = PairingTranscript.decode(DeterministicCbor.encode(CborValue.Fields(fields + (field to CborValue.Bytes(changed))), limits))
            assertNotEquals(transcript.verificationCode(), altered.verificationCode())
            assertFalse(altered.verify(signature, publicKey, PairingProofPurpose.PHONE_BIOMETRIC))
        }
    }
}
