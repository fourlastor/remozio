package dev.remozio.protocol

import kotlinx.serialization.json.*
import kotlin.test.*

class PairingExpiryReceiptTest {
    private fun vectors() = Json.parseToJsonElement(TestVectors.pairingExpiryReceipt).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.bytes(field: String) = hex(getValue(field).jsonPrimitive.content)

    @Test fun sharedExpiryReceiptsRoundTripAndVerify() {
        val values = vectors()
        val transcript = PairingTranscript.decode(values.bytes("transcript"))
        for (value in values.getValue("valid").jsonArray) {
            val row = value.jsonObject
            val name = row.getValue("name").jsonPrimitive.content
            val bytes = row.bytes("hex")
            val receipt = PairingExpiryReceipt.decode(bytes)
            assertContentEquals(bytes, receipt.encode(), name)
            assertEquals(transcript.setupID, receipt.setupID, name)
            assertEquals(row.getValue("reason").jsonPrimitive.content.toULong(), receipt.reason.tag, name)
            assertEquals("PairingExpiryReceipt(redacted)", receipt.toString(), name)
            assertContentEquals(row.bytes("signingInput"), PairingExpiryReceipt.signingInput(transcript, receipt.reason), name)
            assertContentEquals(bytes, PairingExpiryReceipt(transcript, receipt.reason, receipt.signature.copyBytes()).encode(), name)
            assertTrue(receipt.verify(transcript), name)
        }
    }

    @Test fun malformedExpiryReceiptsAndEnrolledReceiptFramesAreRejected() {
        val values = vectors()
        for (value in values.getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) { PairingExpiryReceipt.decode(row.bytes("hex")) }
        }
        for (value in values.getValue("valid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) { PairingReceiptFrame.decode(row.bytes("hex")) }
        }
        assertFails { PairingExpiryReceipt.decode(ByteArray(PairingExpiryReceipt.MAXIMUM_BYTES + 1)) }
    }

    @Test fun expiryVerificationBindsTheRetainedTranscriptAndRootSignature() {
        val values = vectors()
        val transcript = PairingTranscript.decode(values.bytes("transcript"))
        for (value in values.getValue("unverified").jsonArray) {
            val row = value.jsonObject
            val name = row.getValue("name").jsonPrimitive.content
            val bytes = row.bytes("hex")
            val receipt = PairingExpiryReceipt.decode(bytes)
            if (name.startsWith("another ")) {
                val envelope = assertIs<CborValue.Fields>(
                    DeterministicCbor.decode(bytes, CborLimits(PairingExpiryReceipt.MAXIMUM_BYTES, 1, 8)),
                )
                val input = assertIs<CborValue.Bytes>(envelope.values[0uL]).copyBytes()
                assertTrue(P256Verification.verify(receipt.signature.copyBytes(), transcript.macAuthorityKey.copyBytes(), input), name)
            }
            if (name == "valid MAC_COMMIT signature in the expiry envelope") {
                assertTrue(transcript.verify(receipt.signature.copyBytes(), transcript.macAuthorityKey.copyBytes(),
                    PairingProofPurpose.MAC_COMMIT), name)
            }
            assertFalse(receipt.verify(transcript), name)
        }
        val ordinary = PairingTranscript.decode(values.bytes("ordinaryTranscript"))
        val row = values.getValue("valid").jsonArray.first().jsonObject
        assertFalse(PairingExpiryReceipt.decode(row.bytes("hex")).verify(ordinary))
        assertFails { PairingExpiryReceipt.signingInput(ordinary, PairingExpiryReason.DEADLINE_ELAPSED) }
    }
}
