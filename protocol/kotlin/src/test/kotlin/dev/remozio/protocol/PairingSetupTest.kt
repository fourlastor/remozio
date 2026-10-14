package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

class PairingSetupTest {
    private fun vectors() = Json.parseToJsonElement(File(System.getProperty("remozio.pairingSetupVectors")).readText()).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun sharedProposalAndEverySetupFrameAgree() {
        val v = vectors(); val proposal = PairingPhoneProposal.decode(hex(v.getValue("proposal").jsonPrimitive.content))
        assertContentEquals(hex(v.getValue("proposal").jsonPrimitive.content), proposal.encode())
        proposal.validate(PairingTranscript.decode(hex(v.getValue("transcript").jsonPrimitive.content)))
        for (row in v.getValue("frames").jsonArray) {
            val bytes = hex(row.jsonObject.getValue("hex").jsonPrimitive.content)
            assertContentEquals(bytes, PairingSetupFrame.decode(bytes).encode())
            assertEquals("PairingSetupFrame(redacted)", PairingSetupFrame.decode(bytes).toString())
        }
        assertEquals("PairingPhoneProposal(redacted)", proposal.toString())
    }
    @Test fun unknownVersionsFieldsKindsAndAuthorityConfusionFail() {
        val v = vectors()
        for (row in v.getValue("invalidProposals").jsonArray) assertFails(row.jsonObject.getValue("name").jsonPrimitive.content) {
            PairingPhoneProposal.decode(hex(row.jsonObject.getValue("hex").jsonPrimitive.content))
        }
        for (row in v.getValue("invalidFrames").jsonArray) assertFails(row.jsonObject.getValue("name").jsonPrimitive.content) {
            PairingSetupFrame.decode(hex(row.jsonObject.getValue("hex").jsonPrimitive.content))
        }
        assertFails { PairingSetupFrame.decode(ByteArray(PairingSetupFrame.MAXIMUM_BYTES + 1)) }
        assertFails { PairingPhoneProposal.decode(ByteArray(66_001)) }
    }
    @Test fun phoneClaimsBindOfferNonceAndEachKeyRole() {
        val v = vectors(); val transcript = PairingTranscript.decode(hex(v.getValue("transcript").jsonPrimitive.content))
        val proposal = PairingPhoneProposal.decode(hex(v.getValue("proposal").jsonPrimitive.content))
        val limits = CborLimits(66000, 3, 24)
        val f = (DeterministicCbor.decode(proposal.encode(), limits) as CborValue.Fields).values
        val offerLimits = CborLimits(65536, 5, 5000)
        val offer = (DeterministicCbor.decode(proposal.phone.encode(), offerLimits) as CborValue.Fields).values
        val changedOffer = DeterministicCbor.encode(CborValue.Fields(offer + (3uL to CborValue.Bytes(ByteArray(32) { 8 }))), offerLimits)
        val keys = (f.getValue(3u) as CborValue.ArrayValue).values
        for (changed in listOf(f + (2uL to CborValue.Bytes(changedOffer)), f + (3uL to CborValue.ArrayValue(listOf(keys[1],keys[0],keys[2]))))) {
            assertFails { PairingPhoneProposal.decode(DeterministicCbor.encode(CborValue.Fields(changed), limits)).validate(transcript) }
        }
        val invitation = PairingInvitation(ByteArray(16) { 9 }, ByteArray(16) { 2 }, "Other", transcript.macAuthorityKey.copyBytes(), transcript.macTransportKey.copyBytes(), 1u)
        assertFails { proposal.validateMacScope(invitation) }
    }
}
