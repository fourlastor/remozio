package dev.remozio.protocol

import kotlinx.serialization.json.*
import kotlin.test.*

class PairingInvitationV2Test {
    private fun vectors() = Json.parseToJsonElement(TestVectors.pairingInvitationV2).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.bytes(key: String) = hex(text(key))
    private fun rows(values: JsonObject) = values.getValue("valid").jsonArray.map { it.jsonObject }

    @Test fun invitationAndProofInteroperateForBothSetupModes() {
        val values = vectors()
        val challenge = values.bytes("challenge")
        val exporter = values.bytes("exporter")
        for (row in rows(values)) {
            val invitation = PairingInvitationV2.importText(row.text("text"))
            val proposal = PairingPhoneProposal.decode(row.bytes("proposal"))
            assertContentEquals(row.bytes("invitation"), invitation.encode(), row.text("name"))
            assertEquals(row.text("text"), invitation.exportText())
            assertEquals(row.text("lifetimeMilliseconds").toULong(), invitation.lifetimeMilliseconds)
            assertEquals(proposal.replacement?.value(), invitation.replacement?.value())
            assertContentEquals(row.bytes("proofInput"), invitation.proofInput(proposal, challenge, exporter))
            assertContentEquals(row.bytes("tag"), invitation.proof(proposal, challenge, exporter))
            val transcript = PairingTranscript.decode(row.bytes("transcript"))
            invitation.invitation.validateMacClaims(transcript)
            proposal.validate(transcript)
            assertEquals("PairingInvitationV2(redacted)", invitation.toString())
        }
    }

    @Test fun bonjourNameMatchesTheSharedVectorBeforeAndAfterExport() {
        val values = vectors()
        val template = PairingInvitationV2.importText(rows(values).first().text("text"))
        val names = mutableSetOf<String>()
        for (vector in values.getValue("bonjourWindowNames").jsonArray) {
            val row = vector.jsonObject
            val invitation = PairingInvitationV2(template.invitation, row.bytes("windowID"), ByteArray(32) { 2 },
                lifetimeMilliseconds = template.lifetimeMilliseconds)
            val name = invitation.bonjourInstanceName()
            assertEquals(row.text("name"), name)
            assertEquals(name, PairingInvitationV2.importText(invitation.exportText()).bonjourInstanceName())
            assertTrue(names.add(name))
        }
        assertEquals(2, names.size)
    }

    @Test fun proofBindsTheConnectionAndRejectsInvalidInputs() {
        val values = vectors()
        val row = rows(values).first()
        val invitation = PairingInvitationV2.importText(row.text("text"))
        val proposal = PairingPhoneProposal.decode(row.bytes("proposal"))
        val challenge = values.bytes("challenge")
        val exporter = values.bytes("exporter")
        assertFalse(row.bytes("tag").contentEquals(invitation.proof(proposal, exporter, challenge)))
        assertFails { invitation.proof(proposal, challenge, ByteArray(0)) }
        val wrongInvitation = PairingInvitationV2(invitation.invitation, ByteArray(16) { 1 }, ByteArray(32) { 2 },
            lifetimeMilliseconds = invitation.lifetimeMilliseconds)
        assertFalse(row.bytes("tag").contentEquals(wrongInvitation.proof(proposal, challenge, exporter)))
        val replacement = PairingPhoneProposal.decode(rows(values).last().bytes("proposal"))
        assertFails { invitation.proof(replacement, challenge, exporter) }
    }

    @Test fun invitationAndPreludeRejectMalformedAndLegacyInputs() {
        val values = vectors()
        for (invalid in values.getValue("invalid").jsonArray) {
            val row = invalid.jsonObject
            assertFails(row.text("name")) { PairingInvitationV2.decode(row.bytes("hex")) }
        }
        val text = rows(values).first().text("text")
        val invitation = PairingInvitationV2.importText(text)
        assertFails { PairingInvitationV2.importText(invitation.invitation.exportText()) }
        assertFails { PairingInvitationV2.importText(text + "=") }
        assertFails { PairingInvitationV2.importText(text + " ") }
        assertFails { PairingInvitationV2.decode(ByteArray(PairingInvitationV2.MAXIMUM_BYTES + 1)) }

        val challengeBytes = values.bytes("challengePrelude")
        val challenge = assertIs<PairingSetupPreludeV2.Challenge>(PairingSetupPreludeV2.decode(challengeBytes))
        assertContentEquals(values.bytes("challenge"), challenge.value.copyBytes())
        assertContentEquals(challengeBytes, challenge.encode())
        for (row in rows(values)) {
            val data = row.bytes("proposalPrelude")
            val frame = assertIs<PairingSetupPreludeV2.Proposal>(PairingSetupPreludeV2.decode(data))
            assertContentEquals(row.bytes("proposal"), frame.value.encode())
            assertContentEquals(row.bytes("tag"), frame.tag.copyBytes())
            assertContentEquals(data, frame.encode())
        }
        for (invalid in values.getValue("invalidPreludes").jsonArray) {
            assertFails { PairingSetupPreludeV2.decode(hex(invalid.jsonPrimitive.content)) }
        }
    }

    @Test fun v2SetupRetainsRecoveryAndSignedExpirySemantics() {
        val values = vectors()
        val row = rows(values).last()
        val proposal = PairingPhoneProposal.decode(row.bytes("proposal"))
        val transcript = PairingTranscript.decode(row.bytes("transcript"))
        proposal.validate(transcript)
        val recovery = values.getValue("recovery").jsonObject
        val lookup = assertIs<PairingRecoveryFrame.Lookup>(PairingRecoveryFrame.decode(recovery.bytes("lookup")))
        val proof = assertIs<PairingRecoveryFrame.Proof>(PairingRecoveryFrame.decode(recovery.bytes("proof")))
        val committed = assertIs<PairingRecoveryFrame.Committed>(PairingRecoveryFrame.decode(recovery.bytes("committed")))
        val expired = assertIs<PairingRecoveryFrame.Expired>(PairingRecoveryFrame.decode(recovery.bytes("expired")))
        assertEquals(transcript.setupID, lookup.query.setupID)
        assertEquals(transcript.phone.scope.value, lookup.query.scope.value)
        assertContentEquals(transcript.digest(), lookup.query.transcriptDigest.copyBytes())
        val input = lookup.query.signingInput(recovery.bytes("exporter"), recovery.bytes("challenge"))
        assertContentEquals(recovery.bytes("signingInput"), input)
        assertTrue(P256Verification.verify(proof.signature.copyBytes(), transcript.transportKey.publicKey.copyBytes(), input))
        assertTrue(transcript.verify(committed.signature.copyBytes(), transcript.macAuthorityKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
        assertTrue(expired.receipt.verify(transcript))
        assertContentEquals(recovery.bytes("expiryInput"), PairingExpiryReceipt.signingInput(transcript, PairingExpiryReason.DEADLINE_ELAPSED))
        assertFalse(expired.receipt.verify(PairingTranscript.decode(rows(values).first().bytes("transcript"))))
    }
}
