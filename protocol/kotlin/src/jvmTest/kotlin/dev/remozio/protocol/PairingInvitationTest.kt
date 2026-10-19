package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

class PairingInvitationTest {
    private fun vectors() = Json.parseToJsonElement(File(System.getProperty("remozio.invitationVectors")).readText()).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun bytes(row: JsonObject) = hex(row.getValue("hex").jsonPrimitive.content)
    private fun sample() = PairingInvitation.decode(bytes(vectors().getValue("valid").jsonArray.first().jsonObject))
    private fun transcript(): PairingTranscript {
        val row = Json.parseToJsonElement(File(System.getProperty("remozio.pairingVectors")).readText())
            .jsonObject.getValue("valid").jsonArray.first().jsonObject
        return PairingTranscript.decode(bytes(row))
    }
    @Test fun sharedQRAndTextInvitationsAgree() {
        for (value in vectors().getValue("valid").jsonArray) {
            val row = value.jsonObject; val encoded = bytes(row)
            val invitation = PairingInvitation.decode(encoded)
            val text = row.getValue("text").jsonPrimitive.content
            assertEquals(text, invitation.exportText())
            assertEquals(row.getValue("fingerprint").jsonPrimitive.content, invitation.fingerprint())
            assertContentEquals(encoded, PairingInvitation.importText(text).encode())
            encoded.fill(0)
            assertContentEquals(bytes(row), invitation.encode())
            assertEquals("PairingInvitation(redacted)", invitation.toString())
        }
    }
    @Test fun malformedAndOversizedInvitationsFail() {
        for (value in vectors().getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) { PairingInvitation.decode(bytes(row)) }
        }
        assertFails { PairingInvitation.decode(ByteArray(513)) }
        val text = sample().exportText()
        for (bad in listOf("", text + "=", text + "\n", " " + text, text.replace("v1:", "v2:"),
            text.replace("remozio-pairing:", "https://example.com/"), "remozio-pairing:v1:A", "remozio-pairing:v1:" + "A".repeat(700),
            "remozio-pairing:v1:" + "é".repeat(300))) {
            assertFails { PairingInvitation.importText(bad) }
        }
        val original = sample()
        assertFails { PairingInvitation(original.macID.copyBytes(), original.accountID.copyBytes(), "\ud800",
            original.authorityPublicKey.copyBytes(), original.transportPublicKey.copyBytes(), 1u) }
    }
    @Test fun nonzeroBase64PadBitsCannotAliasAnInvitation() {
        val text = sample().exportText()
        assertEquals(3, (text.length - "remozio-pairing:v1:".length) % 4)
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val i = alphabet.indexOf(text.last())
        assertEquals(0, i and 3)
        for (offset in 1..3) assertFails { PairingInvitation.importText(text.dropLast(1) + alphabet[i + offset]) }
    }
    @Test fun everyClaimChangesTheFullFingerprint() {
        val invitation = sample()
        val limits = CborLimits(512, 1, 15)
        val f = (DeterministicCbor.decode(invitation.encode(), limits) as CborValue.Fields).values
        val anotherPoint = transcript().transportKey.publicKey
        val variants = mapOf(1uL to CborValue.Bytes(ByteArray(16) { 8 }), 2uL to CborValue.Bytes(ByteArray(16) { 9 }),
            3uL to CborValue.Text("Another Mac"), 4uL to anotherPoint, 5uL to anotherPoint,
            6uL to CborValue.Unsigned(2u))
        for ((field, value) in variants) {
            val changed = f + (field to value)
            assertNotEquals(invitation.fingerprint(), PairingInvitation.decode(DeterministicCbor.encode(CborValue.Fields(changed), limits)).fingerprint())
        }
    }
    @Test fun transcriptChecksScopeBothPinsAndExactFloor() {
        val transcript = transcript()
        val invitation = sample()
        invitation.validateMacClaims(transcript)
        val limits = CborLimits(512, 1, 15)
        val f = (DeterministicCbor.decode(invitation.encode(), limits) as CborValue.Fields).values
        val changed = listOf(f + (1uL to CborValue.Bytes(ByteArray(16) { 8 })),
            f + (2uL to CborValue.Bytes(ByteArray(16) { 9 })), f + (6uL to CborValue.Unsigned(2u)),
            f + (4uL to transcript.transportKey.publicKey), f + (5uL to transcript.transportKey.publicKey))
        for (claims in changed) assertFails {
            PairingInvitation.decode(DeterministicCbor.encode(CborValue.Fields(claims), limits)).validateMacClaims(transcript)
        }
    }
}
