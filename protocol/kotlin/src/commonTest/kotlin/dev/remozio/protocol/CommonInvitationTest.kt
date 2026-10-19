package dev.remozio.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

// Runs on every target, so the iOS platform functions see the same vectors as the JVM.
class CommonInvitationTest {
    private val vectors = Json.parseToJsonElement(TestVectors.pairingInvitation).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun bytes(row: JsonObject) = hex(row.getValue("hex").jsonPrimitive.content)
    private fun sample() = PairingInvitation.decode(bytes(vectors.getValue("valid").jsonArray.first().jsonObject))

    @Test fun validVectorsRoundTripThroughBytesAndText() {
        val rows = vectors.getValue("valid").jsonArray
        assertTrue(rows.size >= 5)
        for (value in rows) {
            val row = value.jsonObject
            val encoded = bytes(row)
            val invitation = PairingInvitation.decode(encoded)
            val text = row.getValue("text").jsonPrimitive.content
            assertEquals(text, invitation.exportText())
            assertEquals(row.getValue("fingerprint").jsonPrimitive.content, invitation.fingerprint())
            assertContentEquals(encoded, PairingInvitation.importText(text).encode())
            assertEquals("PairingInvitation(redacted)", invitation.toString())
        }
    }

    @Test fun invalidVectorsFail() {
        val rows = vectors.getValue("invalid").jsonArray
        assertTrue(rows.any { it.jsonObject.getValue("name").jsonPrimitive.content == "invalid-curve" })
        for (value in rows) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) { PairingInvitation.decode(bytes(row)) }
        }
        assertFails { PairingInvitation.decode(ByteArray(513)) }
    }

    @Test fun malformedTextFails() {
        val text = sample().exportText()
        for (bad in listOf("", text + "=", text + "\n", " " + text, text.replace("v1:", "v2:"),
            "remozio-pairing:v1:A", "remozio-pairing:v1:" + "A".repeat(700), "remozio-pairing:v1:" + "é".repeat(300))) {
            assertFails(bad.take(40)) { PairingInvitation.importText(bad) }
        }
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val last = alphabet.indexOf(text.last())
        for (offset in 1..3) assertFails { PairingInvitation.importText(text.dropLast(1) + alphabet[last + offset]) }
    }

    @Test fun pointsOutsideTheFieldOrOffTheCurveFail() {
        val valid = sample().transportPublicKey.copyBytes()
        pairingPoint(valid)
        val p = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        // x = p, x = 2^256 - 1, y = p: each is out of range even if a reduced value would be on the curve.
        for (bad in listOf(byteArrayOf(4) + p + valid.copyOfRange(33, 65), byteArrayOf(4) + ByteArray(32) { -1 } + valid.copyOfRange(33, 65),
            byteArrayOf(4) + valid.copyOfRange(1, 33) + p, valid.copyOf().also { it[64] = (it[64] + 1).toByte() },
            ByteArray(65).also { it[0] = 4 }, valid.copyOf(64), byteArrayOf(2) + valid.copyOfRange(1, 33))) {
            assertFails { pairingPoint(bad) }
        }
    }

    @Test fun labelCodePointsMatchTheJvmDefinition() {
        assertEquals(listOf(0x41, 0x1f600, 0x42), codePoints("A😀B"))
        assertEquals(listOf(0xd800, 0x41), codePoints("\ud800A"))
        assertEquals(listOf(0xdc00), codePoints("\udc00"))
        val original = sample()
        for (label in listOf("‮", "a b", "\u0085", "‏", "⁦x")) {
            assertFails(label) { PairingInvitation(original.macID.copyBytes(), original.accountID.copyBytes(), label,
                original.authorityPublicKey.copyBytes(), original.transportPublicKey.copyBytes(), 1u) }
        }
        PairingInvitation(original.macID.copyBytes(), original.accountID.copyBytes(), "Mac 😀 é",
            original.authorityPublicKey.copyBytes(), original.transportPublicKey.copyBytes(), 1u)
    }

    @Test fun sha256MatchesKnownAnswers() {
        fun digest(text: String) = sha256(text.encodeToByteArray()).joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest(""))
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest("abc"))
    }
}
