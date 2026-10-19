package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class PushDataTest {
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.pushDataVectors"))).readText()).jsonObject
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.data() = getValue("data").jsonObject.mapValues { it.value.jsonPrimitive.content }
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
    @Test fun sharedPayloadsRoundTripAndPreserveEveryByte() {
        val rows = vectors().getValue("valid").jsonArray; assertEquals(2, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val data = f.data(); val value = PushData.decode(data)
            assertEquals(data, value.encode())
            when (value) {
                is PushData.Wake -> {
                    assertEquals("wake", f.text("name")); assertEquals(f.text("identifier"), hex(value.identifier))
                    assertEquals(f.text("enrollmentTag"), hex(value.enrollmentTag))
                }
                is PushData.TokenChallenge -> {
                    assertEquals("challenge", f.text("name")); assertEquals(f.text("candidateID"), hex(value.candidateID))
                    assertEquals(f.text("challenge"), hex(value.challenge)); assertEquals(f.text("enrollmentTag"), hex(value.enrollmentTag))
                }
            }
        }
    }
    @Test fun sharedMalformedMixedAndNoncanonicalDataFail() {
        val rows = vectors().getValue("invalid").jsonArray; assertEquals(76, rows.size)
        for (row in rows) {
            val f = row.jsonObject
            assertFailsWith<IllegalArgumentException>(f.text("name")) { PushData.decode(f.data()) }
        }
    }
    @Test fun ConstructorsRejectInvalidLengthsCopyArraysAndRedact() {
        val id = ByteArray(16) { 1 }; val secret = ByteArray(32) { 2 }
        for (size in listOf(0, 15, 17, 31, 33)) {
            val bad = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { PushData.Wake(bad, secret) }
            assertFailsWith<IllegalArgumentException> { PushData.Wake(secret, bad) }
            assertFailsWith<IllegalArgumentException> { PushData.TokenChallenge(bad, secret, secret) }
            assertFailsWith<IllegalArgumentException> { PushData.TokenChallenge(id, bad, secret) }
            assertFailsWith<IllegalArgumentException> { PushData.TokenChallenge(id, secret, bad) }
        }
        val value = PushData.TokenChallenge(id, secret, secret); val wake = PushData.Wake(secret, secret)
        val before = value.encode(); val wakeBefore = wake.encode()
        id[0] = 0; secret[0] = 0
        value.candidateID[0] = 0; value.challenge[0] = 0; value.enrollmentTag[0] = 0
        wake.identifier[0] = 0; wake.enrollmentTag[0] = 0
        assertEquals(before, value.encode()); assertEquals(wakeBefore, wake.encode())
        val mutable = before.toMutableMap(); val parsed = PushData.decode(mutable); mutable.clear()
        assertEquals(before, parsed.encode())
        assertEquals("PushTokenChallenge(redacted)", value.toString()); assertEquals("PushWake(redacted)", wake.toString())
    }
}
