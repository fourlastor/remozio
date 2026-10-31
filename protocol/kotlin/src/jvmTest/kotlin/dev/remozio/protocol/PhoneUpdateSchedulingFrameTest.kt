package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

private fun updateChannelVectors(property: String) = Json.parseToJsonElement(File(checkNotNull(System.getProperty(property))).readText()).jsonObject
private fun JsonObject.channelText(name: String) = getValue(name).jsonPrimitive.content
private fun channelHex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

class PhoneUpdateSchedulingFrameTest {
    private fun vectors() = updateChannelVectors("remozio.phoneUpdateSchedulingVectors")
    @Test fun sharedFramesPreserveCanonicalBytesAndQueryNonces() {
        val rows = vectors().getValue("valid").jsonArray; assertEquals(8, rows.size)
        for (element in rows) {
            val bytes = channelHex(element.jsonObject.channelText("hex")); val value = PhoneUpdateSchedulingFrame.decode(bytes)
            assertContentEquals(bytes, value.encode()); assertEquals(CborValue.Bytes(ByteArray(32) { 9 }), value.queryNonce)
            assertEquals("PhoneUpdateSchedulingFrame(redacted)", value.toString())
        }
    }
    @Test fun malformedFramesAndNestedClaimsFailStrictly() {
        val rows = vectors().getValue("invalid").jsonArray; assertEquals(109, rows.size)
        for (element in rows) assertFails(element.jsonObject.channelText("name")) { PhoneUpdateSchedulingFrame.decode(channelHex(element.jsonObject.channelText("hex"))) }
    }
    @Test fun everyRoleHasItsOwnTypedPayloadAndUnsignedBoundaries() {
        val rows = vectors().getValue("valid").jsonArray
        fun value(n: Int) = PhoneUpdateSchedulingFrame.decode(channelHex(rows[n].jsonObject.channelText("hex")))
        assertIs<PhoneUpdateSchedulingFrame.Status>(value(0))
        val maximum = assertIs<PhoneUpdateSchedulingFrame.Challenge>(value(2))
        assertEquals(ULong.MAX_VALUE, maximum.generation); assertEquals(ULong.MAX_VALUE, maximum.revision)
        assertEquals(UpdateSchedulingAction.CANCEL_DRAIN, maximum.action)
        assertIs<PhoneUpdateSchedulingFrame.Apply>(value(3)); assertIs<PhoneUpdateSchedulingFrame.ChallengeResponse>(value(4))
        assertIs<PhoneUpdateSchedulingFrame.StateResponse>(value(5))
        assertEquals(PhoneUpdateSchedulingFailure.UNAVAILABLE, assertIs<PhoneUpdateSchedulingFrame.Failure>(value(6)).reason)
        assertEquals(PhoneUpdateSchedulingFailure.INCOMPATIBLE, assertIs<PhoneUpdateSchedulingFrame.Failure>(value(7)).reason)
    }
    @Test fun directConstructionCannotBypassNestedNonceOrSignatureBounds() {
        val rows = vectors().getValue("valid").jsonArray
        val value = PhoneUpdateSchedulingFrame.decode(channelHex(rows[5].jsonObject.channelText("hex"))) as PhoneUpdateSchedulingFrame.StateResponse
        assertFails { PhoneUpdateSchedulingFrame.StateResponse(ByteArray(32) { 8 }, value.canonicalPayload.copyBytes(), value.signature.copyBytes()) }
        for (size in listOf(63, 65)) assertFails { PhoneUpdateSchedulingFrame.StateResponse(value.queryNonce.copyBytes(), value.canonicalPayload.copyBytes(), ByteArray(size)) }
        assertFails { PhoneUpdateSchedulingFrame.Challenge(value.queryNonce.copyBytes(), ByteArray(32), 0u, 0u, UpdateSchedulingAction.DEFER_UPDATE) }
        assertFails { PhoneUpdateSchedulingFrame.Status(ByteArray(31)) }
    }
    @Test fun responseCodecsCannotAcceptAnotherRoleAndArraysAreCopied() {
        val rows = vectors().getValue("valid").jsonArray
        val status = PhoneUpdateSchedulingFrame.decode(channelHex(rows[5].jsonObject.channelText("hex"))) as PhoneUpdateSchedulingFrame.StateResponse
        val challenge = PhoneUpdateSchedulingFrame.decode(channelHex(rows[4].jsonObject.channelText("hex"))) as PhoneUpdateSchedulingFrame.ChallengeResponse
        val nonce = status.queryNonce.copyBytes(); val body = status.canonicalPayload.copyBytes(); val signature = status.signature.copyBytes()
        val copied = PhoneUpdateSchedulingFrame.StateResponse(nonce, body, signature)
        nonce.fill(0); body.fill(0); signature.fill(0)
        assertContentEquals(status.encode(), copied.encode())
        assertFails { PhoneUpdateSchedulingFrame.ChallengeResponse(status.queryNonce.copyBytes(), status.canonicalPayload.copyBytes(), status.signature.copyBytes()) }
        assertFails { PhoneUpdateSchedulingFrame.StateResponse(status.queryNonce.copyBytes(), challenge.canonicalPayload.copyBytes(), status.signature.copyBytes()) }
        assertFails { PhoneUpdateSchedulingFrame.Apply(status.queryNonce.copyBytes(), challenge.canonicalPayload.copyBytes(), status.signature.copyBytes()) }
        assertNotEquals(PhoneRoutingFrame.APPLICATION_PROTOCOL, PhoneUpdateSchedulingFrame.APPLICATION_PROTOCOL)
    }
}
