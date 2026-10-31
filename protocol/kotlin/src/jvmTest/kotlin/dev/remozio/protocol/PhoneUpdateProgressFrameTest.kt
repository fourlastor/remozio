package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

private fun frameHex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun JsonObject.frameText(name: String) = getValue(name).jsonPrimitive.content

class PhoneUpdateProgressFrameTest {
    private fun vectors() = Json.parseToJsonElement(
        File(checkNotNull(System.getProperty("remozio.phoneUpdateProgressVectors"))).readText(),
    ).jsonObject

    @Test fun sharedFramesPreserveCanonicalBytesAndSignedNestedProgress() {
        val data = vectors()
        val rows = data.getValue("valid").jsonArray
        assertEquals(13, rows.size)
        var responses = 0
        for (entry in rows) {
            val row = entry.jsonObject
            val bytes = frameHex(row.frameText("hex"))
            val frame = PhoneUpdateProgressFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode(), row.frameText("name"))
            assertEquals(CborValue.Bytes(ByteArray(32) { 9 }), frame.queryNonce)
            assertEquals("PhoneUpdateProgressFrame(redacted)", frame.toString())
            if (frame is PhoneUpdateProgressFrame.Response) {
                responses++
                val progress = UpdateSchedulingProgressResponse.decode(frame.canonicalPayload.copyBytes())
                assertEquals(frame.queryNonce, progress.status.queryNonce)
                assertTrue(UpdateSchedulingProgressSignature.verify(frame.signature.copyBytes(),
                    frameHex(data.frameText("publicKey")), 1u, frame.canonicalPayload.copyBytes(), CborLimits(8192, 2, 32)))
            }
        }
        assertEquals(10, responses)
    }

    @Test fun malformedFramesAndSignedMalformedNestedBodiesFailStrictly() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(287, rows.size)
        for (entry in rows) {
            val row = entry.jsonObject
            assertFails(row.frameText("name")) { PhoneUpdateProgressFrame.decode(frameHex(row.frameText("hex"))) }
        }
    }

    @Test fun parsingDoesNotAuthenticateAWellFormedSignature() {
        val response = response()
        val bytes = PhoneUpdateProgressFrame.Response(response.queryNonce.copyBytes(),
            response.canonicalPayload.copyBytes(), ByteArray(64)).encode()
        val parsed = assertIs<PhoneUpdateProgressFrame.Response>(PhoneUpdateProgressFrame.decode(bytes))
        assertFalse(UpdateSchedulingProgressSignature.verify(parsed.signature.copyBytes(),
            frameHex(vectors().frameText("publicKey")), 1u, parsed.canonicalPayload.copyBytes(), CborLimits(8192, 2, 32)))
    }

    @Test fun directConstructionCannotBypassNonceBoundsAndCopies() {
        val response = response()
        val nonce = response.queryNonce.copyBytes()
        val body = response.canonicalPayload.copyBytes()
        val signature = response.signature.copyBytes()
        val retained = PhoneUpdateProgressFrame.Response(nonce, body, signature)
        nonce.fill(0); body.fill(0); signature.fill(0)
        assertContentEquals(response.encode(), retained.encode())
        for (size in listOf(0, 31, 33)) assertFails { PhoneUpdateProgressFrame.Status(ByteArray(size)) }
        for (size in listOf(0, 63, 65)) assertFails { PhoneUpdateProgressFrame.Response(response.queryNonce.copyBytes(),
            response.canonicalPayload.copyBytes(), ByteArray(size)) }
        assertFails { PhoneUpdateProgressFrame.Response(ByteArray(32) { 8 },
            response.canonicalPayload.copyBytes(), response.signature.copyBytes()) }
    }

    @Test fun schedulingMessagesAndUnsignedLateClaimsCannotBecomeProgress() {
        val nonce = ByteArray(32) { 9 }
        val old = PhoneUpdateSchedulingFrame.Status(nonce).encode()
        assertFails { PhoneUpdateProgressFrame.decode(old) }
        assertFails { PhoneUpdateSchedulingFrame.decode(PhoneUpdateProgressFrame.Status(nonce).encode()) }
        assertNotEquals(PhoneUpdateSchedulingFrame.APPLICATION_PROTOCOL, PhoneUpdateProgressFrame.APPLICATION_PROTOCOL)
        val values = vectors().getValue("valid").jsonArray
        val unavailable = values.single { it.jsonObject.frameText("name") == "unavailable" }.jsonObject
        val incompatible = values.single { it.jsonObject.frameText("name") == "incompatible" }.jsonObject
        assertEquals(PhoneUpdateProgressFailure.UNAVAILABLE,
            assertIs<PhoneUpdateProgressFrame.Failure>(PhoneUpdateProgressFrame.decode(frameHex(unavailable.frameText("hex")))).reason)
        assertEquals(PhoneUpdateProgressFailure.INCOMPATIBLE,
            assertIs<PhoneUpdateProgressFrame.Failure>(PhoneUpdateProgressFrame.decode(frameHex(incompatible.frameText("hex")))).reason)
    }

    @Test fun maximumFrameBytesRemainBounded() {
        assertEquals(8192, PhoneUpdateProgressFrame.MAXIMUM_BYTES)
        assertFails { PhoneUpdateProgressFrame.decode(ByteArray(PhoneUpdateProgressFrame.MAXIMUM_BYTES + 1)) }
    }

    private fun response(): PhoneUpdateProgressFrame.Response {
        val row = vectors().getValue("valid").jsonArray[1].jsonObject
        return assertIs<PhoneUpdateProgressFrame.Response>(PhoneUpdateProgressFrame.decode(frameHex(row.frameText("hex"))))
    }
}
