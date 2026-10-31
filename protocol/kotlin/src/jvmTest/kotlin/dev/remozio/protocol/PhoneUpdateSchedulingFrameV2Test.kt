package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

private fun v2Hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun JsonObject.v2Text(name: String) = getValue(name).jsonPrimitive.content

class PhoneUpdateSchedulingFrameV2Test {
    private val limits = CborLimits(16384, 4, 64)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(
        System.getProperty("remozio.phoneUpdateSchedulingV2Vectors"))).readText()).jsonObject
    private fun rows() = vectors().getValue("rows").jsonArray.map { it.jsonObject }
    private fun fields(bytes: ByteArray) = (DeterministicCbor.decode(bytes, limits) as CborValue.Fields).values
    private fun encode(fields: Map<ULong, CborValue>) = DeterministicCbor.encode(CborValue.Fields(fields), limits)

    @Test fun sharedRequestsAndRepliesHaveExactCanonicalVersion2Bytes() {
        assertEquals(8, rows().size)
        for (row in rows()) {
            val request = PhoneUpdateSchedulingFrame.decode(v2Hex(row.v2Text("requestV1")))
            val wrapped = PhoneUpdateSchedulingFrameV2.Message(request)
            assertContentEquals(v2Hex(row.v2Text("requestV2")), wrapped.encode())
            val reply = assertIs<PhoneUpdateSchedulingFrameV2.TooLate>(
                PhoneUpdateSchedulingFrameV2.decode(v2Hex(row.v2Text("replyV2"))))
            assertContentEquals(v2Hex(row.v2Text("replyV2")), reply.encode())
            assertEquals(request.queryNonce, reply.queryNonce)
            assertContentEquals(v2Hex(row.v2Text("payload")), reply.canonicalPayload.copyBytes())
            assertContentEquals(v2Hex(row.v2Text("signature")), reply.signature.copyBytes())
        }
    }

    @Test fun version1AndVersion2CannotBeSubstitutedInEitherDirection() {
        for (row in rows()) {
            assertFails { PhoneUpdateSchedulingFrame.decode(v2Hex(row.v2Text("requestV2"))) }
            assertFails { PhoneUpdateSchedulingFrame.decode(v2Hex(row.v2Text("replyV2"))) }
            assertFails { PhoneUpdateSchedulingFrameV2.decode(v2Hex(row.v2Text("requestV1"))) }
        }
        assertEquals("remozio-update-scheduling/2", PhoneUpdateSchedulingFrameV2.APPLICATION_PROTOCOL)
        assertNotEquals(PhoneUpdateSchedulingFrame.APPLICATION_PROTOCOL, PhoneUpdateSchedulingFrameV2.APPLICATION_PROTOCOL)
    }

    @Test fun allExistingRolesRetainTheirOriginalCanonicalMeaningAndBounds() {
        val row = rows().first(); val request = PhoneUpdateSchedulingFrame.decode(v2Hex(row.v2Text("requestV1")))
        val late = UpdateSchedulingTooLateResponse.decode(v2Hex(row.v2Text("payload")))
        val nonce = request.queryNonce.copyBytes()
        val apply = rows().first { it.v2Text("name").endsWith("apply") }.let {
            PhoneUpdateSchedulingFrame.decode(v2Hex(it.v2Text("requestV1"))) as PhoneUpdateSchedulingFrame.Apply
        }
        val challenge = RootUpdateSchedulingChallenge(nonce, apply.canonicalControl.copyBytes(), CborLimits(2048, 2, 32))
            .encode(CborLimits(2048, 2, 32))
        val frames = listOf(PhoneUpdateSchedulingFrame.Status(nonce), request, apply,
            PhoneUpdateSchedulingFrame.ChallengeResponse(nonce, challenge, ByteArray(64)),
            PhoneUpdateSchedulingFrame.StateResponse(nonce, late.progress.status.encode(), ByteArray(64)),
            PhoneUpdateSchedulingFrame.Failure(nonce, PhoneUpdateSchedulingFailure.UNAVAILABLE))
        for (frame in frames) {
            val decoded = assertIs<PhoneUpdateSchedulingFrameV2.Message>(
                PhoneUpdateSchedulingFrameV2.decode(PhoneUpdateSchedulingFrameV2.Message(frame).encode()))
            assertContentEquals(frame.encode(), decoded.frame.encode())
        }
    }

    @Test fun everyRootSignatureAndRequestDigestRemainBoundToTheOriginalRequest() {
        val key = v2Hex(vectors().v2Text("publicKey"))
        for (row in rows()) {
            val request = assertIs<PhoneUpdateSchedulingFrameV2.Message>(
                PhoneUpdateSchedulingFrameV2.decode(v2Hex(row.v2Text("requestV2")))).frame
            val reply = assertIs<PhoneUpdateSchedulingFrameV2.TooLate>(
                PhoneUpdateSchedulingFrameV2.decode(v2Hex(row.v2Text("replyV2"))))
            val value = UpdateSchedulingTooLateResponse.decode(reply.canonicalPayload.copyBytes())
            assertTrue(value.matches(request, value.progress.status.scope))
            assertTrue(UpdateSchedulingTooLateSignature.verify(reply.signature.copyBytes(), key, 1u,
                reply.canonicalPayload.copyBytes(), CborLimits(8192, 2, 32)))
        }
    }

    @Test fun unknownVersionsKindsFieldsMalformedPairsAndOversizedMessagesAreRejected() {
        val source = fields(v2Hex(rows().first().v2Text("replyV2")))
        for (changed in listOf(source + (1uL to CborValue.Unsigned(3u)), source + (2uL to CborValue.Unsigned(7u)),
            source + (5uL to CborValue.Null), source - 3uL,
            source + (4uL to CborValue.ArrayValue(emptyList())),
            source + (3uL to CborValue.Bytes(ByteArray(32) { 99 })),
            source + (4uL to CborValue.ArrayValue(listOf(CborValue.Bytes(ByteArray(8193)), CborValue.Bytes(ByteArray(64))))))) {
            assertFails { PhoneUpdateSchedulingFrameV2.decode(encode(changed)) }
        }
        assertFails { PhoneUpdateSchedulingFrameV2.decode(ByteArray(PhoneUpdateSchedulingFrameV2.MAXIMUM_BYTES + 1)) }
        val pair = (source.getValue(4u) as CborValue.ArrayValue).values
        assertFails { PhoneUpdateSchedulingFrameV2.decode(encode(source + (4uL to CborValue.ArrayValue(
            listOf(pair[0], CborValue.Bytes(ByteArray(63))))))) }
    }

    @Test fun defensiveCopiesAndDescriptionsDoNotExposeOrReplaceThePayload() {
        val row = rows().first(); val nonce = PhoneUpdateSchedulingFrame.decode(v2Hex(row.v2Text("requestV1"))).queryNonce.copyBytes()
        val body = v2Hex(row.v2Text("payload")); val signature = v2Hex(row.v2Text("signature"))
        val frame = PhoneUpdateSchedulingFrameV2.TooLate(nonce, body, signature); val original = frame.encode()
        nonce.fill(0); body.fill(0); signature.fill(0); frame.signature.copyBytes().fill(0)
        assertContentEquals(original, frame.encode()); assertEquals("PhoneUpdateSchedulingFrameV2(redacted)", frame.toString())
    }
}
