package dev.remozio.protocol

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.assertTrue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs

class PairingRecoveryFrameTest {
    @Test fun sharedRecoveryFramesRoundTripIncludingBothSignedExpiryReasons() {
        val vectors = Json.parseToJsonElement(TestVectors.pairingRecoveryFrames).jsonObject
        fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        fun bytes(key: String) = hex(vectors.getValue(key).jsonPrimitive.content)
        val transcript = PairingTranscript.decode(bytes("transcript"))
        for ((name, value) in vectors.getValue("frames").jsonObject) {
            val payload = hex(value.jsonPrimitive.content)
            val frame = PairingRecoveryFrame.decode(payload)
            assertContentEquals(payload, frame.encode(), name)
            when {
                name == "lookup" -> assertContentEquals(bytes("signingInput"),
                    assertIs<PairingRecoveryFrame.Lookup>(frame).query.signingInput(bytes("exporter"), bytes("challenge")))
                name.startsWith("expired-") -> {
                    val expiry = assertIs<PairingRecoveryFrame.Expired>(frame).receipt
                    assertEquals(name.last().digitToInt().toULong(), expiry.reason.tag)
                    assertTrue(expiry.verify(transcript), name)
                }
            }
        }
    }

    @Test fun lookupAndProofInputMatchTheMacWireOrder() {
        val setup = ByteArray(16) { 1 }
        val digest = ByteArray(32) { 2 }
        val ids = (3..6).map { value -> ByteArray(16) { value.toByte() } }
        val scope = ChannelScope(ids[0], ids[1], ids[2], ids[3])
        val lookup = byteArrayOf(0) + setup + digest + ids[0] + ids[1] + ids[2] + ids[3]
        val exporter = ByteArray(32) { 7 }
        val challenge = ByteArray(32) { 8 }
        val query = assertIs<PairingRecoveryFrame.Lookup>(PairingRecoveryFrame.decode(lookup)).query
        assertEquals(scope, query.scope)
        assertContentEquals(lookup, PairingRecoveryFrame.Lookup(query).encode())
        assertContentEquals(
            "dev.remozio.pairing.recovery-lookup/1".encodeToByteArray() + byteArrayOf(0) + exporter + challenge +
                lookup.copyOfRange(1, lookup.size),
            query.signingInput(exporter, challenge),
        )
        assertFails { query.signingInput(exporter.copyOf(31), challenge) }
    }

    @Test fun recoveryFramesRejectWrongTagsAndLengths() {
        val valid = listOf(
            byteArrayOf(1) + ByteArray(32),
            byteArrayOf(2) + ByteArray(64),
            byteArrayOf(3),
            byteArrayOf(4) + ByteArray(64),
        )
        for (frame in valid) {
            assertContentEquals(frame, PairingRecoveryFrame.decode(frame).encode())
            assertFails { PairingRecoveryFrame.decode(frame.copyOf(frame.size + 1)) }
            assertFails { PairingRecoveryFrame.decode(frame.copyOf(frame.size - 1)) }
        }
        assertFails { PairingRecoveryFrame.decode(byteArrayOf(6)) }
        assertFails { PairingRecoveryFrame.decode(ByteArray(PairingRecoveryFrame.MAXIMUM_BYTES + 1)) }
    }
}
