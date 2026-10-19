package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

class PhonePushRegistrationFrameTest {
    private val id = ByteArray(16) { it.toByte() }
    private fun vectors() = Json.parseToJsonElement(File(System.getProperty("remozio.pushRegistrationVectors")).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun binding() = GatewayTokenBinding(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
        ByteArray(16) { 4 }, ByteArray(16) { 5 }, ByteArray(16) { 6 }, ByteArray(16) { 7 }, ByteArray(16) { 8 },
        ByteArray(32) { 9 }, ByteArray(32) { 170.toByte() }, ByteArray(32) { 11 })
    private fun metadata() = PhonePushRegistrationMetadata(GatewayTokenCandidate(binding(), 7u, ByteArray(16) { 12 }, 1000u, 2000u))
    @Test fun sharedVectorsRetainTheirRolesAndCanonicalBytes() {
        val values = vectors()
        assertEquals(values.getValue("applicationProtocol").jsonPrimitive.content, PhonePushRegistrationFrame.APPLICATION_PROTOCOL)
        for (value in values.getValue("valid").jsonArray) {
            val row = value.jsonObject; val bytes = hex(row.getValue("hex").jsonPrimitive.content)
            val frame = PhonePushRegistrationFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode()); assertContentEquals(id, frame.correlationID.copyBytes())
            assertEquals("PhonePushRegistrationFrame(redacted)", frame.toString())
            when (val name = row.getValue("name").jsonPrimitive.content) {
                "offer" -> assertEquals("synthetic-token", assertIs<PhonePushRegistrationFrame.Offer>(frame).offer.token)
                "prepared" -> assertContentEquals(binding().tokenDigest, assertIs<PhonePushRegistrationFrame.Prepared>(frame).metadata.tokenDigest)
                "proof" -> assertEquals(binding(), assertIs<PhonePushRegistrationFrame.Proof>(frame).proof.binding)
                else -> assertEquals(name.removePrefix("outcome-").toULong(), assertIs<PhonePushRegistrationFrame.Outcome>(frame).outcome.tag)
            }
        }
    }
    @Test fun hostileAndConfusedContractsFail() {
        for (value in vectors().getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) {
                PhonePushRegistrationFrame.decode(hex(row.getValue("hex").jsonPrimitive.content))
            }
        }
    }
    @Test fun fetchableMetadataCannotRevealTheProviderChallenge() {
        val m = metadata()
        val frame = PhonePushRegistrationFrame.Prepared(id, m)
        val bytes = frame.encode()
        assertFalse(bytes.toList().windowed(32).any { it.all { b -> b == 170.toByte() } })
        val challenge = PushData.TokenChallenge(binding().candidateID, binding().challenge, binding().enrollmentTag)
        assertEquals(binding(), m.proof(challenge).binding)
        assertEquals("PhonePushRegistrationMetadata(redacted)", m.toString())
        assertFails { m.proof(PushData.TokenChallenge(ByteArray(16), binding().challenge, binding().enrollmentTag)) }
        assertFails { m.proof(PushData.TokenChallenge(binding().candidateID, binding().challenge, ByteArray(32))) }
    }
    @Test fun offeredTokensAndCorrelationIDsAreNotMutableOrPrintable() {
        val source = id.copyOf()
        val offer = PhonePushTokenOffer("secret-provider-token", "project", "123", "dev.remozio.android")
        val frame = PhonePushRegistrationFrame.Offer(source, offer); val before = frame.encode(); source.fill(0)
        assertContentEquals(before, frame.encode()); assertFalse(frame.toString().contains(offer.token))
        assertEquals("PhonePushTokenOffer(redacted)", offer.toString())
    }
    @Test fun providerRoutingHintsCannotCarryControlCharactersOrInvalidShapes() {
        for (token in listOf("", "space token", "newline\n", "x".repeat(4097))) {
            assertFails { PhonePushTokenOffer(token, "project", "123", "dev.remozio.android") }
        }
        assertFails { PhonePushTokenOffer("token", "project\n", "123", "dev.remozio.android") }
        assertFails { PhonePushTokenOffer("token", "project", "١", "dev.remozio.android") }
        assertFails { PhonePushTokenOffer("token", "project", "123", "package") }
        assertFails { PhonePushRegistrationFrame.Outcome(ByteArray(15), PhonePushRegistrationOutcome.UNAVAILABLE) }
    }
    @Test fun proofCommitIsNotMappingConfirmationOrDelivery() {
        assertNotEquals(PhonePushRegistrationOutcome.PROOF_COMMITTED.tag, PhonePushRegistrationOutcome.MAPPING_CONFIRMED.tag)
        assertEquals(setOf(0uL, 1uL, 2uL, 3uL, 4uL, 5uL), PhonePushRegistrationOutcome.entries.map { it.tag }.toSet())
    }
}
