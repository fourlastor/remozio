package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.*
import kotlin.test.*

class PhonePushRecoveryFrameTest {
    private val id = ByteArray(16) { it.toByte() }
    private fun vectors(property: String = "remozio.pushRecoveryVectors") = Json.parseToJsonElement(File(System.getProperty(property)).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun binding() = GatewayTokenBinding(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
        ByteArray(16) { 4 }, ByteArray(16) { 5 }, ByteArray(16) { 6 }, ByteArray(16) { 7 }, ByteArray(16) { 8 },
        ByteArray(32) { 9 }, ByteArray(32) { 170.toByte() }, ByteArray(32) { 11 })
    private fun metadata() = PhonePushRegistrationMetadata(GatewayTokenCandidate(binding(), 7u, ByteArray(16) { 12 }, 1000u, 2000u))
    @Test fun sharedVectorsKeepRolesAndCanonicalBytes() {
        val values = vectors()
        assertEquals(values.getValue("applicationProtocol").jsonPrimitive.content, PhonePushRecoveryFrame.APPLICATION_PROTOCOL)
        for (value in values.getValue("valid").jsonArray) {
            val row = value.jsonObject; val name = row.getValue("name").jsonPrimitive.content
            val bytes = hex(row.getValue("hex").jsonPrimitive.content); val frame = PhonePushRecoveryFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode()); assertContentEquals(id, frame.correlationID.copyBytes())
            assertEquals("PhonePushRecoveryFrame(redacted)", frame.toString())
            when (frame) {
                is PhonePushRecoveryFrame.Probe -> assertEquals("probe", name)
                is PhonePushRecoveryFrame.Ready -> assertEquals("ready", name)
                is PhonePushRecoveryFrame.Resume -> { assertEquals("resume", name); assertEquals("synthetic-token", frame.offer.token) }
                is PhonePushRecoveryFrame.State -> {
                    assertContentEquals(binding().tokenDigest, frame.state.metadata.tokenDigest)
                    val phase = when (name) {
                        "awaiting-proof" -> PhonePushRecoveryPhase.AWAITING_PROVIDER_PROOF
                        "proof-committed" -> PhonePushRecoveryPhase.PROOF_COMMITTED
                        else -> PhonePushRecoveryPhase.MAPPING_OBSERVED
                    }
                    assertEquals(phase, frame.state.phase)
                    val age = when (name) { "mapping-observed-new" -> 0uL; "mapping-observed-boundary" -> 4999uL; else -> null }
                    assertEquals(age, frame.state.observationAgeMilliseconds)
                }
                is PhonePushRecoveryFrame.Outcome -> assertEquals(name.removePrefix("failure-").toULong(), frame.failure.tag)
            }
        }
    }
    @Test fun readinessContainsOnlyCorrelationAndFixedCapabilityFields() {
        val limits = CborLimits(8192, 4, 64)
        val probe = (DeterministicCbor.decode(PhonePushRecoveryFrame.Probe(id).encode(), limits) as CborValue.Fields).values
        val ready = (DeterministicCbor.decode(PhonePushRecoveryFrame.Ready(id).encode(), limits) as CborValue.Fields).values
        assertEquals(CborValue.Null, probe[4u]); assertEquals(CborValue.Unsigned(2u), ready[4u])
        assertEquals(CborValue.Bytes(id), probe[3u]); assertEquals(probe[3u], ready[3u])
    }
    @Test fun hostileVersionsRolesAndAgesFail() {
        for (value in vectors().getValue("invalid").jsonArray) {
            val row = value.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) { PhonePushRecoveryFrame.decode(hex(row.getValue("hex").jsonPrimitive.content)) }
        }
    }
    @Test fun version1BytesRemainSeparateAndUnchanged() {
        for (value in vectors("remozio.pushRegistrationVectors").getValue("valid").jsonArray) {
            val bytes = hex(value.jsonObject.getValue("hex").jsonPrimitive.content)
            assertContentEquals(bytes, PhonePushRegistrationFrame.decode(bytes).encode())
            assertFails { PhonePushRecoveryFrame.decode(bytes) }
        }
        for (value in vectors().getValue("valid").jsonArray) {
            assertFails { PhonePushRegistrationFrame.decode(hex(value.jsonObject.getValue("hex").jsonPrimitive.content)) }
        }
    }
    @Test fun committedMappingKeepsHistoricalProofExpiry() {
        val state = PhonePushRecoveryState(metadata(), PhonePushRecoveryPhase.MAPPING_OBSERVED, 0u)
        val bytes = PhonePushRecoveryFrame.State(id, state).encode()
        val decoded = assertIs<PhonePushRecoveryFrame.State>(PhonePushRecoveryFrame.decode(bytes)).state
        assertEquals(2000uL, decoded.metadata.expiresAtUnixMillis)
        assertEquals(PhonePushRecoveryPhase.MAPPING_OBSERVED, decoded.phase); assertEquals(0uL, decoded.observationAgeMilliseconds)
    }
    @Test fun stateExcludesChallengeAndRedactsDescriptions() {
        val state = PhonePushRecoveryState(metadata(), PhonePushRecoveryPhase.PROOF_COMMITTED)
        val bytes = PhonePushRecoveryFrame.State(id, state).encode()
        assertFalse(bytes.toList().windowed(32).any { it.all { b -> b == 170.toByte() } })
        assertEquals("PhonePushRecoveryState(redacted)", state.toString())
        val source = id.copyOf(); val offer = PhonePushTokenOffer("private-provider-token", "project", "123", "dev.remozio.android")
        val frame = PhonePushRecoveryFrame.Resume(source, offer); val before = frame.encode(); source.fill(0)
        assertContentEquals(before, frame.encode()); assertFalse(frame.toString().contains(offer.token))
    }
    @Test fun invalidStateAgesAndCorrelationsFailBeforeEncoding() {
        for (phase in listOf(PhonePushRecoveryPhase.AWAITING_PROVIDER_PROOF, PhonePushRecoveryPhase.PROOF_COMMITTED)) {
            assertFails { PhonePushRecoveryState(metadata(), phase, 0u) }
        }
        assertFails { PhonePushRecoveryState(metadata(), PhonePushRecoveryPhase.MAPPING_OBSERVED) }
        assertFails { PhonePushRecoveryState(metadata(), PhonePushRecoveryPhase.MAPPING_OBSERVED, 5000u) }
        assertFails { PhonePushRecoveryFrame.Outcome(ByteArray(15), PhonePushRecoveryFailure.UNAVAILABLE) }
        assertNotEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, PhonePushRecoveryPhase.MAPPING_OBSERVED)
    }
}
