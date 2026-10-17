package dev.remozio.android.push

import dev.remozio.protocol.PushData
import org.junit.Test
import kotlin.test.*

class FCMDataRoutingTest {
    @Test fun challengeReachesOnlyThePrivateChallengeSink() {
        val expected = PushData.TokenChallenge(ByteArray(16) { 1 }, ByteArray(32) { 42 }, ByteArray(32) { 2 })
        var calls = 0
        assertTrue(dispatchFCMData(expected.encode(), { error("Challenge became a wake") }, { challenge ->
            calls++; assertContentEquals(expected.candidateID, challenge.candidateID)
            assertContentEquals(expected.enrollmentTag, challenge.enrollmentTag); assertContentEquals(expected.challenge, challenge.challenge)
        }))
        assertEquals(1, calls)
    }
    @Test fun ordinaryWakeKeepsItsExistingSink() {
        val expected = PushData.Wake(ByteArray(32) { 1 }, ByteArray(32) { 2 }); var calls = 0
        assertTrue(dispatchFCMData(expected.encode(), { wake -> calls++; assertContentEquals(expected.identifier, wake.identifier) },
            { error("Wake became a challenge") }))
        assertEquals(1, calls)
    }
    @Test fun malformedMixedAndUnknownFieldsReachNeitherSink() {
        val challenge = PushData.TokenChallenge(ByteArray(16), ByteArray(32), ByteArray(32)).encode()
        val wake = PushData.Wake(ByteArray(32), ByteArray(32)).encode()
        val bad = listOf(emptyMap(), challenge + wake, challenge + ("unexpected" to "secret"), challenge - "token_challenge_v1",
            challenge + ("token_challenge_v1" to "malformed"))
        for (data in bad) assertFalse(dispatchFCMData(data, { error("Malformed wake accepted") }, { error("Malformed challenge accepted") }))
    }
    @Test fun admissionFailureDoesNotFallBackToWakeOrRetryAnotherSink() {
        val expected = PushData.TokenChallenge(ByteArray(16), ByteArray(32), ByteArray(32)); var calls = 0
        assertFailsWith<IllegalStateException> { dispatchFCMData(expected.encode(), { error("Failed challenge became a wake") },
            { calls++; error("synthetic-storage-failure") }) }
        assertEquals(1, calls)
    }
}
