package dev.remozio.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class EnvelopeVersionPolicyTest {
    @Test fun picksHighestSharedVersionNotBelowTheTrustedMinimum() {
        assertEquals(3uL, selectEnvelopeVersion(setOf(1uL, 2uL, 3uL), setOf(2uL, 3uL, 4uL), 2uL))
        assertEquals(2uL, selectEnvelopeVersion(setOf(1uL, 2uL), setOf(1uL, 2uL, 5uL), 1uL))
    }

    @Test fun rejectsZeroMinimumEmptyOverlapAndOverlapBelowMinimum() {
        assertEquals(CompatibilityFailure.INVALID_POLICY,
            assertFailsWith<CompatibilityException> { selectEnvelopeVersion(setOf(1uL), setOf(1uL), 0uL) }.reason)
        assertEquals(CompatibilityFailure.NO_SAFE_ENVELOPE_VERSION,
            assertFailsWith<CompatibilityException> { selectEnvelopeVersion(setOf(1uL), setOf(2uL), 1uL) }.reason)
        assertEquals(CompatibilityFailure.NO_SAFE_ENVELOPE_VERSION,
            assertFailsWith<CompatibilityException> { selectEnvelopeVersion(setOf(1uL, 2uL), setOf(1uL, 2uL), 3uL) }.reason)
    }
}
