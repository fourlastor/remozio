package dev.sebastiano.remozio.android.routing

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.verifiedSyntheticRouting
import dev.remozio.phone.transport.PhoneRoutingResult
import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class MacRoutingDisplayTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private inner class Fixture {
        val root = key()
        var nanos = 1_000_000L
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(3), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, key()), local(EnrollmentKeyRole.BIOMETRIC, key()),
            ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        suspend fun verified(mode: RoutingStatusMode = RoutingStatusMode.PRESENT): PhoneRoutingResult.Verified {
            val state = RoutingStatusState(mode, 1u,
                if (mode == RoutingStatusMode.AWAY) RoutingStatusDestination.PHONES else RoutingStatusDestination.LOCAL_MAC,
                if (mode == RoutingStatusMode.AWAY) RoutingStatusReason.MANUAL_AWAY else RoutingStatusReason.MANUAL_PRESENT, false)
            val response = RoutingStatusResponse(ChannelScope(id(20), id(21), id(3), id(4)), ByteArray(32) { 31 },
                RoutingStatusOutcome.STATUS, id(30), 100u, state)
            return verifiedSyntheticRouting(record, root.private, response, { nanos })
        }
    }
    @Test fun unavailableOwnersNeverClaimCurrentModeEvenWithARecentSignedSample() = runTest {
        val f = Fixture(); val signed = f.verified()
        for (availability in listOf(MacRoutingAvailability.OFFLINE, MacRoutingAvailability.INCOMPATIBLE, MacRoutingAvailability.CLOSED)) {
            val display = routingDisplay(MacRoutingStatus(availability, signed), 1000, true)
            assertEquals(availability, display.availability)
            assertNull(display.currentMode); assertEquals(RoutingStatusMode.PRESENT, display.lastKnownMode)
            assertNull(display.destination); assertNull(display.reason); assertFalse(display.canSetAway)
        }
    }
    @Test fun aMissingObservationCannotClaimConnectivityOrEnableAway() {
        val display = routingDisplay(MacRoutingStatus(MacRoutingAvailability.ONLINE), 1000, true)
        assertEquals(MacRoutingAvailability.OFFLINE, display.availability)
        assertNull(display.currentMode); assertNull(display.lastKnownMode); assertFalse(display.canSetAway)
    }
    @Test fun expiryChangesCurrentStateToLastKnownAtTheExactBoundary() = runTest {
        val f = Fixture(); val signed = f.verified(); val status = MacRoutingStatus(MacRoutingAvailability.ONLINE, signed)
        val fresh = routingDisplay(status, 1000, true)
        assertEquals(RoutingStatusMode.PRESENT, fresh.currentMode); assertNull(fresh.lastKnownMode); assertTrue(fresh.canSetAway)
        f.nanos += 1_000_000_000
        val expired = routingDisplay(status, 1000, true)
        assertEquals(MacRoutingAvailability.OFFLINE, expired.availability)
        assertNull(expired.currentMode); assertEquals(RoutingStatusMode.PRESENT, expired.lastKnownMode)
        assertNull(expired.destination); assertFalse(expired.canSetAway)
    }
    @Test fun clockFailureCannotRecoverAFreshClaimFromALaterRead() = runTest {
        val f = Fixture(); val signed = f.verified(); val status = MacRoutingStatus(MacRoutingAvailability.ONLINE, signed)
        f.nanos = 0
        val invalid = routingDisplay(status, 1000, true)
        assertEquals(MacRoutingAvailability.OFFLINE, invalid.availability); assertNull(invalid.sampleAgeMilliseconds)
        f.nanos = 2_000_000
        val later = routingDisplay(status, 1000, true)
        assertNull(later.currentMode); assertFalse(later.canSetAway)
    }
    @Test fun aNewStatusObservationCannotResolveAnUnknownChangeOutcome() = runTest {
        val f = Fixture(); val signed = f.verified(RoutingStatusMode.AWAY)
        val display = routingDisplay(MacRoutingStatus(MacRoutingAvailability.ONLINE, signed, MacRoutingAction.UNCERTAIN), 1000, true)
        assertEquals(RoutingStatusMode.AWAY, display.currentMode)
        assertEquals(MacRoutingAction.UNCERTAIN, display.action); assertFalse(display.canSetAway)
    }
    @Test fun displayNeverBroadensTheOwnersActionEligibility() = runTest {
        val f = Fixture(); val signed = f.verified()
        assertFalse(routingDisplay(MacRoutingStatus(MacRoutingAvailability.ONLINE, signed), 1000, false).canSetAway)
        assertFalse(routingDisplay(MacRoutingStatus(MacRoutingAvailability.ONLINE, signed, MacRoutingAction.SETTING_AWAY), 1000, true).canSetAway)
    }
}
