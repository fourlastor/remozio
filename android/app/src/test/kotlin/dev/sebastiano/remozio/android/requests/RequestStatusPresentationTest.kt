package dev.sebastiano.remozio.android.requests

import dev.remozio.phone.requests.RequestTiming
import dev.remozio.phone.requests.TrackedRequestStatus

import dev.remozio.protocol.RequestPhase
import dev.remozio.protocol.RequestStatusPayload
import dev.remozio.protocol.RequestStatusReason
import kotlin.test.Test
import kotlin.test.assertEquals

class RequestStatusPresentationTest {
    private fun snapshot(phase: RequestPhase, reason: RequestStatusReason, estimateRemaining: ULong? = null,
        clockUncertain: Boolean = false): TrackedRequestStatus {
        val id = ByteArray(16)
        val pending = phase == RequestPhase.QUEUED || phase == RequestPhase.PRESENTED
        val status = RequestStatusPayload(id, id, id, ByteArray(32), ByteArray(32), 1u, phase, reason, id,
            70_000u, if (pending) 0u else null, if (estimateRemaining == null) null else 60_000u,
            false, if (phase.isTerminal) 69_000u else null, null)
        return TrackedRequestStatus(status, RequestTiming(70_000u, if (pending) 0u else null, estimateRemaining, clockUncertain))
    }

    @Test fun elapsedEstimatesAndClockUncertaintyCannotChangeTheHeadline() {
        assertEquals(StatusHeadline.PRESENTED,
            statusHeadline(snapshot(RequestPhase.PRESENTED, RequestStatusReason.NONE, estimateRemaining = 0u)))
        assertEquals(StatusHeadline.PRESENTED,
            statusHeadline(snapshot(RequestPhase.PRESENTED, RequestStatusReason.NONE, estimateRemaining = 0u, clockUncertain = true)))
    }

    @Test fun distinguishesTargetTimeoutAuthorizationExpiryAndDisappearance() {
        assertEquals(StatusHeadline.TARGET_EXPIRED,
            statusHeadline(snapshot(RequestPhase.EXPIRED, RequestStatusReason.TARGET_TIMED_OUT)))
        assertEquals(StatusHeadline.AUTHORIZATION_EXPIRED,
            statusHeadline(snapshot(RequestPhase.EXPIRED, RequestStatusReason.AUTHORIZATION_EXPIRED)))
        assertEquals(StatusHeadline.DISAPPEARED,
            statusHeadline(snapshot(RequestPhase.CANCELLED, RequestStatusReason.TARGET_DISAPPEARED)))
    }

    @Test fun uncertainExecutionRemainsUnknownAfterRestartOrElapsedEstimate() {
        assertEquals(StatusHeadline.UNKNOWN,
            statusHeadline(snapshot(RequestPhase.UNKNOWN, RequestStatusReason.AUTHORITY_RESTARTED, estimateRemaining = 0u)))
        assertEquals(StatusHeadline.UNKNOWN,
            statusHeadline(snapshot(RequestPhase.UNKNOWN, RequestStatusReason.OUTCOME_UNAVAILABLE)))
    }

    @Test fun distinguishesCancellationEvidence() {
        assertEquals(StatusHeadline.CANCELLED, statusHeadline(snapshot(RequestPhase.CANCELLED, RequestStatusReason.USER_CANCELLED)))
        assertEquals(StatusHeadline.RESTART_CANCELLED, statusHeadline(snapshot(RequestPhase.CANCELLED, RequestStatusReason.AUTHORITY_RESTARTED)))
        assertEquals(StatusHeadline.NOT_DISPATCHED, statusHeadline(snapshot(RequestPhase.CANCELLED, RequestStatusReason.NO_DISPATCH_PROVED)))
    }

    @Test fun roundsAgeDownAndRemainingTimeUpWithoutOverflow() {
        assertEquals("0", seconds(999u))
        assertEquals("1", secondsCeiling(1u))
        assertEquals("1", secondsCeiling(1000u))
        assertEquals("2", secondsCeiling(1001u))
        assertEquals("18446744073709551", seconds(ULong.MAX_VALUE))
        assertEquals("18446744073709552", secondsCeiling(ULong.MAX_VALUE))
    }
}
