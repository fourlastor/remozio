package dev.remozio.phone.push

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.PushData
import org.junit.Assert.*
import org.junit.Test

class PushWakeRouterTest {
    private fun bytes(value: Int, size: Int = 16) = ByteArray(size) { value.toByte() }
    private fun router(cache: Int = 8) = PushWakeRouter(4, 8, cache, 100uL, 10uL)
    private fun add(r: PushWakeRouter, mac: Int = 1, account: Int = 2, tag: Int = 3) =
        r.add(bytes(mac), bytes(account), bytes(4), bytes(tag, 32))
    private fun wake(e: WakeEnrollment, id: Int = 1) = PushData.Wake(bytes(id, 32), e.notificationTag.copyBytes()).encode()
    private fun receive(r: PushWakeRouter, e: WakeEnrollment, id: Int = 1, time: ULong = 0uL) =
        r.receive(wake(e, id), { ElapsedInstant(1, time) }) { _, _ -> WakeNotificationResult.POSTED }

    @Test fun untrustedFieldsAndChallengesNeverScheduleRequestFetches() {
        val r = router(); val e = add(r)
        var calls = 0
        val notify: (WakeEnrollment, Boolean) -> WakeNotificationResult = { _, _ -> calls++; WakeNotificationResult.POSTED }
        assertEquals(WakeReception.MALFORMED, r.receive(wake(e) + ("endpoint" to "attacker"), { ElapsedInstant(1, 0uL) }, notify).reception)
        assertEquals(WakeReception.UNKNOWN_ENROLLMENT, r.receive(PushData.Wake(bytes(1, 32), bytes(9, 32)).encode(), { ElapsedInstant(1, 0uL) }, notify).reception)
        assertEquals(WakeReception.TOKEN_CHALLENGE, r.receive(PushData.TokenChallenge(bytes(8), bytes(7, 32), e.notificationTag.copyBytes()).encode(), { ElapsedInstant(1, 0uL) }, notify).reception)
        assertEquals(0, calls); assertNull(r.beginFetch(e))
    }

    @Test fun notificationPrecedesDemandAndFailureStillAllowsFetch() {
        for (result in WakeNotificationResult.entries) {
            val r = router(); val e = add(r)
            val receipt = r.receive(wake(e), { ElapsedInstant(1, 0uL) }) { selected, alert ->
                assertSame(e, selected); assertTrue(alert); assertNull(r.beginFetch(e)); result
            }
            assertEquals(result, receipt.notification)
            assertNotNull(r.beginFetch(e))
        }
        val r = router(); val e = add(r)
        assertEquals(WakeNotificationResult.FAILED, r.receive(wake(e), { ElapsedInstant(1, 0uL) }) { _, _ -> error("platform failed") }.notification)
        assertNotNull(r.beginFetch(e))
    }

    @Test fun wakesCoalesceButArrivalDuringFetchRequiresAnotherFetch() {
        val r = router(); val e = add(r)
        receive(r, e); receive(r, e, 2)
        val first = requireNotNull(r.beginFetch(e)); assertNull(r.beginFetch(e))
        assertEquals(WakeReception.DUPLICATE, receive(r, e, 2).reception)
        receive(r, e, 3)
        assertTrue(r.finishFetch(first, true))
        val second = requireNotNull(r.beginFetch(e))
        assertFalse(r.finishFetch(first, false)); assertTrue(r.isCurrent(second))
        assertTrue(r.finishFetch(second, true)); assertNull(r.beginFetch(e))
    }

    @Test fun duplicateDuringFetchDoesNotCreateAnotherFetch() {
        val r = router(); val e = add(r); receive(r, e)
        val flight = requireNotNull(r.beginFetch(e)); receive(r, e)
        assertTrue(r.finishFetch(flight, true)); assertNull(r.beginFetch(e))
    }

    @Test fun failedMacDoesNotBlockOtherMacOrAccount() {
        val r = router(); val a = add(r); val b = add(r, mac = 5, tag = 6); val c = add(r, account = 7, tag = 8)
        listOf(a, b, c).forEach { assertEquals(WakeReception.ACCEPTED, receive(r, it).reception) }
        val fa = requireNotNull(r.beginFetch(a)); val fb = requireNotNull(r.beginFetch(b)); val fc = requireNotNull(r.beginFetch(c))
        assertTrue(r.finishFetch(fa, false)); assertNotNull(r.beginFetch(a))
        assertTrue(r.finishFetch(fb, true)); assertTrue(r.finishFetch(fc, true))
        assertNull(r.beginFetch(b)); assertNull(r.beginFetch(c))
    }

    @Test fun alertsHaveIndependentFloorsAndFailedPostsDoNotAdvanceThem() {
        val r = router(); val a = add(r); val b = add(r, mac = 5, tag = 6)
        val alerts = mutableListOf<Boolean>()
        fun post(e: WakeEnrollment, id: Int, time: ULong, result: WakeNotificationResult = WakeNotificationResult.POSTED) =
            r.receive(wake(e, id), { ElapsedInstant(1, time) }) { _, alert -> alerts += alert; result }
        post(a, 1, 0uL, WakeNotificationResult.PERMISSION_DENIED)
        post(a, 2, 1uL); post(a, 3, 2uL); post(b, 1, 2uL); post(a, 4, 11uL)
        post(a, 4, 12uL)
        assertEquals(listOf(true, true, false, true, true), alerts)
    }

    @Test fun hintEvictionAndExpiryNeverDiscardFetchDemand() {
        val r = router(cache = 1); val a = add(r); val b = add(r, mac = 5, tag = 6)
        receive(r, a); receive(r, b)
        assertEquals(WakeReception.ACCEPTED, receive(r, a).reception)
        assertEquals(WakeReception.DUPLICATE, receive(r, a, time = 99uL).reception)
        assertEquals(WakeReception.ACCEPTED, receive(r, a, time = 100uL).reception)
        assertNotNull(r.beginFetch(a)); assertNotNull(r.beginFetch(b))
    }

    @Test fun removalInvalidatesFlightAndRetiredTagCannotSelectReplacement() {
        val r = router(); val old = add(r); receive(r, old)
        val flight = requireNotNull(r.beginFetch(old)); assertTrue(r.remove(old))
        assertThrows(IllegalArgumentException::class.java) { add(r) }
        val replacement = add(r, tag = 9)
        assertFalse(r.remove(old)); assertFalse(r.isCurrent(flight)); assertFalse(r.finishFetch(flight, false))
        assertEquals(WakeReception.UNKNOWN_ENROLLMENT, receive(r, old).reception)
        assertNull(r.beginFetch(replacement)); receive(r, replacement); assertNotNull(r.beginFetch(replacement))
    }

    @Test fun clockDiscontinuityClosesOnlyThisProcessOwner() {
        for (bad in listOf(ElapsedInstant(2, 10uL), ElapsedInstant(1, 9uL))) {
            val r = router(); val e = add(r); receive(r, e, time = 10uL)
            val flight = requireNotNull(r.beginFetch(e))
            assertEquals(WakeReception.INVALID_CLOCK, r.receive(wake(e), { bad }) { _, _ -> error("must not notify") }.reception)
            assertFalse(r.isCurrent(flight)); assertNull(r.beginFetch(e))
            assertEquals(WakeReception.CLOSED, receive(r, e, time = 11uL).reception)
            assertThrows(IllegalStateException::class.java) { add(r, tag = 9) }
        }
    }

    @Test fun concurrentReceiptsSampleClockInsideTheRouterLock() {
        val r = router(); val e = add(r)
        val ticks = java.util.concurrent.atomic.AtomicLong()
        val pool = java.util.concurrent.Executors.newFixedThreadPool(4)
        try {
            val jobs = (1..100).map { id -> pool.submit<WakeReceipt> {
                r.receive(wake(e, id), {
                    assertTrue(Thread.holdsLock(r))
                    ElapsedInstant(1, ticks.incrementAndGet().toULong())
                }) { _, _ -> WakeNotificationResult.POSTED }
            } }
            jobs.forEach { assertEquals(WakeReception.ACCEPTED, it.get(5, java.util.concurrent.TimeUnit.SECONDS).reception) }
            assertNotNull(r.beginFetch(e))
        } finally { pool.shutdownNow() }
    }

    @Test fun enrollmentBoundsRejectWithoutEvictingAndInputsAreCopied() {
        val r = PushWakeRouter(1, 2, 1, 100uL, 10uL)
        val mac = bytes(1); val tag = bytes(3, 32)
        val e = r.add(mac, bytes(2), bytes(4), tag)
        mac.fill(9); tag.fill(9)
        assertArrayEquals(bytes(1), e.macID.copyBytes()); assertArrayEquals(bytes(3, 32), e.notificationTag.copyBytes())
        assertThrows(IllegalArgumentException::class.java) { add(r, tag = 8) }
        assertThrows(IllegalStateException::class.java) { add(r, mac = 9, tag = 8) }
        receive(r, e); assertNotNull(r.beginFetch(e)); r.remove(e)
        val next = add(r, tag = 8); r.remove(next)
        assertThrows(IllegalStateException::class.java) { add(r, tag = 7) }
        assertEquals("WakeEnrollment(redacted)", e.toString())
    }
    @Test fun failedPersistenceRetryPreservesAlertFloorAndPendingFetch() {
        val r = router(); val e = add(r); val alerts = mutableListOf<Boolean>()
        fun deliver(time: ULong) = r.receive(wake(e), { ElapsedInstant(1, time) }) { _, alert ->
            alerts += alert; WakeNotificationResult.POSTED
        }
        assertEquals(WakeReception.ACCEPTED, deliver(0u).reception)
        assertTrue(r.retryWake(e, bytes(1, 32)))
        assertEquals(WakeReception.ACCEPTED, deliver(1u).reception)
        assertEquals(WakeReception.DUPLICATE, deliver(2u).reception)
        assertEquals(listOf(true, false), alerts); assertNotNull(r.beginFetch(e))
    }
    @Test fun retiredHandleCannotForgetAReplacementHint() {
        val r = router(); val old = add(r); receive(r, old); r.remove(old)
        val next = add(r, tag = 9); receive(r, next)
        assertFalse(r.retryWake(old, bytes(1, 32)))
        assertEquals(WakeReception.DUPLICATE, receive(r, next).reception)
        assertFalse(r.retryWake(next, bytes(8, 32)))
        assertThrows(IllegalArgumentException::class.java) { r.retryWake(next, bytes(1, 31)) }
        r.close(); assertFalse(r.retryWake(next, bytes(1, 32)))
    }

    @Test fun delayedPersistenceRetryCannotRingAgainAfterTheAlertFloor() {
        val r = router(); val e = add(r); val alerts = mutableListOf<Boolean>()
        fun deliver(time: ULong) = r.receive(wake(e), { ElapsedInstant(1, time) }) { _, alert ->
            alerts += alert; WakeNotificationResult.POSTED
        }
        deliver(0u); assertTrue(r.retryWake(e, bytes(1, 32)))
        assertEquals(WakeReception.ACCEPTED, deliver(11u).reception)
        assertEquals(listOf(true, false), alerts)
        val other = r.receive(wake(e, 2), { ElapsedInstant(1, 12u) }) { _, alert ->
            assertTrue(alert); WakeNotificationResult.POSTED
        }
        assertEquals(WakeReception.ACCEPTED, other.reception)
    }
    @Test fun persistenceRetryCanAlertWhenTheOriginalPlatformPostFailed() {
        val r = router(); val e = add(r)
        r.receive(wake(e), { ElapsedInstant(1, 0u) }) { _, alert -> assertTrue(alert); WakeNotificationResult.FAILED }
        assertTrue(r.retryWake(e, bytes(1, 32)))
        r.receive(wake(e), { ElapsedInstant(1, 11u) }) { _, alert -> assertTrue(alert); WakeNotificationResult.POSTED }
    }

}
