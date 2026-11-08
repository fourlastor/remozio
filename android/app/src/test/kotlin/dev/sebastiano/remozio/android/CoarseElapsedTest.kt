package dev.sebastiano.remozio.android

import kotlin.test.Test
import kotlin.test.assertEquals

class CoarseElapsedTest {
    @Test fun agesBelowOneMinuteShareOneLabel() {
        assertEquals(CoarseElapsed(ElapsedUnit.UNDER_MINUTE, 0), coarseElapsed(0u))
        assertEquals(CoarseElapsed(ElapsedUnit.UNDER_MINUTE, 0), coarseElapsed(59_999u))
    }

    @Test fun eachUnitStartsAtItsBoundaryAndRoundsDown() {
        assertEquals(CoarseElapsed(ElapsedUnit.MINUTES, 1), coarseElapsed(60_000u))
        assertEquals(CoarseElapsed(ElapsedUnit.MINUTES, 59), coarseElapsed(3_599_999u))
        assertEquals(CoarseElapsed(ElapsedUnit.HOURS, 1), coarseElapsed(3_600_000u))
        assertEquals(CoarseElapsed(ElapsedUnit.HOURS, 23), coarseElapsed(86_399_999u))
        assertEquals(CoarseElapsed(ElapsedUnit.DAYS, 1), coarseElapsed(86_400_000u))
    }

    @Test fun theTextChangesAtMostOncePerMinute() {
        val labels = (0uL until 3_600_000uL step 1000L).map(::coarseElapsed)
        assertEquals(60, labels.distinct().size)
        assertEquals(59, labels.zipWithNext().count { (a, b) -> a != b })
    }

    @Test fun theLargestAgeStaysInRange() {
        assertEquals(CoarseElapsed(ElapsedUnit.DAYS, (ULong.MAX_VALUE / 86_400_000uL).toLong()), coarseElapsed(ULong.MAX_VALUE))
    }
}
