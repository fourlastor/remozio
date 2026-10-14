package dev.remozio.phone.transport

import java.io.IOException
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class PairingRouteSelectionTest {
    @Test fun hangingFirstHintDoesNotPreventALaterAuthenticatedRoute(): Unit = runTest {
        var blockedClosed = false
        val released = mutableListOf<Int>()
        val result = firstAuthenticatedPairingRoute(flowOf(1, 2), 1000, { route ->
            if (route == 1) try { awaitCancellation() } finally { blockedClosed = true }
            delay(100); route
        }, { released.add(it) })
        assertEquals(2, result)
        assertTrue(blockedClosed)
        assertTrue(released.isEmpty())
        assertEquals(100L, currentTime)
    }

    @Test fun failedAuthenticationDoesNotEndDiscoveryBeforeAValidRoute(): Unit = runTest {
        val attempts = mutableListOf<Int>()
        assertEquals(2, firstAuthenticatedPairingRoute(flowOf(1, 2), 1000, { route ->
            attempts.add(route)
            if (route == 1) throw IOException("Synthetic bad pin")
            route
        }, { }))
        assertEquals(listOf(1, 2), attempts)
    }

    @Test fun discoveryAndAuthenticationShareOneBudget(): Unit = runTest {
        var retired = false
        assertFailsWith<TimeoutCancellationException> {
            firstAuthenticatedPairingRoute(flow { delay(600); emit(1) }, 1000, {
                try { delay(600); it } finally { retired = true }
            }, { })
        }
        assertTrue(retired)
        assertEquals(1000L, currentTime)
    }

    @Test fun candidateCountIsBoundedAndAllWorkersRetireOnTimeout(): Unit = runTest {
        val opened = mutableListOf<Int>(); val retired = mutableListOf<Int>()
        assertFailsWith<TimeoutCancellationException> {
            firstAuthenticatedPairingRoute((1..50).asFlow(), 1000, { route ->
                opened.add(route)
                try { awaitCancellation() } finally { retired.add(route) }
            }, { _: Nothing -> })
        }
        assertEquals((1..8).toList(), opened)
        assertEquals(opened.toSet(), retired.toSet())
    }

    @Test fun parentCancellationAtSuccessfulHandoffReleasesTheWinner(): Unit = runTest {
        val released = mutableListOf<Int>()
        lateinit var parent: Job
        parent = launch(start = CoroutineStart.LAZY) {
            firstAuthenticatedPairingRoute<Int, Int>(flowOf(1), 1000, {
                parent.cancel(); it
            }, { released.add(it) })
        }
        parent.start(); parent.join()
        assertEquals(listOf(1), released)
    }

    @Test fun losingCleanupFailureDoesNotTransferTheWinner(): Unit = runTest {
        val released = mutableListOf<Int>()
        assertFailsWith<IOException> {
            firstAuthenticatedPairingRoute(flowOf(1, 2), 1000, { route ->
                if (route == 2) withContext(NonCancellable) { delay(10) }
                route
            }, { value -> released.add(value); if (value == 2) throw IOException("Synthetic close failure") })
        }
        assertEquals(listOf(2, 1), released)
    }
}
