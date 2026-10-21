package dev.remozio.android.requests

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.protocol.CborLimits
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Test
import kotlin.test.*

class ForegroundCommandConnectionsTest {
    private val bounds = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bounds, bounds, bounds, bounds)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun publicKey() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair().public.encoded
    private class Wire : CommandConnectionWire {
        val ended = CompletableDeferred<Unit>()
        var closed = false
        override suspend fun receive() { ended.await() }
        override suspend fun send(bytes: ByteArray) = Unit
        override fun close() { closed = true; ended.complete(Unit) }
    }
    private fun owner(n: Int, open: suspend () -> CommandConnectionWire): StoredCommandOwner {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = publicKey()
            return EnrollmentKeyReference(role, id(10 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(10 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(n), id(n + 20), id(100), id(101), id(102),
            "Synthetic Mac", publicKey().takeLast(65).toByteArray(), publicKey(), key(EnrollmentKeyRole.TRANSPORT),
            key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC), ByteArray(32), null), EnrollmentPhase.ACTIVE)
        val connection = CommandConnection(record, limits, { _, _ -> open() }, { ElapsedInstant(0, 0u) }, dispatcher = Dispatchers.Unconfined)
        val e = record.enrollment
        return StoredCommandOwner(e.recordID, e.macID, e.accountID, e.label, connection)
    }
    private suspend fun ForegroundCommandConnections.ready() = withTimeout(5000) {
        state.first { it is ForegroundCommandState.Ready } as ForegroundCommandState.Ready
    }
    private suspend fun waitUntil(predicate: () -> Boolean) = withTimeout(5000) { while (!predicate()) yield() }

    @Test fun allPeersRunAndRefreshKeepsHealthyTransports() = runBlocking<Unit> {
        val wires = mutableListOf<Wire>()
        val first = owner(1) { Wire().also { wires += it } }
        val second = owner(2) { Wire().also { wires += it } }
        var loads = 0
        val runtime = ForegroundCommandConnections { loads++; listOf(first, second) }
        val running = launch { runtime.runForeground() }
        try {
            runtime.ready(); waitUntil { wires.size == 2 }
            runtime.refresh(); runtime.refresh()
            waitUntil { loads >= 2 }; yield()
            assertEquals(2, wires.size)
            assertTrue(wires.none { it.closed })
            assertEquals(2, (runtime.state.value as ForegroundCommandState.Ready).owners.size)
        } finally { running.cancelAndJoin() }
        assertTrue(wires.all { it.closed })
        assertEquals(ForegroundCommandState.Stopped, runtime.state.value)
        assertEquals(CommandConnectionState.DISCONNECTED, first.connection!!.connectionState.value)
        first.connection.close(); second.connection!!.close()
    }

    @Test fun failedPeerDoesNotCancelHealthyPeerAndRefreshRetriesOnlyCompletedJobs() = runBlocking<Unit> {
        var attempts = 0; var fail = true
        val first = owner(1) { attempts++; if (fail) error("Synthetic network failure"); Wire() }
        var healthyOpens = 0; val wire = Wire()
        val second = owner(2) { healthyOpens++; wire }
        val runtime = ForegroundCommandConnections { listOf(first, second) }
        val running = launch { runtime.runForeground() }
        try {
            runtime.ready(); waitUntil { attempts == 1 && healthyOpens == 1 }; yield()
            assertEquals(CommandConnectionState.DISCONNECTED, first.connection!!.connectionState.value)
            assertEquals(CommandConnectionState.CONNECTED, second.connection!!.connectionState.value)
            fail = false; runtime.refresh()
            waitUntil { first.connection.connectionState.value == CommandConnectionState.CONNECTED }
            assertEquals(2, attempts); assertEquals(1, healthyOpens); assertFalse(wire.closed)
        } finally { running.cancelAndJoin(); first.connection!!.close(); second.connection!!.close() }
    }

    @Test fun replacementJoinsOldAttemptBeforeOpeningAndLeavesOtherPeerRunning() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>(); val oldWire = Wire()
        val old = owner(1) { withContext(NonCancellable) { entered.complete(Unit); release.await() }; oldWire }
        var otherOpens = 0; val otherWire = Wire()
        val other = owner(2) { otherOpens++; otherWire }
        var replacementOpens = 0
        val replacement = owner(1) { assertTrue(oldWire.closed); replacementOpens++; Wire() }
        var rows = listOf(old, other)
        val runtime = ForegroundCommandConnections { rows }
        val running = launch { runtime.runForeground() }
        try {
            entered.await(); waitUntil { otherOpens == 1 }
            rows = listOf(replacement, other); runtime.refresh(); yield()
            assertEquals(0, replacementOpens); assertFalse(otherWire.closed)
            release.complete(Unit); waitUntil { replacementOpens == 1 }
            assertEquals(1, otherOpens); assertFalse(otherWire.closed)
        } finally {
            release.complete(Unit); running.cancelAndJoin()
            old.connection!!.close(); other.connection!!.close(); replacement.connection!!.close()
        }
    }

    @Test fun unreadableArchiveClearsRowsAndJoinsEveryPeerBeforeRecovery() = runBlocking<Unit> {
        val wires = mutableListOf<Wire>(); val owner = owner(1) { Wire().also { wires += it } }
        var fail = false
        val runtime = ForegroundCommandConnections { if (fail) error("Synthetic storage failure"); listOf(owner) }
        val running = launch { runtime.runForeground() }
        try {
            runtime.ready(); waitUntil { wires.size == 1 }
            fail = true; runtime.refresh()
            withTimeout(5000) { runtime.state.first { it == ForegroundCommandState.Unavailable } }
            assertTrue(wires.single().closed)
            fail = false; runtime.refresh(); runtime.ready(); waitUntil { wires.size == 2 }
        } finally { running.cancelAndJoin(); owner.connection!!.close() }
    }

    @Test fun nextForegroundHostWaitsForCancelledHostsLateOpenerCleanup() = runBlocking<Unit> {
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val oldWire = Wire(); var opens = 0
        val owner = owner(1) {
            opens++
            if (opens == 1) withContext(NonCancellable) { entered.complete(Unit); release.await() }
            if (opens == 1) oldWire else Wire().also { assertTrue(oldWire.closed) }
        }
        val runtime = ForegroundCommandConnections { listOf(owner) }
        val first = launch { runtime.runForeground() }
        entered.await(); first.cancel()
        val next = launch { runtime.runForeground() }
        try {
            yield(); assertEquals(1, opens); assertFalse(first.isCompleted)
            release.complete(Unit); first.join(); waitUntil { opens == 2 }
            assertTrue(oldWire.closed)
        } finally { release.complete(Unit); first.cancelAndJoin(); next.cancelAndJoin(); owner.connection!!.close() }
    }

    @Test fun missingOwnerKeepsItsRowWithoutHidingHealthyMacs() = runBlocking<Unit> {
        val healthyWire = Wire()
        val healthy = owner(1) { healthyWire }
        val failed = owner(2) { error("Missing owner must not open") }
        val missing = StoredCommandOwner(failed.recordID, failed.macID, failed.accountID, failed.label, null)
        val runtime = ForegroundCommandConnections { listOf(missing, healthy) }
        val running = launch { runtime.runForeground() }
        try {
            val rows = runtime.ready().owners
            assertNull(rows.single { it.recordID == missing.recordID }.connection)
            waitUntil { healthy.connection!!.connectionState.value == CommandConnectionState.CONNECTED }
            assertFalse(healthyWire.closed)
        } finally { running.cancelAndJoin(); healthy.connection!!.close(); failed.connection!!.close() }
    }

    @Test fun refreshWhileStoppedDoesNotOpenNetworkAndRemovingPeerStopsOnlyThatPeer() = runBlocking<Unit> {
        val firstWire = Wire(); val secondWire = Wire(); var opens = 0
        val first = owner(1) { opens++; firstWire }; val second = owner(2) { opens++; secondWire }
        var rows = listOf(first, second); var loads = 0
        val runtime = ForegroundCommandConnections { loads++; rows }
        repeat(3) { runtime.refresh() }; yield()
        assertEquals(0, loads); assertEquals(0, opens)
        val running = launch { runtime.runForeground() }
        try {
            runtime.ready(); waitUntil { opens == 2 }
            rows = listOf(second); runtime.refresh()
            withTimeout(5000) { runtime.state.first { it is ForegroundCommandState.Ready && it.owners.size == 1 } }
            assertTrue(firstWire.closed); assertFalse(secondWire.closed); assertEquals(2, opens)
        } finally { running.cancelAndJoin(); first.connection!!.close(); second.connection!!.close() }
    }

    @Test fun cancellingWaitingHostCannotClearOrStopActiveHost() = runBlocking<Unit> {
        val wire = Wire(); var loads = 0
        val owner = owner(1) { wire }
        val runtime = ForegroundCommandConnections { loads++; listOf(owner) }
        val active = launch { runtime.runForeground() }
        try {
            runtime.ready(); waitUntil { owner.connection!!.connectionState.value == CommandConnectionState.CONNECTED }
            val waiting = launch { runtime.runForeground() }
            yield(); waiting.cancelAndJoin()
            assertEquals(1, loads); assertFalse(wire.closed)
            assertIs<ForegroundCommandState.Ready>(runtime.state.value)
            assertEquals(CommandConnectionState.CONNECTED, owner.connection!!.connectionState.value)
        } finally { active.cancelAndJoin(); owner.connection!!.close() }
    }

}
