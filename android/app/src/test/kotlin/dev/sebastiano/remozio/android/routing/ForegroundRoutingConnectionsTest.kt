package dev.sebastiano.remozio.android.routing

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.PhoneRoutingChallenge
import dev.remozio.phone.transport.PhoneRoutingResult
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class ForegroundRoutingConnectionsTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private inner class Peer(n: Int, private val dispatcher: CoroutineDispatcher, val blockCleanup: CompletableDeferred<Unit>? = null) {
        var calls = 0; var closes = 0
        val enteredCleanup = CompletableDeferred<Unit>()
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val pair = key(); return EnrollmentKeyReference(role, id(role.ordinal + 10), "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
                if (role == EnrollmentKeyRole.TRANSPORT) pair else pair.takeLast(65).toByteArray())
        }
        val enrollment = PhoneEnrollment(id(n), id(20 + n), id(21), id(n + 30), id(4), "Same host label", key().takeLast(65).toByteArray(), key(),
            local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { 5 }, null)
        val connection = MacRoutingConnection(StoredPhoneEnrollment(enrollment, EnrollmentPhase.ACTIVE), open = { _, _ ->
            object : RoutingWire {
                override suspend fun status(): PhoneRoutingResult { calls++; if (blockCleanup != null) awaitCancellation(); return PhoneRoutingResult.Failure(PhoneRoutingFailure.UNAVAILABLE) }
                override suspend fun challenge(expectedRevision: ULong): PhoneRoutingResult = error("No mutation")
                override suspend fun apply(challenge: PhoneRoutingChallenge, signature: ByteArray): PhoneRoutingResult = error("No mutation")
                override fun close() { closes++ }
                override suspend fun closeAndJoin() { close(); enteredCleanup.complete(Unit); blockCleanup?.await() }
            }
        }, loadSigner = { error("Polling must not load decision custody") }, current = { true }, freshnessMillis = { 1000 }, timeoutMillis = { 5000 }, dispatcher = dispatcher)
        val row get() = StoredRoutingOwner(enrollment.recordID, enrollment.macID, enrollment.accountID, enrollment.label, connection)
    }
    @Test fun allScopesPollIndependentlyAndRefreshKeepsHealthyJobs() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher); val b = Peer(2, dispatcher)
        var rows = listOf(a.row, b.row); val host = ForegroundRoutingConnections({ rows }) { 1000 }
        val run = launch { host.runForeground() }; runCurrent(); assertEquals(1, a.calls); assertEquals(1, b.calls)
        host.refresh(); runCurrent(); assertEquals(1, a.calls); assertEquals(1, b.calls)
        advanceTimeBy(1000); runCurrent(); assertEquals(2, a.calls); assertEquals(2, b.calls)
        val c = Peer(3, dispatcher); rows = rows + c.row; host.refresh(); runCurrent()
        assertEquals(2, a.calls); assertEquals(1, c.calls); run.cancelAndJoin()
        assertIs<ForegroundRoutingState.Stopped>(host.state.value)
    }
    @Test fun removalAndMissingOwnersDoNotRestartAnotherMac() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher); val b = Peer(2, dispatcher)
        var rows = listOf(a.row, b.row, StoredRoutingOwner(CborValue.Bytes(id(8)), CborValue.Bytes(id(28)), CborValue.Bytes(id(21)), "Unavailable", null))
        val host = ForegroundRoutingConnections({ rows }) { 1000 }; val run = launch { host.runForeground() }; runCurrent()
        a.connection.close(); rows = listOf(b.row); host.refresh(); runCurrent()
        assertEquals(1, b.calls); assertEquals(listOf(b.enrollment.recordID), assertIs<ForegroundRoutingState.Ready>(host.state.value).owners.map { it.recordID })
        run.cancelAndJoin(); assertEquals(MacRoutingAvailability.OFFLINE, b.connection.snapshot().availability)
    }
    @Test fun storageFailureExposesUnavailableAndCanResumeWithFreshOwners() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val a = Peer(1, dispatcher); var fail = false; var rows = listOf(a.row)
        val host = ForegroundRoutingConnections({ if (fail) error("Archive unavailable"); rows }) { 1000 }
        val run = launch { host.runForeground() }; runCurrent(); fail = true; host.refresh(); runCurrent()
        assertIs<ForegroundRoutingState.Unavailable>(host.state.value); advanceTimeBy(1000); runCurrent(); assertEquals(1, a.calls)
        val fresh = Peer(2, dispatcher); rows = listOf(fresh.row); fail = false; host.refresh(); runCurrent()
        assertEquals(1, fresh.calls); assertIs<ForegroundRoutingState.Ready>(host.state.value); run.cancelAndJoin()
    }
    @Test fun replacementActivityWaitsForActualNetworkCleanupBeforeStartingAnotherPoll() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler); val cleanup = CompletableDeferred<Unit>(); val a = Peer(1, dispatcher, cleanup)
        var acquisitions = 0; val host = ForegroundRoutingConnections({ acquisitions++; listOf(a.row) }) { 1000 }
        val first = launch { host.runForeground() }; runCurrent(); assertEquals(1, a.calls)
        first.cancel(); runCurrent(); a.enteredCleanup.await()
        val second = launch { host.runForeground() }; runCurrent(); assertEquals(1, acquisitions); assertEquals(1, a.calls)
        cleanup.complete(Unit); first.join(); runCurrent(); assertEquals(2, acquisitions); assertEquals(2, a.calls)
        second.cancelAndJoin(); assertIs<ForegroundRoutingState.Stopped>(host.state.value)
    }
}
