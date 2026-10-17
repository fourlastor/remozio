package dev.remozio.android.push

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.push.*
import dev.remozio.phone.transport.PhonePushRecoveryResult
import dev.remozio.protocol.*
import java.io.IOException
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.test.*
import org.junit.Test
import kotlin.test.*

class StoredPushRegistrationsTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun metadata(record: StoredPhoneEnrollment, token: String = "synthetic-token", candidate: Int = 6,
                         revision: ULong = 1u): PhonePushRegistrationMetadata {
        val e = record.enrollment
        return PhonePushRegistrationMetadata(GatewayTokenCandidate(GatewayTokenBinding(id(7), e.macID.copyBytes(), e.accountID.copyBytes(),
            id(8), id(9), e.phoneID.copyBytes(), e.epoch.copyBytes(), id(candidate), MessageDigest.getInstance("SHA-256").digest(token.toByteArray()),
            ByteArray(32) { 42 }, e.enrollmentTag.copyBytes()), revision, id(10), 1000u, 2000u))
    }
    private fun current(metadata: PhonePushRegistrationMetadata, phase: PhonePushRecoveryPhase = PhonePushRecoveryPhase.AWAITING_PROVIDER_PROOF) =
        PhonePushRecoveryResult.Current(PhonePushRecoveryState(metadata, phase), 0L) { 0L }
    private class ProofStorage : PhonePushProofStorage {
        var bytes: ByteArray? = null
        var writes = 0
        var fails = false
        override fun read(maximumBytes: Int) = bytes?.copyOf()
        override fun replace(bytes: ByteArray) { this.bytes = bytes.copyOf(); writes++; if (fails) error("synthetic-private-storage-fault") }
    }
    private class ChallengeStorage : PushChallengeStorage {
        var bytes: ByteArray? = null
        override fun read(maximumBytes: Int) = bytes?.copyOf()
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
    }
    private inner class Fixture(dispatcher: CoroutineDispatcher) {
        val client = PushClientFixture().apply { enable(); driver.attempts.single().token("synthetic-token") }
        val record = wakeTestRecord(1)
        val archive = WakeTestArchive().apply { activate(record) }
        val mutex = Mutex()
        val proofStorage = ProofStorage()
        val challengeStorage = ChallengeStorage()
        val cipher = PushChallengeCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey())
        var moment = PushChallengeMoment(1u, 100u)
        val challenges = ApplicationPushChallenges(client.owner, { moment }) {
            val journal = PendingPushChallenges(challengeStorage, cipher, 16, 1000u)
            object : PushChallengeOwner {
                override fun selectGeneration(generation: UUID, moment: PushChallengeMoment) = journal.selectGeneration(generation, moment.bootEpoch, moment.milliseconds)
                override fun admit(generation: UUID, challenge: PushData.TokenChallenge, moment: PushChallengeMoment) = journal.admit(generation, challenge, moment.bootEpoch, moment.milliseconds)
                override fun pending(generation: UUID, moment: PushChallengeMoment) = journal.pending(generation, moment.bootEpoch, moment.milliseconds)
                override fun match(generation: UUID, metadata: PhonePushRegistrationMetadata, moment: PushChallengeMoment) = journal.match(generation, metadata, moment.bootEpoch, moment.milliseconds)
                override fun discard(ticket: PendingPushChallengeTicket, moment: PushChallengeMoment) = journal.discard(ticket, moment.bootEpoch, moment.milliseconds)
                override fun close() = Unit
            }
        }
        val proofs = ApplicationPushProofs(client.owner) {
            val ledger = PhonePushProofLedger(proofStorage, 16)
            object : PushProofOwner {
                override fun retainActiveRecords(recordIDs: Set<CborValue.Bytes>) = ledger.retainActiveRecords(recordIDs)
                override fun claim(record: StoredPhoneEnrollment, metadata: PhonePushRegistrationMetadata, offer: PhonePushTokenOffer) = ledger.claim(record, metadata, offer)
                override fun close() = Unit
            }
        }
        var recoveries = 0
        var proofOpens = 0
        var proofCalls = 0
        var recoveryCloses = 0
        var proofCloses = 0
        var onRecover: suspend (StoredPhoneEnrollment, PhonePushTokenOffer) -> PhonePushRecoveryResult = { r, o -> current(metadata(r, o.token)) }
        var onProof: suspend () -> PhonePushRegistrationOutcome = { PhonePushRegistrationOutcome.PROOF_COMMITTED }
        var onOpenProof: suspend () -> Unit = {}
        var onCloseProof: suspend () -> Unit = {}
        private fun unlocked() { check(mutex.tryLock()); mutex.unlock(); check(!Thread.holdsLock(client.owner)) }
        var enrollmentOpens = 0
        var concurrentLimit = 4
        val runner = StoredPushRegistrations({ enrollmentOpens++; archive.open() }, mutex, client.owner, challenges, proofs,
            openRecovery = { _, record ->
                unlocked()
                object : PushRecoveryWire {
                    override suspend fun recover(offer: PhonePushTokenOffer): PhonePushRecoveryResult { unlocked(); recoveries++; return onRecover(record, offer) }
                    override fun close() = Unit
                    override suspend fun closeAndJoin() { unlocked(); recoveryCloses++ }
                }
            }, openProof = { _, _ ->
                unlocked(); proofOpens++; onOpenProof()
                object : PushProofWire {
                    override suspend fun prove(metadata: PhonePushRegistrationMetadata, challenge: PushData.TokenChallenge, offer: PhonePushTokenOffer): PhonePushRegistrationOutcome {
                        unlocked(); assertNotNull(proofStorage.bytes); proofCalls++; return onProof()
                    }
                    override fun close() = Unit
                    override suspend fun closeAndJoin() { unlocked(); proofCloses++; onCloseProof() }
                }
            }, timeoutMillis = { 1000 }, maximumConcurrent = 64, dispatcher = dispatcher, concurrencyLimit = { concurrentLimit })
        val candidate get() = assertNotNull(client.owner.tokenCandidate())
        fun admitted(record: StoredPhoneEnrollment = archive.active().single(), candidateID: Int = 6, revision: ULong = 1u) {
            val m = metadata(record, candidate.token, candidateID, revision)
            assertNotNull(challenges.admit(candidate.generation, PushData.TokenChallenge(m.candidateID, ByteArray(32) { 42 }, m.enrollmentTag)))
        }
        suspend fun run(recordID: CborValue.Bytes = record.recordID, selected: PushTokenCandidate = candidate) =
            runner.run(recordID, selected.generation, selected.revision)
    }
    @Test fun completeProofJoinsTheExactProviderDeliveryAndCommitsItsClaimBeforeSending() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted()
        val result = f.run()
        assertEquals(PushRegistrationOutcome.ROOT_STATE, result.outcome)
        assertEquals(PhonePushRecoveryPhase.PROOF_COMMITTED, assertNotNull(result.root).state.phase)
        assertEquals(1, f.proofCalls); assertEquals(1, f.proofStorage.writes)
        assertEquals(1, f.recoveryCloses); assertEquals(1, f.proofCloses)
        assertSame(result, f.runner.currentStatus(f.record.recordID))
        assertTrue(f.challenges.pending(f.candidate.generation).isEmpty())
    }
    @Test fun absentOrWrongCandidateDeliveryCannotOpenAProofExchange() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(candidateID = 99)
        assertEquals(PushRegistrationOutcome.WAITING_FOR_CHALLENGE, f.run().outcome)
        assertEquals(0, f.proofOpens); assertEquals(0, f.proofStorage.writes)
    }
    @Test fun lostProofReplyRequiresRecoveryAndNeverTransmitsTheSameCandidateAgain() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(); f.onProof = { throw IOException("synthetic-private-result") }
        assertEquals(PushRegistrationOutcome.RETRY, f.run().outcome)
        assertEquals(PushRegistrationOutcome.RECOVERY_REQUIRED, f.run().outcome)
        assertEquals(1, f.proofCalls); assertEquals(1, f.proofStorage.writes)
        f.onRecover = { r, o -> current(metadata(r, o.token), PhonePushRecoveryPhase.PROOF_COMMITTED) }
        assertEquals(PushRegistrationOutcome.ROOT_STATE, f.run().outcome); assertEquals(1, f.proofCalls)
    }
    @Test fun aFreshRootCandidateAllowsAnotherProofWithoutReplacingTheEnrollment() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(); f.onProof = { throw IOException("uncertain") }
        assertEquals(PushRegistrationOutcome.RETRY, f.run().outcome)
        f.onRecover = { r, o -> current(metadata(r, o.token, candidate = 11, revision = 3u)) }
        f.admitted(candidateID = 11, revision = 3u); f.onProof = { PhonePushRegistrationOutcome.PROOF_COMMITTED }
        assertEquals(PushRegistrationOutcome.ROOT_STATE, f.run().outcome)
        assertEquals(2, f.proofCalls); assertEquals(1, f.archive.active().size)
    }
    @Test fun tokenRotationDuringRecoveryRejectsTheOldResultAndClosesItsWire() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(); val entered = CompletableDeferred<Unit>()
        f.onRecover = { _, _ -> entered.complete(Unit); awaitCancellation() }
        val task = async { f.run() }; entered.await(); f.client.driver.attempts.single().token("replacement-token")
        assertEquals(PushRegistrationOutcome.OBSOLETE, task.await().outcome)
        assertEquals(0, f.proofCalls); assertEquals(1, f.recoveryCloses)
        assertNull(f.runner.currentStatus(f.record.recordID))
    }
    @Test fun enrollmentRemovalCancelsRecoveryBeforeAnyProofClaim() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(); val entered = CompletableDeferred<Unit>()
        f.onRecover = { _, _ -> entered.complete(Unit); awaitCancellation() }
        val task = async { f.run() }; entered.await()
        f.mutex.withLock { f.runner.invalidateRecordsLocked(setOf(f.record.recordID)); f.archive.remove(f.record) }
        assertEquals(PushRegistrationOutcome.OBSOLETE, task.await().outcome); assertEquals(0, f.proofStorage.writes)
        assertTrue(f.runner.status.value.isEmpty())
    }
    @Test fun expiredDeliveryDuringProofConnectionSetupCannotClaimOrSend() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted()
        f.onOpenProof = { f.moment = PushChallengeMoment(1u, 1100u) }
        assertEquals(PushRegistrationOutcome.WAITING_FOR_CHALLENGE, f.run().outcome)
        assertEquals(0, f.proofCalls); assertEquals(0, f.proofStorage.writes); assertEquals(1, f.proofCloses)
    }
    @Test fun uncertainClaimWriteWithholdsTheNetworkProofAndSurvivesReopening() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(); f.proofStorage.fails = true
        assertEquals(PushRegistrationOutcome.RETRY, f.run().outcome); assertEquals(0, f.proofCalls)
        f.proofStorage.fails = false
        assertEquals(PushRegistrationOutcome.RECOVERY_REQUIRED, f.run().outcome); assertEquals(0, f.proofCalls)
    }
    @Test fun providerRotationDuringCleanupCannotReturnTheOldSuccess() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted()
        f.onCloseProof = { f.client.driver.attempts.single().token("replacement-token") }
        assertEquals(PushRegistrationOutcome.OBSOLETE, f.run().outcome); assertEquals(1, f.proofCalls)
    }
    @Test fun independentlyEnrolledMacsShareOneProviderWithoutSharingProofClaims() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); val second = wakeTestRecord(2); f.archive.activate(second)
        f.archive.active().forEach { f.admitted(it) }
        val entered = CompletableDeferred<Unit>(); var waiting = 0
        f.onRecover = { r, o -> waiting++; if (waiting == 2) entered.complete(Unit); entered.await(); current(metadata(r, o.token)) }
        val first = async { f.run() }; val next = async { f.run(second.recordID) }
        assertEquals(PushRegistrationOutcome.ROOT_STATE, first.await().outcome)
        assertEquals(PushRegistrationOutcome.ROOT_STATE, next.await().outcome)
        assertEquals(2, f.proofCalls); assertEquals(2, f.proofStorage.writes)
    }
    @Test fun aChangedConcurrencyLimitAffectsNewAttemptsWithoutRetiringExistingOwners() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); val second = wakeTestRecord(2); f.archive.activate(second)
        f.archive.active().forEach { f.admitted(it) }; f.concurrentLimit = 1
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        f.onRecover = { r, o ->
            if (r.enrollment.recordID == f.record.recordID) { entered.complete(Unit); release.await() }
            current(metadata(r, o.token))
        }
        val first = async { f.run() }; entered.await()
        assertEquals(PushRegistrationOutcome.RETRY, f.run(second.recordID).outcome)
        f.concurrentLimit = 2
        assertEquals(PushRegistrationOutcome.ROOT_STATE, f.run(second.recordID).outcome)
        f.concurrentLimit = 1; release.complete(Unit)
        assertEquals(PushRegistrationOutcome.ROOT_STATE, first.await().outcome)
        assertEquals(2, f.proofCalls)
    }
    @Test fun completedStatusCannotSurviveProviderRotationOrEnrollmentRetirement() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); f.admitted(); f.run()
        assertNotNull(f.runner.currentStatus(f.record.recordID))
        f.client.driver.attempts.single().token("replacement-token")
        assertNull(f.runner.currentStatus(f.record.recordID))
        f.mutex.withLock { f.runner.invalidateRecordsLocked(setOf(f.record.recordID)) }
        assertTrue(f.runner.status.value.isEmpty())
    }

    @Test fun obsoleteProviderWorkDoesNotOpenTheEnrollmentArchive() = runTest {
        val f = Fixture(StandardTestDispatcher(testScheduler)); val selected = f.candidate
        assertTrue(f.client.owner.setEnabled(false))
        assertTrue(f.runner.records(selected.generation, selected.revision).isEmpty())
        assertEquals(PushRegistrationOutcome.OBSOLETE, f.run(selected = selected).outcome)
        assertEquals(0, f.enrollmentOpens)
    }

}
