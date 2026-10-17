package dev.remozio.android.push

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.push.PendingPushChallengeTicket
import dev.remozio.phone.transport.PhonePushRecoveryResult
import dev.remozio.protocol.*
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class PushRegistrationOutcome { ROOT_STATE, WAITING_FOR_CHALLENGE, RECOVERY_REQUIRED, RETRY, INCOMPATIBLE, OBSOLETE }
internal class PushRegistrationRun(val outcome: PushRegistrationOutcome, val root: PhonePushRecoveryResult.Current? = null) {
    override fun toString() = "PushRegistrationRun(redacted)"
}

internal class PushRegistrationStatus(val generation: UUID, val tokenRevision: UUID,
                                      val result: PushRegistrationRun) {
    override fun toString() = "PushRegistrationStatus(redacted)"
}

/** Each Mac owns an independent attempt. Network operations never hold enrollment, provider or archive locks. */
internal class StoredPushRegistrations(
    private val open: () -> EncryptedEnrollmentStore?,
    private val enrollmentAccess: Mutex,
    private val provider: PushClientOwner,
    private val challenges: ApplicationPushChallenges,
    private val proofs: ApplicationPushProofs,
    private val openRecovery: suspend (CoroutineScope, StoredPhoneEnrollment) -> PushRecoveryWire,
    private val openProof: suspend (CoroutineScope, StoredPhoneEnrollment) -> PushProofWire,
    private val timeoutMillis: () -> Long,
    maximumConcurrent: Int = 4,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val concurrencyLimit: () -> Int = { maximumConcurrent },
) {
    private class Entry(val record: StoredPhoneEnrollment) {
        val operation = Mutex()
        val jobs = mutableSetOf<Job>()
        var attempt: UUID? = null
        @Volatile var retired = false
    }
    private class Selection(val entry: Entry, val candidate: PushTokenCandidate)
    private class CurrentValue<T>(val value: T)
    private class Matched(val ticket: PendingPushChallengeTicket, val challenge: PushData.TokenChallenge)
    private val entries = mutableMapOf<CborValue.Bytes, Entry>()
    private val slots = PushRegistrationSlots(maximumConcurrent, concurrencyLimit)
    private val reports = MutableStateFlow<Map<CborValue.Bytes, PushRegistrationStatus>>(emptyMap())
    val status = reports.asStateFlow()

    fun currentStatus(recordID: CborValue.Bytes): PushRegistrationRun? {
        val retained = reports.value[recordID] ?: return null
        return provider.withCurrentToken(retained.generation, retained.tokenRevision) { retained.result }
    }

    suspend fun records(generation: UUID, revision: UUID, tag: CborValue.Bytes? = null): List<CborValue.Bytes> = withContext(dispatcher) {
        val selected = provider.tokenCandidate()
        if (selected?.generation != generation || selected.revision != revision) return@withContext emptyList()
        enrollmentAccess.withLock {
            val active = activeLocked()
            provider.withCurrentToken(generation, revision) { active.filter { tag == null || it.enrollment.enrollmentTag == tag }.map { it.enrollment.recordID } } ?: emptyList()
        }
    }
    suspend fun run(recordID: CborValue.Bytes, generation: UUID, revision: UUID): PushRegistrationRun = withContext(dispatcher) {
        val token = provider.tokenCandidate()
        if (token?.generation != generation || token.revision != revision) return@withContext result(PushRegistrationOutcome.OBSOLETE)
        val selected = try { enrollmentAccess.withLock {
            val active = activeLocked()
            val record = active.singleOrNull { it.enrollment.recordID == recordID } ?: return@withLock null
            val candidate = provider.tokenCandidate()?.takeIf { it.generation == generation && it.revision == revision } ?: return@withLock null
            Selection(entries.getOrPut(recordID) { Entry(record) }, candidate)
        } } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { return@withContext result(PushRegistrationOutcome.RETRY) }
        if (selected == null) return@withContext result(PushRegistrationOutcome.OBSOLETE)
        val entry = selected.entry; val candidate = selected.candidate
        if (!entry.operation.tryLock()) return@withContext result(PushRegistrationOutcome.RETRY)
        val admitted = try { slots.tryAcquire() } catch (_: Exception) { false }
        if (!admitted) { entry.operation.unlock(); return@withContext result(PushRegistrationOutcome.RETRY) }
        try {
            val completed = coroutineScope {
                val job = currentCoroutineContext().job; val attempt = UUID.randomUUID()
                val began = enrollmentAccess.withLock {
                    val active = activeLocked()
                    if (!current(entry, active)) false else provider.withCurrentToken(generation, revision) {
                        entry.attempt = attempt; entry.jobs += job; true
                    } ?: false
                }
                if (!began) return@coroutineScope result(PushRegistrationOutcome.OBSOLETE)
                val retired = launch(start = CoroutineStart.UNDISPATCHED) {
                    combine(provider.generationState, provider.tokenRevisionState) { g, r -> g != generation || r != revision }.first { it }
                    job.cancel()
                }
                var recovery: PushRecoveryWire? = null; var proof: PushProofWire? = null
                try {
                    val timeout = timeoutMillis(); require(timeout in 1..60_000)
                    withTimeout(timeout) {
                        if (current(entry, attempt, candidate) { Unit } == null) return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                        recovery = openRecovery(this@coroutineScope, entry.record)
                        if (current(entry, attempt, candidate) { Unit } == null) return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                        val recovered = checkNotNull(recovery).recover(offer(candidate))
                        withContext(NonCancellable) { checkNotNull(recovery).closeAndJoin(); recovery = null }
                        val accepted = current(entry, attempt, candidate) { recovered } ?: return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                        when (val root = accepted.value) {
                            is PhonePushRecoveryResult.Failure -> result(if (root.failure == PhonePushRecoveryFailure.INCOMPATIBLE)
                                PushRegistrationOutcome.INCOMPATIBLE else PushRegistrationOutcome.RETRY)
                            is PhonePushRecoveryResult.Current -> {
                                val state = root.state
                                if (state.phase != PhonePushRecoveryPhase.AWAITING_PROVIDER_PROOF) {
                                    discardMatched(entry, attempt, candidate, state.metadata)
                                    return@withTimeout PushRegistrationRun(PushRegistrationOutcome.ROOT_STATE, root)
                                }
                                val first = current(entry, attempt, candidate) { matched(candidate.generation, state.metadata) }
                                    ?: return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                                if (first.value == null) return@withTimeout PushRegistrationRun(PushRegistrationOutcome.WAITING_FOR_CHALLENGE, root)
                                proof = openProof(this@coroutineScope, entry.record)
                                val claim = current(entry, attempt, candidate) { active ->
                                    val delivery = matched(candidate.generation, state.metadata)
                                    if (delivery == null) null else proofs.claim(candidate, entry.record, state.metadata, active) to delivery
                                } ?: return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                                val ready = claim.value ?: return@withTimeout PushRegistrationRun(PushRegistrationOutcome.WAITING_FOR_CHALLENGE, root)
                                when (ready.first) {
                                    PushProofClaim.OBSOLETE -> return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                                    PushProofClaim.RECOVERY_REQUIRED -> return@withTimeout PushRegistrationRun(PushRegistrationOutcome.RECOVERY_REQUIRED, root)
                                    PushProofClaim.CLAIMED -> Unit
                                }
                                currentCoroutineContext().ensureActive()
                                val outcome = checkNotNull(proof).prove(state.metadata, ready.second.challenge, offer(candidate))
                                val committed = current(entry, attempt, candidate) { outcome } ?: return@withTimeout result(PushRegistrationOutcome.OBSOLETE)
                                when (committed.value) {
                                    PhonePushRegistrationOutcome.PROOF_COMMITTED, PhonePushRegistrationOutcome.MAPPING_CONFIRMED -> {
                                        discardMatched(entry, attempt, candidate, state.metadata)
                                        val known = PhonePushRecoveryResult.Current(PhonePushRecoveryState(state.metadata,
                                            PhonePushRecoveryPhase.PROOF_COMMITTED), 0L) { 0L }
                                        PushRegistrationRun(PushRegistrationOutcome.ROOT_STATE, known)
                                    }
                                    PhonePushRegistrationOutcome.INCOMPATIBLE -> result(PushRegistrationOutcome.INCOMPATIBLE)
                                    else -> PushRegistrationRun(PushRegistrationOutcome.RECOVERY_REQUIRED, root)
                                }
                            }
                        }
                    }
                } finally {
                    retired.cancel()
                    withContext(NonCancellable) {
                        try { try { recovery?.closeAndJoin() } finally { proof?.closeAndJoin() } }
                        finally { enrollmentAccess.withLock { entry.jobs -= job; if (entry.attempt == attempt) entry.attempt = null } }
                    }
                }
            }
            finish(entry, candidate, completed)
        } catch (cancelled: CancellationException) {
            currentCoroutineContext().ensureActive()
            val current = provider.tokenCandidate()
            finish(entry, candidate, result(if (entry.retired || current?.generation != generation || current.revision != revision)
                PushRegistrationOutcome.OBSOLETE else PushRegistrationOutcome.RETRY))
        } catch (_: Exception) { finish(entry, candidate, result(PushRegistrationOutcome.RETRY)) }
        finally { slots.release(); entry.operation.unlock() }
    }

    private suspend fun finish(entry: Entry, candidate: PushTokenCandidate, completed: PushRegistrationRun): PushRegistrationRun =
        enrollmentAccess.withLock {
            val active = activeLocked()
            if (!current(entry, active)) return@withLock result(PushRegistrationOutcome.OBSOLETE)
            provider.withCurrentToken(candidate.generation, candidate.revision) {
                reports.value = reports.value + (entry.record.enrollment.recordID to
                    PushRegistrationStatus(candidate.generation, candidate.revision, completed))
                completed
            } ?: result(PushRegistrationOutcome.OBSOLETE)
        }

    private suspend fun <T> current(entry: Entry, attempt: UUID, candidate: PushTokenCandidate,
                                    body: (List<StoredPhoneEnrollment>) -> T): CurrentValue<T>? = enrollmentAccess.withLock {
        val active = activeLocked()
        if (!current(entry, active) || entry.attempt != attempt) null
        else provider.withCurrentToken(candidate.generation, candidate.revision) { CurrentValue(body(active)) }
    }
    private fun matched(generation: UUID, metadata: PhonePushRegistrationMetadata): Matched? {
        val ticket = challenges.pending(generation).singleOrNull {
            it.tag == CborValue.Bytes(metadata.enrollmentTag) && it.candidateID == CborValue.Bytes(metadata.candidateID)
        } ?: return null
        val challenge = challenges.match(generation, metadata) ?: return null
        return Matched(ticket, challenge)
    }
    private suspend fun discardMatched(entry: Entry, attempt: UUID, candidate: PushTokenCandidate, metadata: PhonePushRegistrationMetadata) {
        try { current(entry, attempt, candidate) { matched(candidate.generation, metadata)?.let { challenges.discard(it.ticket) } } }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { /* Retained buffers cannot undo the authenticated Root result. */ }
    }
    private fun current(entry: Entry, active: List<StoredPhoneEnrollment>) = !entry.retired &&
        active.any { it.enrollment.recordID == entry.record.enrollment.recordID && it.sameConnectionAs(entry.record) }
    private fun activeLocked(): List<StoredPhoneEnrollment> {
        val active = open()?.use { it.snapshot().entries.filter { row -> row.phase == EnrollmentPhase.ACTIVE } } ?: emptyList()
        val rows = active.associateBy { it.enrollment.recordID }
        invalidateRecordsLocked(entries.filter { (id, entry) -> rows[id]?.sameConnectionAs(entry.record) != true }.keys.toSet())
        return active
    }
    /** Pairing invokes this before publishing trust changes, under enrollmentAccess. */
    fun invalidateRecordsLocked(ids: Set<CborValue.Bytes>) {
        ids.forEach { id -> entries.remove(id)?.let { entry -> entry.retired = true; entry.jobs.forEach { it.cancel() } } }
        reports.value = reports.value - ids
    }
    private fun offer(candidate: PushTokenCandidate) = PhonePushTokenOffer(candidate.token, candidate.projectID, candidate.senderID, candidate.packageName)
    private fun result(outcome: PushRegistrationOutcome) = PushRegistrationRun(outcome)
}

/** A lower limit affects new attempts. Existing owners keep their slots until cleanup finishes. */
private class PushRegistrationSlots(private val maximum: Int, private val limit: () -> Int) {
    private var running = 0
    init { require(maximum in 1..64) }
    @Synchronized fun tryAcquire(): Boolean {
        val selected = limit(); require(selected in 1..maximum)
        if (running >= selected) return false
        running++; return true
    }
    @Synchronized fun release() { check(running > 0); running-- }
}
