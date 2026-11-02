package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** COMPLETE means the observed round finished. Retention gaps and unknown outcomes may still exist. */
enum class AuditSyncPhase { IDLE, SYNCING, PAUSED, COMPLETE, CANCELLED, FAILED, CLOSED }
enum class AuditSyncFailure { TRANSPORT, INVALID_RESPONSE, STORAGE, CONFLICT, HISTORY_CHANGED }
class AuditSyncException(val reason: AuditSyncFailure) : IllegalStateException(reason.name)

class AuditEpochObservation internal constructor(val descriptor: AuditEpochDescriptor, val receivedAt: ElapsedInstant)

class AuditSyncSnapshot internal constructor(
    val phase: AuditSyncPhase,
    val history: AuditEvidenceSnapshot,
    val failure: AuditSyncFailure?,
    val lastCompletedAt: ElapsedInstant?,
    val lastResponseAt: ElapsedInstant?,
    val currentObservation: AuditEpochObservation?,
    val localTimes: AuditLocalSyncTimes?,
)

/**
 * Owns one cache and one receiver for an enrolled Mac/account/key. Calls perform blocking I/O off the main thread.
 * The transport owner must authenticate the channel and close this session on revocation or authority replacement.
 * This class never establishes enrollment, connectivity, presence or action authority.
 */
class AuditSyncSession(
    private val cache: EncryptedAuditCache,
    private val responseBudget: Int,
    private val queryLifetimeMs: ULong,
    private val clock: () -> ElapsedInstant,
) : AutoCloseable {
    init { require(responseBudget > 0) }
    internal val binding: AuditCacheBinding get() = cache.binding
    private fun receiver(lifetime: ULong) = AuditPageReceiver(cache.binding.macID, cache.binding.accountID,
        cache.binding.authorityPublicKey, cache.protocolLimits, 1, lifetime, clock)
    private var receiver = receiver(queryLifetimeMs)
    private sealed interface Work {
        class History(val epoch: CborValue.Bytes?, val after: ULong?) : Work
        class Page(val epoch: CborValue.Bytes, val generation: ULong, val after: ULong, val targetHead: ULong) : Work
    }
    private val queue = ArrayDeque<Work>()
    private val plannedEpochs = HashSet<CborValue.Bytes>()
    private val scheduledChecks = HashSet<CborValue.Bytes>()
    private var pending: AuditQuery? = null
    private var remaining = 0
    private var storageFailed = false
    private val mutableState = MutableStateFlow(AuditSyncSnapshot(AuditSyncPhase.IDLE, cache.snapshot(), null, null, null, null, cache.localSyncTimes()))
    val state: StateFlow<AuditSyncSnapshot> = mutableState.asStateFlow()

    /** Starts fresh discovery. A paused round may be abandoned explicitly with cancel first. */
    @Synchronized
    fun start(responseBudget: Int = this.responseBudget, queryLifetimeMs: ULong = this.queryLifetimeMs) {
        check(state.value.phase !in setOf(AuditSyncPhase.CLOSED, AuditSyncPhase.SYNCING, AuditSyncPhase.PAUSED))
        check(!storageFailed) { "Reopen the audit cache before syncing" }
        require(responseBudget > 0 && queryLifetimeMs > 0u)
        val nextReceiver = receiver(queryLifetimeMs)
        receiver.close(); receiver = nextReceiver
        queue.clear(); plannedEpochs.clear(); scheduledChecks.clear(); remaining = responseBudget
        queue.addLast(Work.History(null, null))
        publish(AuditSyncPhase.SYNCING)
    }

    /** Continues the same bounded plan. It does not chase a head that grows during this round. */
    @Synchronized
    fun resume(responseBudget: Int = this.responseBudget, queryLifetimeMs: ULong = this.queryLifetimeMs) {
        check(state.value.phase == AuditSyncPhase.PAUSED)
        require(responseBudget > 0 && queryLifetimeMs > 0u)
        val nextReceiver = receiver(queryLifetimeMs)
        receiver.close(); receiver = nextReceiver
        remaining = responseBudget
        publish(AuditSyncPhase.SYNCING)
    }

    /** Returns at most one live query. The caller sends it through the authenticated enrollment channel. */
    @Synchronized
    fun next(): AuditQuery? {
        if (state.value.phase != AuditSyncPhase.SYNCING) return null
        check(pending == null) { "An audit query is already pending" }
        if (queue.isEmpty()) {
            publish(AuditSyncPhase.COMPLETE, completed = state.value.lastResponseAt)
            return null
        }
        if (remaining == 0) { publish(AuditSyncPhase.PAUSED); return null }
        val work = queue.first()
        return try {
            when (work) {
                is Work.History -> receiver.beginHistory(work.epoch?.copyBytes(), work.after)
                is Work.Page -> receiver.begin(work.epoch.copyBytes(), work.generation, work.after)
            }.also { pending = it }
        } catch (failure: Throwable) {
            fail(AuditSyncFailure.INVALID_RESPONSE)
            throw failure
        }
    }

    /** Verification and durable append precede every cursor or successful-sync update. */
    @Synchronized
    fun accept(query: AuditQuery, body: ByteArray, signature: ByteArray) {
        requirePending(query)
        val work = queue.first()
        val receipt = try {
            when (query) {
                is AuditHistoryQuery -> receiver.receiveHistory(query, body, signature)
                is AuditPageQuery -> receiver.receive(query, body, signature)
            }
        } catch (failure: Throwable) {
            fail(AuditSyncFailure.INVALID_RESPONSE)
            throw failure
        }
        val acceptance = try {
            when (receipt) {
                is ReceivedAuditHistory -> cache.append(receipt)
                is ReceivedAuditPage -> cache.append(receipt)
                else -> error("Unsupported audit receipt")
            }
        } catch (failure: Throwable) {
            storageFailed = true
            fail(AuditSyncFailure.STORAGE)
            throw failure
        }
        pending = null
        queue.removeFirst(); remaining--
        val receivedAt = when (receipt) {
            is ReceivedAuditHistory -> receipt.receivedAt
            is ReceivedAuditPage -> receipt.receivedAt
            else -> error("Unsupported audit receipt")
        }
        try {
            publish(AuditSyncPhase.SYNCING, history = cache.snapshot(), response = receivedAt)
            if (acceptance == AuditEvidenceAcceptance.CONFLICT) {
                fail(AuditSyncFailure.CONFLICT)
                throw AuditSyncException(AuditSyncFailure.CONFLICT)
            }
            when (receipt) {
                is ReceivedAuditHistory -> {
                    val status = receipt.status
                    publish(AuditSyncPhase.SYNCING, current = AuditEpochObservation(status.current, receivedAt))
                    plan(status.current, status.currentRetainedAfter, status.currentHead, first = true)
                    status.queried?.let { plan(it, checkNotNull(status.queriedRetainedAfter), checkNotNull(status.queriedHead)) }
                    val currentEpoch = CborValue.Bytes(status.current.epoch)
                    val knownCurrent = state.value.history.epochs.single { it.epoch == currentEpoch }
                    if (knownCurrent.highestObservedHead > status.currentHead) checkCursor(knownCurrent)
                    if ((work as Work.History).epoch == null) {
                        for (epoch in state.value.history.epochs) {
                            if (epoch.epoch !in plannedEpochs) checkCursor(epoch)
                        }
                    }
                }
                is ReceivedAuditPage -> {
                    val batch = receipt.batch
                    val page = work as Work.Page
                    if (batch.head < page.targetHead) {
                        fail(AuditSyncFailure.HISTORY_CHANGED)
                        throw AuditSyncException(AuditSyncFailure.HISTORY_CHANGED)
                    }
                    enqueuePage(page.epoch, page.generation, batch.retainedAfter, page.targetHead, first = true)
                }
            }
            if (queue.isEmpty()) publish(AuditSyncPhase.COMPLETE, completed = receivedAt)
            else if (remaining == 0) publish(AuditSyncPhase.PAUSED)
        } finally {
            val kind = if (receipt is ReceivedAuditPage) AuditEvidenceKind.PAGE else AuditEvidenceKind.HISTORY_STATUS
            val body = when (receipt) {
                is ReceivedAuditPage -> receipt.canonicalBody
                is ReceivedAuditHistory -> receipt.canonicalBody
                else -> error("Unsupported audit receipt")
            }
            val old = state.value.localTimes
            cache.recordLocalSync(kind, body, state.value.phase == AuditSyncPhase.COMPLETE)
            if (cache.localSyncTimes() != old) publish(state.value.phase, failure = state.value.failure)
        }
    }

    /** A late transport error cannot cancel a newer query or a completed round. */
    @Synchronized
    fun transportFailed(query: AuditQuery) { requirePending(query); fail(AuditSyncFailure.TRANSPORT) }

    @Synchronized
    fun cancel() {
        check(state.value.phase != AuditSyncPhase.CLOSED)
        clearPending(); publish(AuditSyncPhase.CANCELLED)
    }

    @Synchronized
    override fun close() {
        if (state.value.phase == AuditSyncPhase.CLOSED) return
        clearPending(); receiver.close(); publish(AuditSyncPhase.CLOSED)
        cache.close()
    }

    private fun checkCursor(epoch: AuditEpochEvidence) {
        if (scheduledChecks.add(epoch.epoch)) queue.addLast(Work.History(epoch.epoch, epoch.highestObservedHead))
    }

    private fun plan(descriptor: AuditEpochDescriptor, retained: ULong, head: ULong, first: Boolean = false) {
        val epoch = CborValue.Bytes(descriptor.epoch)
        if (plannedEpochs.add(epoch)) enqueuePage(epoch, descriptor.generation, retained, head, first)
    }

    private fun enqueuePage(epoch: CborValue.Bytes, generation: ULong, retained: ULong, head: ULong, first: Boolean) {
        var after = minOf(retained, head)
        val known = state.value.history.epochs.single { it.epoch == epoch }
        for (record in known.records) {
            if (record.sequence <= after) continue
            if (after == head || record.sequence != after + 1uL) break
            after = record.sequence
        }
        if (after < head) {
            val work = Work.Page(epoch, generation, after, head)
            if (first) queue.addFirst(work) else queue.addLast(work)
        }
    }

    private fun requirePending(query: AuditQuery) {
        check(state.value.phase == AuditSyncPhase.SYNCING && pending === query) { "Stale audit query" }
    }
    private fun clearPending() { pending?.close(); pending = null; queue.clear(); plannedEpochs.clear(); scheduledChecks.clear() }
    private fun fail(reason: AuditSyncFailure) { clearPending(); publish(AuditSyncPhase.FAILED, failure = reason) }
    private fun publish(phase: AuditSyncPhase, failure: AuditSyncFailure? = null,
                        history: AuditEvidenceSnapshot = state.value.history,
                        completed: ElapsedInstant? = state.value.lastCompletedAt,
                        response: ElapsedInstant? = state.value.lastResponseAt,
                        current: AuditEpochObservation? = state.value.currentObservation) {
        mutableState.value = AuditSyncSnapshot(phase, history, failure, completed, response, current, if (phase == AuditSyncPhase.CLOSED) state.value.localTimes else cache.localSyncTimes())
    }
}
