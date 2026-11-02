package dev.sebastiano.remozio.android.audit

import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.util.Collections
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal class AuditMacOption(val macID: CborValue.Bytes, val label: String) {
    override fun toString() = "AuditMacOption(redacted)"
}

internal sealed interface CachedAuditContent {
    data object Missing : CachedAuditContent
    data object Unavailable : CachedAuditContent
    class Loaded(val snapshot: AuditEvidenceSnapshot, val history: AuditHistoryGroup,
                 val localTimes: AuditLocalSyncTimes? = null) : CachedAuditContent {
        override fun toString() = "CachedAuditContent.Loaded(redacted)"
    }
}

/** One trusted Root binding. A request identifier never joins timelines across this boundary. */
internal class CachedAuditArchive(val authorityPublicKey: CborValue.Bytes, val retired: Boolean,
                                 val content: CachedAuditContent) {
    val fingerprint: String = MessageDigest.getInstance("SHA-256").digest(authorityPublicKey.copyBytes())
        .joinToString("") { "%02x".format(it) }
    val shortFingerprint: String get() = fingerprint.take(12) + "…" + fingerprint.takeLast(8)
    override fun toString() = "CachedAuditArchive(redacted)"
}

internal class CachedAuditScope(val scope: AuditHistoryScope, val label: String, archives: List<CachedAuditArchive>) {
    val archives: List<CachedAuditArchive> = Collections.unmodifiableList(archives.toList())
    override fun toString() = "CachedAuditScope(redacted)"
}

internal sealed interface StoredAuditState {
    data object Loading : StoredAuditState
    data object Unavailable : StoredAuditState
    class Ready(macs: List<AuditMacOption>, scopes: List<CachedAuditScope>) : StoredAuditState {
        val macs: List<AuditMacOption> = Collections.unmodifiableList(macs.toList())
        val scopes: List<CachedAuditScope> = Collections.unmodifiableList(scopes.toList())
        override fun toString() = "StoredAuditState.Ready(redacted)"
    }
}

/** Read budgets bound retained proof bytes; reaching one never deletes or rewrites retained evidence. */
internal class AuditReadBudget(val perArchiveBytes: Int = 16_777_216, val totalBytes: Int = 33_554_432) {
    init { require(perArchiveBytes in 1..16_777_216 && totalBytes in perArchiveBytes..67_108_864) }
}

/** No callbacks may create a key, reset an archive, connect to a peer, or grant current authority. */
internal class StoredAuditReader(
    private val openEnrollments: () -> EncryptedEnrollmentStore?,
    private val openCache: (AuditCacheBinding, Int) -> EncryptedAuditCache?,
    private val budget: AuditReadBudget = AuditReadBudget(),
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val enrollmentAccess: Mutex = Mutex(),
    private val ownedSnapshot: suspend (AuditCacheBinding) -> AuditEvidenceSnapshot? = { null },
    private val readSnapshot: AuditSnapshotRead = { binding, fallback -> ownedSnapshot(binding)?.let { AuditRetainedSnapshot(it, null) } ?: fallback() },
) {
    private val mutex = Mutex()

    suspend fun read(macID: CborValue.Bytes? = null, category: AuditCategory? = null,
                     outcome: AuditOutcome? = null): StoredAuditState = mutex.withLock {
        try {
            withContext(dispatcher) {
                val rows = enrollmentAccess.withLock {
                    openEnrollments()?.use { it.snapshot().entries } ?: emptyList()
                }
                // Prepared setups are not an established source of history. Removed rows keep cache bindings.
                val retained = rows.filter { it.phase != EnrollmentPhase.PREPARED }
                val groups = retained.groupBy { AuditHistoryScope(it.enrollment.macID, it.enrollment.accountID) }
                    .toList().sortedWith(compareBy({ hex(it.first.macID) }, { hex(it.first.accountID) }))
                val options = retained.groupBy { it.enrollment.macID }.toList().sortedBy { hex(it.first) }
                    .map { (id, entries) -> AuditMacOption(id, label(entries)) }
                var remaining = budget.totalBytes
                val scopes = groups.filter { macID == null || it.first.macID == macID }.map { (scope, entries) ->
                    currentCoroutineContext().ensureActive()
                    val archives = entries.asReversed().groupBy { it.enrollment.authorityPublicKey }.toList()
                        .sortedBy { (_, records) -> records.none { it.phase == EnrollmentPhase.ACTIVE } }
                        .map { (authority, records) ->
                            currentCoroutineContext().ensureActive()
                            val binding = AuditCacheBinding(scope.macID.copyBytes(), scope.accountID.copyBytes(), authority.copyBytes())
                            val content = if (remaining <= 0) CachedAuditContent.Unavailable else {
                                val limit = minOf(remaining, budget.perArchiveBytes)
                                readArchive(binding, limit, category, outcome).also {
                                    if (it is CachedAuditContent.Loaded) remaining -= it.snapshot.storedBytes.toInt()
                                }
                            }
                            CachedAuditArchive(authority, records.none { it.phase == EnrollmentPhase.ACTIVE }, content)
                        }
                    CachedAuditScope(scope, label(entries), archives)
                }
                StoredAuditState.Ready(options, scopes)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            StoredAuditState.Unavailable
        }
    }

    private suspend fun readArchive(binding: AuditCacheBinding, maximumBytes: Int,
                                    category: AuditCategory?, outcome: AuditOutcome?): CachedAuditContent {
        try {
            currentCoroutineContext().ensureActive()
            val retained = readSnapshot(binding) { openCache(binding, maximumBytes)?.use { AuditRetainedSnapshot(it.snapshot(), it.localSyncTimes()) } }
                ?: return CachedAuditContent.Missing
            val snapshot = retained.history
            check(snapshot.scope == AuditHistoryScope(CborValue.Bytes(binding.macID), CborValue.Bytes(binding.accountID)))
            check(snapshot.storedBytes <= maximumBytes)
            val history = AuditHistory.list(listOf(snapshot), AuditHistoryFilter(
                categories = category?.let { setOf(it) }, outcomes = outcome?.let { setOf(it) },
            )).single()
            return CachedAuditContent.Loaded(snapshot, history, retained.localTimes)
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { return CachedAuditContent.Unavailable }
    }

    private fun label(entries: List<StoredPhoneEnrollment>) =
        (entries.lastOrNull { it.phase == EnrollmentPhase.ACTIVE } ?: entries.last()).enrollment.label
    private fun hex(bytes: CborValue.Bytes) = bytes.copyBytes().joinToString("") { "%02x".format(it) }
}
