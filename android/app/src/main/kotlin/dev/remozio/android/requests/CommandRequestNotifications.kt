package dev.remozio.android.requests

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.RequestPhase
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf

/** Observes signed request state only. It owns no transport, key, enrollment or decision action. */
internal class CommandRequestNotifications(
    private val clock: () -> ElapsedInstant,
    private val post: (CommandNotificationTarget, Long) -> Unit,
    private val cancel: (CommandNotificationTarget) -> Unit,
) {
    @OptIn(ExperimentalCoroutinesApi::class)
    fun observe(scope: CoroutineScope, connection: CommandConnection): Job = scope.launch {
        val attempted = mutableMapOf<String, CommandNotificationTarget>()
        val owner = currentCoroutineContext().job
        val retirement = launch(start = CoroutineStart.UNDISPATCHED) {
            connection.connectionState.first { it == CommandConnectionState.CLOSED }
            owner.cancel()
        }
        try {
            connection.requests.flatMapLatest { sessions ->
                if (sessions.isEmpty()) flowOf(emptyList()) else combine(sessions.map { session ->
                    combine(session.revisions, session.closed) { _, _ -> session }
                }) { it.toList() }
            }.collect { sessions ->
                val record = connection.record.enrollment
                val retained = StoredCommandOwner(record.recordID, record.macID, record.accountID, record.label, connection)
                val desired = sessions.mapNotNull { session ->
                    val snapshot = session.snapshot(clock())
                    val status = snapshot.status ?: return@mapNotNull null
                    if (snapshot.closed || status.status.phase !in setOf(RequestPhase.QUEUED, RequestPhase.PRESENTED)) return@mapNotNull null
                    val remaining = status.timing.authorizationRemainingUpperBoundMs
                    if (remaining == 0uL) return@mapNotNull null
                    val target = CommandNotificationTarget.from(ScopedCommandRequest(retained, session))
                    target to (remaining ?: 60_000uL).coerceAtMost(Long.MAX_VALUE.toULong()).toLong().coerceAtLeast(1)
                }
                val keys = desired.map { it.first.encode() }.toSet()
                attempted.keys.toList().filter { it !in keys }.forEach { key ->
                    try { cancel(checkNotNull(attempted[key])); attempted.remove(key) }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { /* Keep the target for later cancellation or retirement. */ }
                }
                desired.forEach { (target, lifetime) ->
                    // Retain before publication, including uncertain publication failures, for eventual cancellation.
                    attempted[target.encode()] = target
                    currentCoroutineContext().ensureActive()
                    try { post(target, lifetime) }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { /* Other signed updates remain observable after a local publication failure. */ }
                }
            }
        } finally {
            retirement.cancel()
            attempted.values.forEach { try { cancel(it) } catch (_: Exception) { } }
        }
    }
}
