package dev.remozio.phone.push

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.PushData

/** A local enrollment handle. It contains no push-supplied endpoint or authority key. */
class WakeEnrollment internal constructor(mac: ByteArray, account: ByteArray, epoch: ByteArray, tag: ByteArray) {
    val macID = CborValue.Bytes(mac)
    val accountID = CborValue.Bytes(account)
    val enrollmentEpoch = CborValue.Bytes(epoch)
    val notificationTag = CborValue.Bytes(tag)
    override fun toString(): String = "WakeEnrollment(redacted)"
}

enum class WakeNotificationResult { POSTED, PERMISSION_DENIED, APP_DISABLED, CHANNEL_DISABLED, FAILED }
enum class WakeReception { ACCEPTED, DUPLICATE, UNKNOWN_ENROLLMENT, TOKEN_CHALLENGE, MALFORMED, CLOSED, INVALID_CLOCK }
data class WakeReceipt(val reception: WakeReception, val enrollment: WakeEnrollment? = null,
                       val notification: WakeNotificationResult? = null)

/** A single fetch reservation for a retained enrollment. It grants no request or decision authority. */
class WakeFetch internal constructor(val enrollment: WakeEnrollment) {
    override fun toString(): String = "WakeFetch(redacted)"
}

/**
 * Trusted setup owns registrations. Incoming pushes can only select an existing opaque tag.
 * Callbacks are synchronous and must not reenter this owner. Network work belongs outside its lock.
 */
class PushWakeRouter(
    private val maximumEnrollments: Int,
    private val maximumRememberedTags: Int,
    private val maximumRememberedWakes: Int,
    private val duplicateLifetimeMillis: ULong,
    private val minimumAlertIntervalMillis: ULong,
) : AutoCloseable {
    private data class Scope(val mac: CborValue.Bytes, val account: CborValue.Bytes)
    private data class Seen(val enrollment: WakeEnrollment, val identifier: CborValue.Bytes)
    private class Entry(val enrollment: WakeEnrollment) {
        var pending = false
        var flight: WakeFetch? = null
        var lastAlert: ULong? = null
    }
    private val entries = linkedMapOf<Scope, Entry>()
    private val tags = mutableMapOf<CborValue.Bytes, WakeEnrollment>()
    private val retiredTags = mutableSetOf<CborValue.Bytes>()
    private class SeenState(val receivedAt: ULong, val posted: Boolean) { var retry = false }
    private val seen = linkedMapOf<Seen, SeenState>()
    private var lastTime: ElapsedInstant? = null
    private var closed = false

    init {
        require(maximumEnrollments in 1..1024 && maximumRememberedTags in maximumEnrollments..4096)
        require(maximumRememberedWakes in 1..4096)
        require(duplicateLifetimeMillis in 1uL..86_400_000uL && minimumAlertIntervalMillis in 1uL..3_600_000uL)
    }

    /** Only completed trusted enrollment may supply these values. Fresh enrollments require fresh random tags. */
    @Synchronized
    fun add(macID: ByteArray, accountID: ByteArray, enrollmentEpoch: ByteArray, notificationTag: ByteArray): WakeEnrollment {
        check(!closed) { "Wake router closed" }
        require(macID.size == 16 && accountID.size == 16 && enrollmentEpoch.size == 16 && notificationTag.size == 32)
        val scope = Scope(CborValue.Bytes(macID), CborValue.Bytes(accountID))
        val tag = CborValue.Bytes(notificationTag)
        require(scope !in entries && tag !in tags && tag !in retiredTags) { "Conflicting wake enrollment" }
        check(entries.size < maximumEnrollments && tags.size + retiredTags.size < maximumRememberedTags) { "Wake enrollment capacity" }
        val enrollment = WakeEnrollment(macID, accountID, enrollmentEpoch, notificationTag)
        entries[scope] = Entry(enrollment)
        tags[tag] = enrollment
        return enrollment
    }

    /** Remove the exact incarnation before installing its replacement. A stale handle cannot remove the new one. */
    @Synchronized
    fun remove(enrollment: WakeEnrollment): Boolean {
        val scope = scope(enrollment)
        if (entries[scope]?.enrollment !== enrollment) return false
        entries.remove(scope)
        tags.remove(enrollment.notificationTag)
        retiredTags += enrollment.notificationTag
        seen.keys.removeAll { it.enrollment === enrollment }
        return true
    }

    /** Attempt the generic notification before exposing new fetch demand, even when notifications are disabled. */
    @Synchronized
    fun receive(data: Map<String, String>, clock: () -> ElapsedInstant,
                notify: (WakeEnrollment, Boolean) -> WakeNotificationResult): WakeReceipt {
        if (closed) return WakeReceipt(WakeReception.CLOSED)
        val now = clock()
        val previous = lastTime
        if (previous != null && (now.epoch != previous.epoch || now.milliseconds < previous.milliseconds)) {
            close()
            return WakeReceipt(WakeReception.INVALID_CLOCK)
        }
        lastTime = now
        val push = try { PushData.decode(data) } catch (_: IllegalArgumentException) { return WakeReceipt(WakeReception.MALFORMED) }
        val tag = when (push) {
            is PushData.Wake -> push.enrollmentTag
            is PushData.TokenChallenge -> push.enrollmentTag
        }
        val enrollment = tags[CborValue.Bytes(tag)] ?: return WakeReceipt(WakeReception.UNKNOWN_ENROLLMENT)
        if (push is PushData.TokenChallenge) return WakeReceipt(WakeReception.TOKEN_CHALLENGE, enrollment)
        push as PushData.Wake
        val entry = checkNotNull(entries[scope(enrollment)])
        seen.entries.removeAll { now.milliseconds - it.value.receivedAt >= duplicateLifetimeMillis }
        val identity = Seen(enrollment, CborValue.Bytes(push.identifier))
        val previousReceipt = seen[identity]
        if (previousReceipt != null && !previousReceipt.retry) return WakeReceipt(WakeReception.DUPLICATE, enrollment)
        val alert = previousReceipt?.posted != true &&
            (entry.lastAlert?.let { now.milliseconds - it >= minimumAlertIntervalMillis } ?: true)
        val notification = try { notify(enrollment, alert) } catch (_: Exception) { WakeNotificationResult.FAILED }
        if (notification == WakeNotificationResult.POSTED && alert) entry.lastAlert = now.milliseconds
        // This bounded hint cache is not authorization replay state. Eviction never drops fetch demand.
        if (identity !in seen && seen.size >= maximumRememberedWakes) seen.remove(seen.keys.first())
        seen[identity] = SeenState(previousReceipt?.receivedAt ?: now.milliseconds,
            previousReceipt?.posted == true || notification == WakeNotificationResult.POSTED)
        entry.pending = true
        return WakeReceipt(WakeReception.ACCEPTED, enrollment, notification)
    }

    /** Retry one hint after failed persistence without resetting its alert floor or retained fetch demand. */
    @Synchronized
    fun retryWake(enrollment: WakeEnrollment, identifier: ByteArray): Boolean {
        require(identifier.size == 32)
        if (closed || entries[scope(enrollment)]?.enrollment !== enrollment) return false
        val receipt = seen[Seen(enrollment, CborValue.Bytes(identifier))] ?: return false
        receipt.retry = true
        return true
    }

    @Synchronized
    internal fun pendingFetches(): List<WakeEnrollment> = entries.values
        .filter { it.pending && it.flight == null }.map { it.enrollment }

    @Synchronized
    internal fun contains(enrollment: WakeEnrollment): Boolean = entries[scope(enrollment)]?.enrollment === enrollment

    /** One complete-pending-set fetch per enrollment. Other Macs can fetch independently. */
    @Synchronized
    fun beginFetch(enrollment: WakeEnrollment): WakeFetch? {
        if (closed) return null
        val entry = entries[scope(enrollment)] ?: return null
        if (entry.enrollment !== enrollment || !entry.pending || entry.flight != null) return null
        return WakeFetch(enrollment).also { entry.pending = false; entry.flight = it }
    }

    /** Recheck around every await; authenticate the Mac using the separately retained enrollment pins. */
    @Synchronized
    fun isCurrent(fetch: WakeFetch): Boolean = !closed && entries[scope(fetch.enrollment)]?.flight === fetch

    /** A failed fetch retains demand. A new wake during a fetch requires another complete-set fetch. */
    @Synchronized
    fun finishFetch(fetch: WakeFetch, successful: Boolean): Boolean {
        if (!isCurrent(fetch)) return false
        val entry = checkNotNull(entries[scope(fetch.enrollment)])
        entry.flight = null
        if (!successful) entry.pending = true
        return true
    }

    @Synchronized
    override fun close() {
        closed = true
        entries.clear(); tags.clear(); retiredTags.clear(); seen.clear()
    }

    private fun scope(enrollment: WakeEnrollment) = Scope(enrollment.macID, enrollment.accountID)
}
