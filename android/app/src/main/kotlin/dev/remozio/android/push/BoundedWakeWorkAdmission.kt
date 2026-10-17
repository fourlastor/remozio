package dev.remozio.android.push

import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

internal enum class WakeWorkAdmission { QUEUED, CAPACITY_LIMIT, UNAVAILABLE }

/** One process owner serializes admissions for one work tag. Keep it across provider changes. Completion is not delivery. */
internal class BoundedWakeWorkAdmission<T>(
    private var maximumQueued: Int,
    private val pendingCount: () -> Int,
    private val enqueue: (T) -> Future<*>,
    private val timeoutMillis: Long = 1_000,
) {
    private val inFlight = mutableListOf<Future<*>>()
    private var uncertain = 0

    init { require(maximumQueued in 1..4096 && timeoutMillis in 1..10_000) }

    @Synchronized fun setMaximumQueued(value: Int) { require(value in 1..4096); maximumQueued = value }

    /** Call off the main thread. Uncertain calls reserve capacity until the process ends. */
    @Synchronized fun admit(request: T): WakeWorkAdmission {
        return try {
            inFlight.removeAll { it.isDone }
            val persisted = pendingCount(); check(persisted >= 0)
            if (persisted.toLong() + inFlight.size + uncertain >= maximumQueued) return WakeWorkAdmission.CAPACITY_LIMIT
            // Reserve before calling the platform. A thrown call may have started work without returning its future.
            uncertain++
            val future = enqueue(request)
            inFlight += future; uncertain--
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
            WakeWorkAdmission.QUEUED
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt(); WakeWorkAdmission.UNAVAILABLE
        } catch (_: Exception) { WakeWorkAdmission.UNAVAILABLE }
    }
}
