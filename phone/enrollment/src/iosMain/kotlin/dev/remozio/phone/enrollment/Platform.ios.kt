package dev.remozio.phone.enrollment

import platform.Foundation.NSRecursiveLock

internal actual fun newEnrollmentLock(): EnrollmentLock = object : EnrollmentLock {
    private val lock = NSRecursiveLock()
    override fun lock() = lock.lock()
    override fun unlock() = lock.unlock()
}

private class FrozenList<T>(private val values: List<T>) : AbstractList<T>() {
    override val size: Int get() = values.size
    override fun get(index: Int): T = values[index]
}

internal actual fun <T> frozenList(values: List<T>): List<T> = FrozenList(values.toList())
