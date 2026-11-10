package dev.remozio.phone.enrollment

import java.util.Collections
import java.util.concurrent.locks.ReentrantLock

internal actual typealias HiddenFromJava = JvmSynthetic

internal actual fun newEnrollmentLock(): EnrollmentLock = object : EnrollmentLock {
    private val lock = ReentrantLock()
    override fun lock() = lock.lock()
    override fun unlock() = lock.unlock()
}

internal actual fun <T> frozenList(values: List<T>): List<T> = Collections.unmodifiableList(values.toList())
