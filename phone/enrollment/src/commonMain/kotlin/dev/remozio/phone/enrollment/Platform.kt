package dev.remozio.phone.enrollment

/** `JvmSynthetic` exists only on the JVM. Java callers must not gain access to the activation transition. */
@OptIn(ExperimentalMultiplatform::class)
@OptionalExpectation
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.SOURCE)
internal expect annotation class HiddenFromJava()

/** A reentrant mutual exclusion. The store is blocking and serves several threads. */
internal interface EnrollmentLock {
    fun lock()
    fun unlock()
}

internal expect fun newEnrollmentLock(): EnrollmentLock

/** A private copy that no caller can change. */
internal expect fun <T> frozenList(values: List<T>): List<T>
