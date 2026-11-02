package dev.sebastiano.remozio.android

/** Main-thread operation ownership. A stopped screen cannot accept an old callback. */
internal class ProbeOperation {
    private var current: Any? = null
    fun begin(): Any = Any().also { current = it }
    fun owns(token: Any): Boolean = current === token
    fun invalidate() { current = null }
    fun complete(token: Any): Boolean {
        if (!owns(token)) return false
        invalidate()
        return true
    }
}

/** Providers may wrap an authentication failure during update or sign. Never match error text. */
internal fun hasAuthenticationCause(error: Throwable, matches: (Throwable) -> Boolean): Boolean {
    val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
    var current: Throwable? = error
    repeat(16) {
        val cause = current ?: return false
        if (!seen.add(cause)) return false
        if (matches(cause)) return true
        current = cause.cause
    }
    return false
}
