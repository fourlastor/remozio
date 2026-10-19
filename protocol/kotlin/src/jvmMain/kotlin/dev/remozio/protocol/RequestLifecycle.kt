package dev.remozio.protocol

enum class RequestPhase {
    QUEUED, PRESENTED, AUTHORIZED, EXECUTING,
    SUCCEEDED, FAILED, UNKNOWN, DECLINED, CANCELLED, EXPIRED;

    val isTerminal: Boolean
        get() = when (this) {
            QUEUED, PRESENTED, AUTHORIZED, EXECUTING -> false
            else -> true
        }
}

enum class RequestEvent {
    PRESENT, AUTHORIZE, DECLINE, CANCEL, EXPIRE, BEGIN_DISPATCH,
    VERIFY_SUCCESS, VERIFY_FAILURE, LOSE_OUTCOME, RESTART_AUTHORITY, PROVE_NO_DISPATCH, LOSE_TARGET,
}

enum class LifecycleFailure { TERMINAL, INVALID_TRANSITION }
class LifecycleException(val reason: LifecycleFailure) : IllegalStateException(reason.name)

/** A transition rule, not a dispatch permit. The authority must serialize and durably commit changes. */
object RequestLifecycle {
    fun transition(phase: RequestPhase, event: RequestEvent): RequestPhase {
        if (phase.isTerminal) throw LifecycleException(LifecycleFailure.TERMINAL)
        val pending = phase == RequestPhase.QUEUED || phase == RequestPhase.PRESENTED
        return when {
            phase == RequestPhase.QUEUED && event == RequestEvent.PRESENT -> RequestPhase.PRESENTED
            pending && event == RequestEvent.AUTHORIZE -> RequestPhase.AUTHORIZED
            pending && event == RequestEvent.DECLINE -> RequestPhase.DECLINED
            pending && event == RequestEvent.CANCEL -> RequestPhase.CANCELLED
            pending && event == RequestEvent.EXPIRE -> RequestPhase.EXPIRED
            pending && event == RequestEvent.LOSE_TARGET -> RequestPhase.UNKNOWN
            phase == RequestPhase.AUTHORIZED && event == RequestEvent.BEGIN_DISPATCH -> RequestPhase.EXECUTING
            phase == RequestPhase.AUTHORIZED && event == RequestEvent.PROVE_NO_DISPATCH -> RequestPhase.CANCELLED
            phase == RequestPhase.EXECUTING && event == RequestEvent.VERIFY_SUCCESS -> RequestPhase.SUCCEEDED
            phase == RequestPhase.EXECUTING && event == RequestEvent.VERIFY_FAILURE -> RequestPhase.FAILED
            !pending && event == RequestEvent.LOSE_OUTCOME -> RequestPhase.UNKNOWN
            event == RequestEvent.RESTART_AUTHORITY -> if (pending) RequestPhase.CANCELLED else RequestPhase.UNKNOWN
            else -> throw LifecycleException(LifecycleFailure.INVALID_TRANSITION)
        }
    }
}
