package dev.remozio.phone.transport

import dev.remozio.phone.updates.PhoneUpdateSchedulingChallenge
import dev.remozio.phone.updates.PhoneUpdateSchedulingTooLateObservation

/** The caller owns the returned challenge or observation until it transfers or closes the result. */
sealed class PhoneUpdateSchedulingChallengeResult : AutoCloseable {
    class Ready(val challenge: PhoneUpdateSchedulingChallenge) : PhoneUpdateSchedulingChallengeResult() {
        override fun close() = challenge.close()
    }
    class TooLate(val observation: PhoneUpdateSchedulingTooLateObservation) : PhoneUpdateSchedulingChallengeResult() {
        override fun close() = observation.close()
    }
    override fun toString() = "PhoneUpdateSchedulingChallengeResult(redacted)"
}

/** TooLate preserves uncertainty about an earlier copy of the apply request. It is not an acknowledgment. */
sealed class PhoneUpdateSchedulingApplyResult : AutoCloseable {
    class Applied(val status: PhoneUpdateSchedulingStatus) : PhoneUpdateSchedulingApplyResult() {
        override fun close() = status.close()
    }
    class TooLate(val observation: PhoneUpdateSchedulingTooLateObservation) : PhoneUpdateSchedulingApplyResult() {
        override fun close() = observation.close()
    }
    override fun toString() = "PhoneUpdateSchedulingApplyResult(redacted)"
}
