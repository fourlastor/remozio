package dev.remozio.phone.updates

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*

/** A Root-verified rejection. An earlier copy of an apply request can still have committed. */
class PhoneUpdateSchedulingTooLateObservation internal constructor(
    val response: UpdateSchedulingTooLateResponse,
    private val record: StoredPhoneEnrollment,
    private val age: UpdateSchedulingAge,
) : AutoCloseable {
    fun matchesEnrollment(current: StoredPhoneEnrollment) =
        current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current)
    fun ageMilliseconds(): Long? = age.milliseconds()
    fun isFresh(maximumAgeMilliseconds: Long): Boolean {
        require(maximumAgeMilliseconds > 0)
        return ageMilliseconds()?.let { it < maximumAgeMilliseconds } == true
    }
    fun readyAgeUpperBoundMilliseconds(): ULong? = response.progress.readyAgeMillisecondsAfterObservation(
        ageMilliseconds()?.toULong())
    override fun close() = age.retire()
    override fun toString() = "PhoneUpdateSchedulingTooLateObservation(redacted)"
}

/** The caller supplies the original request age and rechecks enrollment before publishing this observation. */
internal fun verifyPhoneUpdateSchedulingTooLate(
    record: StoredPhoneEnrollment,
    current: StoredPhoneEnrollment,
    request: PhoneUpdateSchedulingFrame,
    payload: ByteArray,
    signature: ByteArray,
    age: UpdateSchedulingAge,
    replyTimeoutMillis: Long,
): PhoneUpdateSchedulingTooLateObservation {
    require(replyTimeoutMillis in 1..60_000 && current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
    require(age.milliseconds()?.let { it < replyTimeoutMillis } == true)
    require(payload.size <= UpdateSchedulingTooLateResponse.MAXIMUM_BYTES && signature.size == 64)
    val captured = payload.copyOf()
    val signed = signature.copyOf()
    require(UpdateSchedulingTooLateSignature.verify(signed, record.enrollment.authorityPublicKey.copyBytes(),
        1u, captured, CborLimits(8192, 2, 32)))
    val response = UpdateSchedulingTooLateResponse.decode(captured)
    val enrollment = record.enrollment
    require(response.matches(request, ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(),
        enrollment.phoneID.copyBytes(), enrollment.epoch.copyBytes())))
    require(age.milliseconds()?.let { it < replyTimeoutMillis } == true)
    return PhoneUpdateSchedulingTooLateObservation(response, record, age)
}
