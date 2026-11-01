package dev.remozio.android.updates

import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.UpdateSchedulingAction
import dev.remozio.protocol.UpdateSchedulingBlocker
import dev.remozio.protocol.UpdateSchedulingDesignation
import dev.remozio.protocol.UpdateSchedulingProgressResponse

internal class MacUpdateBlockerDisplay(
    val kind: UpdateSchedulingBlocker.Kind,
    val count: ULong?,
    val oldestAgeMilliseconds: ULong?,
)

/** Displays verified facts. Eligibility never replaces a fresh scheduling challenge. */
internal class MacUpdateDisplay(
    val current: UpdateSchedulingProgressResponse?,
    val lastKnown: UpdateSchedulingProgressResponse?,
    val sampleAgeMilliseconds: Long?,
    val readyAgeMilliseconds: ULong?,
    val blockers: List<MacUpdateBlockerDisplay>,
    val attempt: MacUpdateSchedulingAttempt?,
    val tooLate: Boolean,
    val canInstall: Boolean,
    val canDefer: Boolean,
    val canCancelDrain: Boolean,
) {
    override fun toString() = "MacUpdateDisplay(redacted)"
}

internal fun macUpdateDisplay(
    record: StoredPhoneEnrollment,
    progress: MacUpdateProgressState,
    scheduling: MacUpdateSchedulingState,
    freshnessMilliseconds: Long,
    canSchedule: Boolean,
    canOffer: (UpdateSchedulingAction) -> Boolean,
): MacUpdateDisplay {
    require(freshnessMilliseconds > 0)
    val direct = progress.observation?.takeIf { it.matchesEnrollment(record) }
    val late = scheduling.tooLate?.takeIf { it.matchesEnrollment(record) }
    val directAge = direct?.ageMilliseconds()
    val lateAge = late?.ageMilliseconds()
    val directFresh = direct != null && progress.availability == MacUpdateProgressAvailability.ONLINE &&
        direct.isFresh(freshnessMilliseconds)
    val lateFresh = late != null && scheduling.availability == MacUpdateSchedulingAvailability.ONLINE &&
        late.isFresh(freshnessMilliseconds)
    val directFrame = direct?.response
    val lateFrame = late?.response?.progress
    val sameUpdate = directFrame != null && lateFrame != null &&
        directFrame.status.scope == lateFrame.status.scope && directFrame.status.updateID == lateFrame.status.updateID &&
        directFrame.status.generation == lateFrame.status.generation
    val useLate = lateFrame != null && when {
        directFrame == null -> true
        lateFresh && !directFresh -> true
        directFresh && !lateFresh -> false
        sameUpdate -> when {
            !directFrame.phase.irreversible -> true
            lateFrame.status.revision != directFrame.status.revision ->
                lateFrame.status.revision > directFrame.status.revision
            else -> lateAge != null && (directAge == null || lateAge < directAge)
        }
        directFresh -> false
        else -> lateAge != null && (directAge == null || lateAge < directAge)
    }
    val frame = if (useLate) lateFrame else directFrame
    val age = if (useLate) lateAge else directAge
    val current = if (useLate) lateFresh else directFresh
    val status = scheduling.observation?.takeIf { it.matchesEnrollment(record) }
    val coherent = !useLate && current && scheduling.tooLate == null &&
        scheduling.availability == MacUpdateSchedulingAvailability.ONLINE && status?.isFresh(freshnessMilliseconds) == true &&
        frame?.status?.let { displayed ->
            val selected = status.response
            displayed.scope == selected.scope && displayed.updateID == selected.updateID &&
                displayed.generation == selected.generation && displayed.revision == selected.revision &&
                displayed.requestedAction == selected.requestedAction
        } == true && scheduling.attempt?.outcome != MacUpdateSchedulingOutcome.SUBMITTING && canSchedule
    fun eligible(action: UpdateSchedulingAction, rootAllows: Boolean): Boolean = coherent && rootAllows && canOffer(action)
    val elapsed = age?.toULong()
    return MacUpdateDisplay(
        current = frame.takeIf { current },
        lastKnown = frame.takeUnless { current },
        sampleAgeMilliseconds = age,
        readyAgeMilliseconds = frame?.readyAgeMillisecondsAfterObservation(elapsed),
        blockers = frame?.blockers.orEmpty().map {
            MacUpdateBlockerDisplay(it.kind, it.count, it.oldestAgeMillisecondsAfterObservation(elapsed))
        },
        attempt = scheduling.attempt,
        tooLate = lateFrame != null && (useLate || sameUpdate),
        canInstall = eligible(UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES,
            frame?.canInstallWhenCurrentWorkFinishes == true),
        canDefer = eligible(UpdateSchedulingAction.DEFER_UPDATE,
            frame?.canDeferUpdate == true && frame.designation == UpdateSchedulingDesignation.THIS_ACCOUNT),
        canCancelDrain = eligible(UpdateSchedulingAction.CANCEL_DRAIN, frame?.canCancelDrain == true),
    )
}
