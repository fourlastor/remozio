package dev.sebastiano.remozio.android.routing

import dev.remozio.protocol.RoutingStatusDestination
import dev.remozio.protocol.RoutingStatusMode
import dev.remozio.protocol.RoutingStatusReason

/** Display only. A current mode needs both a recent verified sample and an available owner. */
internal class MacRoutingDisplay(
    val availability: MacRoutingAvailability,
    val currentMode: RoutingStatusMode?,
    val lastKnownMode: RoutingStatusMode?,
    val destination: RoutingStatusDestination?,
    val reason: RoutingStatusReason?,
    val detectionLimited: Boolean,
    val sampleAgeMilliseconds: Long?,
    val action: MacRoutingAction,
    val canSetAway: Boolean,
) {
    override fun toString() = "MacRoutingDisplay(redacted)"
}

internal fun routingDisplay(status: MacRoutingStatus, freshnessMilliseconds: Long, canSetAway: Boolean): MacRoutingDisplay {
    require(freshnessMilliseconds > 0)
    val observed = status.observation
    val age = observed?.ageMilliseconds()
    val current = status.availability == MacRoutingAvailability.ONLINE && age != null && age < freshnessMilliseconds
    val availability = if (status.availability == MacRoutingAvailability.ONLINE && !current) MacRoutingAvailability.OFFLINE else status.availability
    val state = observed?.response?.state
    return MacRoutingDisplay(availability,
        currentMode = state?.mode.takeIf { current }, lastKnownMode = state?.mode.takeUnless { current },
        destination = state?.destination.takeIf { current }, reason = state?.reason.takeIf { current },
        detectionLimited = current && state?.detectionLimited == true,
        sampleAgeMilliseconds = age, action = status.action,
        canSetAway = current && canSetAway && state?.mode != RoutingStatusMode.AWAY && status.action != MacRoutingAction.SETTING_AWAY)
}
