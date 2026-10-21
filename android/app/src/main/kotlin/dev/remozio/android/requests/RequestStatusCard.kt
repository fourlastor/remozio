package dev.remozio.android.requests

import dev.remozio.phone.requests.TrackedRequestStatus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.remozio.android.R
import dev.remozio.protocol.RequestPhase
import dev.remozio.protocol.RequestStatusReason

internal enum class StatusHeadline {
    QUEUED, PRESENTED, AUTHORIZED, EXECUTING, SUCCEEDED, FAILED, UNKNOWN, DECLINED,
    CANCELLED, DISAPPEARED, RESTART_CANCELLED, NOT_DISPATCHED, AUTHORIZATION_EXPIRED, TARGET_EXPIRED,
}

internal fun statusHeadline(status: TrackedRequestStatus): StatusHeadline = when (status.status.phase) {
    RequestPhase.QUEUED -> StatusHeadline.QUEUED
    RequestPhase.PRESENTED -> StatusHeadline.PRESENTED
    RequestPhase.AUTHORIZED -> StatusHeadline.AUTHORIZED
    RequestPhase.EXECUTING -> StatusHeadline.EXECUTING
    RequestPhase.SUCCEEDED -> StatusHeadline.SUCCEEDED
    RequestPhase.FAILED -> StatusHeadline.FAILED
    RequestPhase.UNKNOWN -> StatusHeadline.UNKNOWN
    RequestPhase.DECLINED -> StatusHeadline.DECLINED
    RequestPhase.CANCELLED -> when (status.status.reason) {
        RequestStatusReason.TARGET_DISAPPEARED -> StatusHeadline.DISAPPEARED
        RequestStatusReason.AUTHORITY_RESTARTED -> StatusHeadline.RESTART_CANCELLED
        RequestStatusReason.NO_DISPATCH_PROVED -> StatusHeadline.NOT_DISPATCHED
        else -> StatusHeadline.CANCELLED
    }
    RequestPhase.EXPIRED -> if (status.status.reason == RequestStatusReason.TARGET_TIMED_OUT)
        StatusHeadline.TARGET_EXPIRED else StatusHeadline.AUTHORIZATION_EXPIRED
}

internal fun statusHeadlineResource(snapshot: TrackedRequestStatus): Int = when (statusHeadline(snapshot)) {
        StatusHeadline.QUEUED -> R.string.status_queued
        StatusHeadline.PRESENTED -> R.string.status_presented
        StatusHeadline.AUTHORIZED -> R.string.status_authorized
        StatusHeadline.EXECUTING -> R.string.status_executing
        StatusHeadline.SUCCEEDED -> R.string.status_succeeded
        StatusHeadline.FAILED -> R.string.status_failed
        StatusHeadline.UNKNOWN -> R.string.status_unknown
        StatusHeadline.DECLINED -> R.string.status_declined
        StatusHeadline.CANCELLED -> R.string.status_cancelled
        StatusHeadline.DISAPPEARED -> R.string.status_disappeared
        StatusHeadline.RESTART_CANCELLED -> R.string.status_restart_cancelled
        StatusHeadline.NOT_DISPATCHED -> R.string.status_not_dispatched
        StatusHeadline.AUTHORIZATION_EXPIRED -> R.string.status_authorization_expired
        StatusHeadline.TARGET_EXPIRED -> R.string.status_target_expired
    }

/** Read-only status. Countdown changes never enter the status announcement node. */
@Composable
internal fun RequestStatusCard(snapshot: TrackedRequestStatus) {
    val status = snapshot.status
    val timing = snapshot.timing
    val headline = statusHeadlineResource(snapshot)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(headline), style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading(); liveRegion = LiveRegionMode.Polite })
            Text(stringResource(R.string.status_age_lower_bound, seconds(timing.ageLowerBoundMs)))
            if (timing.clockUncertain) Text(stringResource(R.string.status_clock_uncertain))
            if (timing.deliveryDelayUnknown) Text(stringResource(R.string.status_delivery_unknown), style = MaterialTheme.typography.bodySmall)
            if (!status.phase.isTerminal) {
                timing.authorizationRemainingUpperBoundMs?.let { remaining ->
                    Text(if (remaining == 0uL) stringResource(R.string.status_authorization_elapsed)
                        else stringResource(R.string.status_authorization_remaining, secondsCeiling(remaining)))
                }
                timing.estimatedTargetRemainingMs?.let { remaining ->
                    Text(if (remaining == 0uL) stringResource(R.string.status_estimate_elapsed)
                        else stringResource(R.string.status_estimate_remaining, secondsCeiling(remaining)))
                    Text(stringResource(R.string.status_estimate_explanation), style = MaterialTheme.typography.bodySmall)
                }
                if (status.lateObservation) Text(stringResource(R.string.status_late_observation))
            } else {
                status.terminalAgeMs?.let { Text(stringResource(R.string.status_terminal_age, seconds(it))) }
            }
            if (status.decisionPhoneID != null) Text(stringResource(R.string.status_phone_decided))
        }
    }
}

/** List summary. Full inspection keeps the complete signed timing and outcome explanation. */
@Composable
internal fun RequestStatusSummary(snapshot: TrackedRequestStatus) {
    val status = snapshot.status
    val timing = snapshot.timing
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(statusHeadlineResource(snapshot)), style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        Text(stringResource(R.string.status_age_lower_bound, seconds(timing.ageLowerBoundMs)), style = MaterialTheme.typography.bodySmall)
        if (timing.clockUncertain) Text(stringResource(R.string.status_clock_uncertain), style = MaterialTheme.typography.bodySmall)
        if (timing.deliveryDelayUnknown) Text(stringResource(R.string.status_delivery_unknown), style = MaterialTheme.typography.bodySmall)
        if (!status.phase.isTerminal) {
            timing.authorizationRemainingUpperBoundMs?.let { remaining ->
                Text(if (remaining == 0uL) stringResource(R.string.status_authorization_elapsed)
                    else stringResource(R.string.status_authorization_remaining, secondsCeiling(remaining)), style = MaterialTheme.typography.bodySmall)
            }
            timing.estimatedTargetRemainingMs?.let { remaining ->
                Text(if (remaining == 0uL) stringResource(R.string.status_estimate_elapsed)
                    else stringResource(R.string.status_estimate_remaining, secondsCeiling(remaining)), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.status_estimate_explanation), style = MaterialTheme.typography.bodySmall)
            }
            if (status.lateObservation) Text(stringResource(R.string.status_late_observation), style = MaterialTheme.typography.bodySmall)
        } else {
            status.terminalAgeMs?.let { Text(stringResource(R.string.status_terminal_age, seconds(it)), style = MaterialTheme.typography.bodySmall) }
        }
        if (status.decisionPhoneID != null) Text(stringResource(R.string.status_phone_decided), style = MaterialTheme.typography.bodySmall)
    }
}

internal fun seconds(milliseconds: ULong): String = (milliseconds / 1000u).toString()
internal fun secondsCeiling(milliseconds: ULong): String = (milliseconds / 1000u + if (milliseconds % 1000u == 0uL) 0u else 1u).toString()
