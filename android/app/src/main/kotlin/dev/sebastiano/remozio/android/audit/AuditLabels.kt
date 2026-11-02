package dev.sebastiano.remozio.android.audit

import androidx.annotation.StringRes
import dev.sebastiano.remozio.android.R
import dev.remozio.protocol.*

@StringRes internal fun auditLabel(value: AuditEventKind): Int = when (value) {
    AuditEventKind.UNKNOWN -> R.string.audit_unknown
    AuditEventKind.REQUEST_CREATED -> R.string.audit_event_kind_request_created
    AuditEventKind.PHONE_DECISION -> R.string.audit_event_kind_phone_decision
    AuditEventKind.DECISION_ACCEPTED -> R.string.audit_event_kind_decision_accepted
    AuditEventKind.DECISION_REJECTED -> R.string.audit_event_kind_decision_rejected
    AuditEventKind.CONSUMED -> R.string.audit_event_kind_consumed
    AuditEventKind.DISPATCHED -> R.string.audit_event_kind_dispatched
    AuditEventKind.VERIFIED_RESULT -> R.string.audit_event_kind_verified_result
    AuditEventKind.EXPIRED -> R.string.audit_event_kind_expired
    AuditEventKind.CANCELLED -> R.string.audit_event_kind_cancelled
    AuditEventKind.UNKNOWN_OUTCOME -> R.string.audit_event_kind_unknown_outcome
    AuditEventKind.ENROLLMENT_ADDED -> R.string.audit_event_kind_enrollment_added
    AuditEventKind.ENROLLMENT_REVOKED -> R.string.audit_event_kind_enrollment_revoked
    AuditEventKind.RECOVERY -> R.string.audit_event_kind_recovery
    AuditEventKind.UPDATE_SCHEDULED -> R.string.audit_event_kind_update_scheduled
    AuditEventKind.UPDATE_ACTIVATED -> R.string.audit_event_kind_update_activated
    AuditEventKind.UPDATE_INTERRUPTED -> R.string.audit_event_kind_update_interrupted
    AuditEventKind.BRIDGE_STARTED -> R.string.audit_event_kind_bridge_started
    AuditEventKind.BRIDGE_STOPPED -> R.string.audit_event_kind_bridge_stopped
    AuditEventKind.DISMISSED -> R.string.audit_event_kind_dismissed
    AuditEventKind.BIOMETRIC_CANCELLED -> R.string.audit_event_kind_biometric_cancelled
    AuditEventKind.AGGREGATED_REJECTIONS -> R.string.audit_event_kind_aggregated_rejections
    AuditEventKind.ROUTING_CHANGED -> R.string.audit_event_kind_routing_changed
}

@StringRes internal fun auditLabel(value: AuditCategory): Int = when (value) {
    AuditCategory.UNKNOWN -> R.string.audit_unknown
    AuditCategory.COMMAND -> R.string.audit_category_command
    AuditCategory.ONE_PASSWORD_ACCESS -> R.string.audit_category_one_password_access
    AuditCategory.ONE_PASSWORD_UNLOCK -> R.string.audit_category_one_password_unlock
    AuditCategory.LITTLE_SNITCH -> R.string.audit_category_little_snitch
    AuditCategory.ENROLLMENT -> R.string.audit_category_enrollment
    AuditCategory.AUTHORITY -> R.string.audit_category_authority
    AuditCategory.UPDATE -> R.string.audit_category_update
    AuditCategory.ADB_BRIDGE -> R.string.audit_category_adb_bridge
}

@StringRes internal fun auditLabel(value: AuditActionKind): Int = when (value) {
    AuditActionKind.UNKNOWN -> R.string.audit_unknown
    AuditActionKind.DECLINE -> R.string.audit_action_kind_decline
    AuditActionKind.CANCEL_TARGET -> R.string.audit_action_kind_cancel_target
    AuditActionKind.EXECUTE -> R.string.audit_action_kind_execute
    AuditActionKind.APPROVE_ACCESS -> R.string.audit_action_kind_approve_access
    AuditActionKind.UNLOCK_VAULT -> R.string.audit_action_kind_unlock_vault
    AuditActionKind.ALLOW -> R.string.audit_action_kind_allow
    AuditActionKind.DENY -> R.string.audit_action_kind_deny
    AuditActionKind.REMOVE_RULE -> R.string.audit_action_kind_remove_rule
}

@StringRes internal fun auditLabel(value: AuditLifetime): Int = when (value) {
    AuditLifetime.UNKNOWN -> R.string.audit_unknown
    AuditLifetime.CURRENT_REQUEST -> R.string.audit_lifetime_current_request
    AuditLifetime.SESSION -> R.string.audit_lifetime_session
    AuditLifetime.TIMED -> R.string.audit_lifetime_timed
    AuditLifetime.FOREVER -> R.string.audit_lifetime_forever
}

@StringRes internal fun auditLabel(value: AuditTargetScope): Int = when (value) {
    AuditTargetScope.UNKNOWN -> R.string.audit_unknown
    AuditTargetScope.HOST -> R.string.audit_target_scope_host
    AuditTargetScope.DOMAIN -> R.string.audit_target_scope_domain
    AuditTargetScope.ANY -> R.string.audit_target_scope_any
}

@StringRes internal fun auditLabel(value: AuditAuthentication): Int = when (value) {
    AuditAuthentication.UNKNOWN -> R.string.audit_unknown
    AuditAuthentication.UNVERIFIED -> R.string.audit_authentication_unverified
    AuditAuthentication.DECISION_KEY -> R.string.audit_authentication_decision_key
    AuditAuthentication.BIOMETRIC_KEY -> R.string.audit_authentication_biometric_key
    AuditAuthentication.LOCAL_ADMINISTRATOR -> R.string.audit_authentication_local_administrator
    AuditAuthentication.SYSTEM -> R.string.audit_authentication_system
    AuditAuthentication.LOCAL_USER -> R.string.audit_authentication_local_user
}

@StringRes internal fun auditLabel(value: AuditOutcome): Int = when (value) {
    AuditOutcome.UNKNOWN -> R.string.audit_unknown
    AuditOutcome.PENDING -> R.string.audit_outcome_pending
    AuditOutcome.ACCEPTED -> R.string.audit_outcome_accepted
    AuditOutcome.REJECTED -> R.string.audit_outcome_rejected
    AuditOutcome.NO_DISPATCH -> R.string.audit_outcome_no_dispatch
    AuditOutcome.ATTEMPTED -> R.string.audit_outcome_attempted
    AuditOutcome.VERIFIED_SUCCESS -> R.string.audit_outcome_verified_success
    AuditOutcome.VERIFIED_FAILURE -> R.string.audit_outcome_verified_failure
    AuditOutcome.UNRESOLVED -> R.string.audit_outcome_unresolved
    AuditOutcome.CANCELLED -> R.string.audit_outcome_cancelled
    AuditOutcome.EXPIRED -> R.string.audit_outcome_expired
}

@StringRes internal fun auditLabel(value: AuditReason): Int = when (value) {
    AuditReason.UNKNOWN -> R.string.audit_unknown
    AuditReason.NONE -> R.string.audit_reason_none
    AuditReason.USER_DECLINED -> R.string.audit_reason_user_declined
    AuditReason.USER_CANCELLED -> R.string.audit_reason_user_cancelled
    AuditReason.AUTHORIZATION_EXPIRED -> R.string.audit_reason_authorization_expired
    AuditReason.TARGET_TIMED_OUT -> R.string.audit_reason_target_timed_out
    AuditReason.TARGET_DISAPPEARED -> R.string.audit_reason_target_disappeared
    AuditReason.REVOKED -> R.string.audit_reason_revoked
    AuditReason.BINDING_MISMATCH -> R.string.audit_reason_binding_mismatch
    AuditReason.REPLAY -> R.string.audit_reason_replay
    AuditReason.INCOMPATIBLE -> R.string.audit_reason_incompatible
    AuditReason.AUTHORITY_RESTARTED -> R.string.audit_reason_authority_restarted
    AuditReason.STORAGE_UNAVAILABLE -> R.string.audit_reason_storage_unavailable
    AuditReason.OUTCOME_UNAVAILABLE -> R.string.audit_reason_outcome_unavailable
    AuditReason.UPDATE_INTERRUPTED -> R.string.audit_reason_update_interrupted
    AuditReason.PEER_DISCONNECTED -> R.string.audit_reason_peer_disconnected
    AuditReason.MANUAL_STOP -> R.string.audit_reason_manual_stop
}

@StringRes internal fun auditLabel(value: AuditEpochCause): Int = when (value) {
    AuditEpochCause.INITIAL -> R.string.audit_epoch_initial
    AuditEpochCause.RESTART -> R.string.audit_epoch_restart
    AuditEpochCause.REPLACEMENT -> R.string.audit_epoch_replacement
    AuditEpochCause.RECOVERY -> R.string.audit_epoch_recovery
    AuditEpochCause.RESTORATION -> R.string.audit_epoch_restoration
    AuditEpochCause.UNKNOWN -> R.string.audit_unknown
}
