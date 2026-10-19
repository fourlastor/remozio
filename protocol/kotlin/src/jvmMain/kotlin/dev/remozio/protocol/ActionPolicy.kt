package dev.remozio.protocol

enum class RequestKind { COMMAND, ONE_PASSWORD_ACCESS, ONE_PASSWORD_UNLOCK, LITTLE_SNITCH }
enum class ActionChoice {
    DECLINE, CANCEL_TARGET, EXECUTE, APPROVE_ACCESS, UNLOCK_VAULT,
    ALLOW_ONCE, DENY_ONCE, ALLOW_RULE, DENY_RULE, REMOVE_RULE,
}

sealed interface ActionScope {
    data object CurrentRequest : ActionScope
    data object Session : ActionScope
    data class Timed(val seconds: ULong) : ActionScope
    data object Forever : ActionScope
}

data class CapturedAction(val choice: ActionChoice, val scope: ActionScope)
enum class ApprovalKeyClass { DECISION, BIOMETRIC }
enum class ApprovalPurpose { CANCELLATION, ONE_TIME_UI, BIOMETRIC_AUTHORIZATION }
enum class ActionEffect { RESOLVE_REQUEST, DISPATCH_TARGET }
data class ActionRequirement(val keyClass: ApprovalKeyClass, val purpose: ApprovalPurpose, val effect: ActionEffect)
enum class ActionPolicyFailure { NOT_PERMITTED, INCOMPATIBLE_ACTION, INVALID_SCOPE }
class ActionPolicyException(val reason: ActionPolicyFailure) : IllegalArgumentException(reason.name)

/** Evaluate against trusted capture, never a permitted-action list supplied by a decision. */
object ActionPolicy {
    fun requirement(
        action: CapturedAction,
        requestKind: RequestKind,
        retainedPermittedActions: Set<CapturedAction>,
    ): ActionRequirement {
        ensure(action in retainedPermittedActions, ActionPolicyFailure.NOT_PERMITTED)
        return when (action.choice) {
            ActionChoice.DECLINE -> {
                requireCurrentRequest(action.scope)
                ActionRequirement(ApprovalKeyClass.DECISION, ApprovalPurpose.CANCELLATION, ActionEffect.RESOLVE_REQUEST)
            }
            ActionChoice.CANCEL_TARGET -> {
                ensure(requestKind != RequestKind.COMMAND, ActionPolicyFailure.INCOMPATIBLE_ACTION)
                requireCurrentRequest(action.scope)
                ActionRequirement(ApprovalKeyClass.DECISION, ApprovalPurpose.ONE_TIME_UI, ActionEffect.DISPATCH_TARGET)
            }
            ActionChoice.EXECUTE -> {
                ensure(requestKind == RequestKind.COMMAND, ActionPolicyFailure.INCOMPATIBLE_ACTION)
                requireCurrentRequest(action.scope)
                biometric
            }
            ActionChoice.APPROVE_ACCESS -> {
                ensure(requestKind == RequestKind.ONE_PASSWORD_ACCESS, ActionPolicyFailure.INCOMPATIBLE_ACTION)
                requireCurrentRequest(action.scope)
                biometric
            }
            ActionChoice.UNLOCK_VAULT -> {
                ensure(requestKind == RequestKind.ONE_PASSWORD_UNLOCK, ActionPolicyFailure.INCOMPATIBLE_ACTION)
                requireCurrentRequest(action.scope)
                biometric
            }
            ActionChoice.ALLOW_ONCE, ActionChoice.DENY_ONCE -> {
                ensure(requestKind == RequestKind.LITTLE_SNITCH, ActionPolicyFailure.INCOMPATIBLE_ACTION)
                requireCurrentRequest(action.scope)
                ActionRequirement(ApprovalKeyClass.DECISION, ApprovalPurpose.ONE_TIME_UI, ActionEffect.DISPATCH_TARGET)
            }
            ActionChoice.ALLOW_RULE, ActionChoice.DENY_RULE, ActionChoice.REMOVE_RULE -> {
                ensure(requestKind == RequestKind.LITTLE_SNITCH, ActionPolicyFailure.INCOMPATIBLE_ACTION)
                ensure(
                    when (val scope = action.scope) {
                        ActionScope.Session, ActionScope.Forever -> true
                        is ActionScope.Timed -> scope.seconds > 0uL
                        ActionScope.CurrentRequest -> false
                    },
                    ActionPolicyFailure.INVALID_SCOPE,
                )
                biometric
            }
        }
    }

    private val biometric = ActionRequirement(
        ApprovalKeyClass.BIOMETRIC, ApprovalPurpose.BIOMETRIC_AUTHORIZATION, ActionEffect.DISPATCH_TARGET,
    )

    private fun requireCurrentRequest(scope: ActionScope) = ensure(scope == ActionScope.CurrentRequest, ActionPolicyFailure.INVALID_SCOPE)
    private fun ensure(condition: Boolean, failure: ActionPolicyFailure) {
        if (!condition) throw ActionPolicyException(failure)
    }
}
