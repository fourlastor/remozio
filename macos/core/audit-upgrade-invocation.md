# Audit upgrade invocation ownership

`SetupAuditUpgradeInvocation` connects the authenticated setup scope to the cutover operation.
The exported maintenance method in the setup daemon uses this internal owner.
The app reaches it through the [app channel](audit-upgrade-channel.md) and the [audit setup panel](audit-upgrade-app.md).

## Scoped observations

`SetupAuditUpgradeProgress` is a bounded, canonical CBOR frame, codec version 1.
It contains the existing runtime scope, the installation ID, the release digest and the initialization digest.
It also contains the observed stage and the registrations that this invocation confirmed.
It carries no private material, credential, graph content or file path.
A stage never grants permission to skip a cutover check.
The invocation compares the complete scope with fresh authorized setup state.
It does not trust the stage that the client sends.

The stages keep three facts apart:

| Stage | Meaning |
| --- | --- |
| `metadataCommitted` | Target files and metadata are durable. This is read from the machine store. |
| `readyToRestart` | The cutover completed in this invocation and the startup fence is removed. |
| `registrationObserved` | launchd registrations were confirmed for the listed roles. |

No stage says that a service is healthy. No stage verifies service health.
A read after a committed upgrade reports `metadataCommitted` with no observed registrations.

Read-only recovery uses the authenticated caller's account.
It checks the current inventory, account ownership, code policy, initialization and runtime scope.
It skips only the account startup fence. Normal setup still enforces that fence.

## One bounded invocation

The native factory accepts only Root and an authorization imported on the exported invocation.
It reserves setup admission without a shared Root activity token.
The operation then acquires its own exclusive token.

The invocation advances through the finite cutover stages, at most eight transitions.
It stops and replies on busy activity, busy machine storage, pending quiescence,
observed registrations or an already-selected audit runtime. It does not poll busy resources.
It checks live rights before it encodes the reply and again before it calls the reply callback.
The callback runs while the operation and the setup scope are still held.
A second run cannot send another reply or repeat the action.

After a committed cutover with no startup fence, the operation only restores the immutable private graph copy.
It does this under shared activity and a short machine-writer borrow.
The invocation and the progress codec do not rewrite live targets and do not capture the source again.

## Cleanup and retention

The endpoint calls `settleAuditUpgradeInvocation` after the work and the reply callback have returned.
The setup owner keeps the invocation before it tries cleanup.
If cleanup fails, the setup owner keeps the invocation, the operation and the setup scope.
The setup admission stays held. No path relies on a deinitializer to release it.
`retryAuditUpgradeCleanup` tries each kept cleanup once.
It does not import rights, resume the upgrade or start services.
Expired rights do not prevent cleanup.
No cleanup collection lock is held while an invocation closes.

A failed `SetupAccountOwner.close()` leaves the owner closing. It accepts no new work after that.
`closeWhenIdle` retries kept cleanup until both admissions are free, then closes the owner.
It needs no rights and no new connection.

## Verification limits

Owned SQLite, files, fake rights and fake registration operations cover these cases:
the complete invocation, reply admission, busy resources, fenced recovery, foreign scopes,
rights expiry after registration, failed replies, task cancellation, an already-selected runtime,
failed cleanup after the connection drops its reference, and shutdown with kept cleanup.
The progress codec rejects malformed fields, unknown stages, duplicate roles and invalid role claims.

These tests do not qualify native authorization import, real XPC dispatch,
privileged service changes or an installed Mac-to-phone flow. Those checks stay separate.
See [the endpoint contract](audit-upgrade-endpoint.md) for the remaining limits.
