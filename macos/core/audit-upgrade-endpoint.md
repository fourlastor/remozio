# Audit upgrade setup endpoint

The existing setup daemon exports an additional maintenance interface.
`AdministrativeSetupMaintenanceXPCProtocol` combines the original client protocol with `AuditUpgradeSetupXPCProtocol`.
Existing client selectors and their handshake versions do not change.
This change needs no second service and no new installation.

## Release and caller checks

Maintenance uses local setup version 11 and progress codec version 1.
The native handshake checks the installed signed release and the current inventory.
The app component and the setup component must both declare version 11 and the progress codec.
The release must also pass the complete cutover capability checks.
The release generator declares both formats for these two components only.
It keeps the earlier setup versions 1 to 10.
The app channel that opens this interface is a separate change.

The endpoint authenticates each exported invocation with its existing peer guard.
It checks the size of the expected progress and decodes it before it imports authorization.
The owner UID in the progress and the UID of the imported grant must both equal the kernel-authenticated caller UID.
The invocation factory then compares the complete Mac, account, installation, release and initialization scope.
A request from the same UID for another Mac cannot select work for this account.
The external authorization form never crosses task dispatch.

## Execution and reply ownership

The native endpoint imports the authorization on the exported invocation.
It runs the work on the setup owner's maintenance worker.
The worker has an explicit 8 MiB stack and runs one body at a time.
The worker takes its cancellation token from that same grant.
The mutation path takes no outer shared Root activity token and no second setup admission.
The invocation keeps its authorization, operation and setup admission until the reply callback returns.

Every reply is sent while the invocation still holds the setup reservation.
This includes the failure reply.
Cleanup starts only after the reply callback returns.
If the operation never opened, the endpoint sends the failure reply after the task ends. No reservation exists then.

Closing the endpoint cancels its maintenance task.
The setup scope checks cancellation on the blocking thread.
Cleanup runs after the reply callback and outside the endpoint lock.
Failed cleanup moves to the setup owner before the task drops its invocation.
A later valid native connection retries kept cleanup before normal owner admission.
Daemon shutdown also retries kept cleanup until it succeeds.
Cleanup retries do not resume the upgrade or start services.

Read-only recovery keeps the account ownership and installation checks.
It skips only the account startup fence.
A saved metadata commit does not say that services are registered or healthy.

## Verification limits

Owned fixtures call the exported methods directly.
They cover handshake and request bounds, release refusal, kernel UID binding,
rights import before dispatch, worker stack size, the complete cutover, scoped replies,
the failure reply before cleanup, rejection of another Mac with the same UID,
cancellation on disconnect, invalidation during the cutover, and kept cleanup after failure.
Legacy endpoint checks remain part of validation.
Objective-C interface construction checks the old and the combined selector sets.

These checks do not qualify native administrator rights, native peer signatures
or installed launchd behaviour.
No anonymous XPC test is part of this change; it needs the app channel.
No service installation, production credential access or physical phone test happens here.
