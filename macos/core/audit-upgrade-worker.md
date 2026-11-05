# Bounded maintenance work

The default Swift worker thread has a small stack on this Mac.
Earlier isolated Debug probes reached that limit in real preparation and cutover code.
Both probes reported a 536576-byte stack and stopped with SIGBUS.
This is recorded from the donor investigation. It was not measured again for this change.

The preparation crash reached `RuntimeConfigurationBundle.init(retaining:)` through artifact capture.
The cutover crash reached activation-plan decoding through the machine store.

## Execution and cancellation

`SetupAuditUpgradeWorkExecutor` runs one blocking body at a time on a thread with an explicit 8 MiB stack.
The setup owner keeps one executor. It starts no thread while it is idle.
A concurrent request fails. It does not start another body or join a queue.
A finished or failed body frees the slot before its result returns.

The waiting Swift task uses a cancellation handler.
The handler cancels an explicit `SetupAuditUpgradeCancellation` token.
The endpoint imports authorization on the exported invocation and passes it to `performAuditUpgradeWork`.
The setup owner takes the worker's cancellation token from that same authorization.
Authorization checks the token before and after every rights check.
So the setup scope sees cancellation on the blocking thread, where `Task.isCancelled` is false.
Cleanup needs no live rights and no uncancelled token.
Cancellation does not release resources that another thread holds.
After cancellation, failed cleanup stays with the setup owner until a retry succeeds.

## Test coverage

Worker tests check that a managed worker thread has at least 8 MiB of stack.
They run source-plan rebuilding, target staging, graph capture and storage,
and a complete owned invocation with file cutover, metadata commit, fake registration and cleanup.

Owned rights tests also cover cancellation before admission, cancellation after scope admission,
cancellation during the cutover with failed cleanup, a failed body followed by a successful body,
and refusal of a concurrent body.
These tests use process-owned files, SQLite, fake rights and fake registration operations.
They do not qualify native authorization import, service-account isolation, real XPC or installed launchd behaviour.
The exported maintenance method in the setup daemon uses this executor.
See [the endpoint contract](audit-upgrade-endpoint.md) for integration limits.
