# Durable routing choices

`RoutingJournal` stores the selected mode for one protected Mac/account journal.
Schema 7 introduced the mode, its unsigned revision, and retained phone operations. Schema 11 preserves them and retains gateway acknowledgments. It preserves recovered delivery receipts and revocations, and adds unknown trust restrictions. Explicit migrations accept schemas 1 through 10.
A new store starts in Automatic at revision zero. Migration preserves enrollment, gateway, audit, and consumption state.
Manual choices survive restart. Routing never changes approval policy or authorizes an action.

## Local and phone controls

Enable the APIs by supplying `RoutingJournalPolicy` when opening `JournalDatabase`.
The policy supplies encoding limits, a clock epoch, a challenge lifetime, and a retained-operation limit.
The controller must expose these configurable limits through the agreed settings integration.

The protected local control surface can call `setLocalRoutingMode` with Automatic, Present, or Away.
The host must authenticate that local caller. This entry point must never become a phone or transport RPC.
Local choices do not require phone enrollment or approval-authority setup. Their audit scope comes from the protected journal identity.
Each choice advances the routing revision and writes a metadata-only audit event in the same transaction.
A stale expected revision changes nothing. Selecting the current mode still records an explicit new choice.

```mermaid
sequenceDiagram
    participant Phone
    participant Root as Root journal
    participant Local as Mac control surface
    Phone->>Root: Request challenge for authenticated enrollment and revision
    Root->>Root: Retain exact Away payload, random challenge, run and deadline
    Root-->>Phone: Return challenge after commit
    Local->>Root: Change mode against revision
    Root->>Root: Commit mode, new revision and audit event
    Phone->>Root: Return signed Away payload for old revision
    Root-->>Phone: Conflict; no mode change
```

`issueRoutingChallenge` reads current durable enrollment and its decision key inside the transaction.
The host supplies the separately authenticated phone identity and enrollment epoch, never an incoming trust snapshot.
The root generates a fresh operation ID and 256-bit challenge. It retains the exact payload and both original deadlines.
Publish the returned challenge only after commit and the required continuity checks.

`applyRoutingAway` reloads current enrollment, requires its expected trust revision, and selects only the enrolled decision key.
It verifies the separate routing signature and matches every field against the stored challenge.
An unused challenge must belong to this database run and pass both original deadlines and the routing revision check.
A newly signed expiry cannot extend the retained deadline. Removed phones and stale enrollment epochs cannot change routing.

The mode, consumed result, revision, and audit event commit atomically.
A repeated accepted operation returns its original Away result and revision while the journal retains its receipt.
That result is historical acknowledgment. The controller must also read current routing status before displaying the current mode.
Retries still require current enrollment and a valid signature. They cannot restore an earlier mode after a local change.

## Restart, storage and integration

Each database owner has a fresh run ID. Reopening preserves modes and accepted results. It rejects unused challenges from an earlier run.
A phone can obtain a fresh challenge automatically. This does not require a new biometric or administrator prompt.
After restart, new audit writes require a fresh audit epoch under the existing journal rules.

Clock regression or detected corruption retires the owner. Storage faults roll back the transaction; swallowed operation errors cannot commit later writes.
Read-only and escaped transactions cannot mutate state. A failed migration preserves its source version and existing data.
Revision overflow still fails. Routing revisions and audit records are independent of operation cleanup.

When a valid challenge request reaches the operation cap, the same write first removes unused challenges from earlier runs or past their monotonic deadline.
If space is still needed, it removes only the necessary number of eligible receipts, starting with the oldest applied revision.
A receipt is eligible after its original monotonic deadline or after its run ends. At the exact deadline the row is eligible.
If all remaining rows are live, the request fails for capacity and rolls back. It can succeed later as rows expire.
The first valid request can reclaim rows on an existing full Mac without a schema migration.
A retry for an evicted receipt fails without another mode change. Read current routing status to reconcile.
These rows do not prove freshness after a complete, internally consistent backup restoration. Whole-Mac backup rollback is outside the [accepted guarantee](../../docs/design-decisions.md#whole-mac-backup-rollback); ordinary replay and protected-state checks remain required.

The host must authenticate local and phone channels, establish continuity, and serialize calls with current enrollment changes.
It must send success only after commit, synchronize status to the Mac menu and other phones, and show conflicts without optimistic mode changes.
The routing journal does not implement those network or UI surfaces. It does not read OS presence signals or route pending requests itself.
Offline Macs remain offline or unknown; this API does not queue phone changes for later delivery.

## Audit and validation

Routing changes use audit kind `routingChanged` (22), category `authority`, and no action or request payload.
Phone changes identify the decision-key signer. Local changes use `localUser` authentication (6), without claiming administrator authorization.
Shared Swift and Kotlin audit fixtures cover both new tags. They do not permit unknown tags or change approval signing purposes.

Tests use private normal-user fixtures, synthetic enrollment, and ephemeral P-256 keys.
They cover races, exact signed bindings, revocation, expiry, restart, replay, persistent modes, atomic failures, transaction scope, capacity, corruption, and migration.
No privileged service, real phone, or provider is contacted.

See [gateway history recovery](gateway-history-recovery.md) for transactional counter repair and its trust boundary.

See [recovered gateway revocations](recovered-gateway-revocations.md) for permanent restrictions and atomic system audit events.
