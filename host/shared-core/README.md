# Shared host core

`RemozioHostCore` contains the shared decision verifier, its retained-request,
trust and clock value types, a sleep-inclusive clock sampler, the SQLite audit
journal, decision-consumption and command-submission replay tables, consumption outcomes, continuity
checkpoints, history-recovery intent encoding and storage-reconciliation selection.
The Mac authority uses the same implementations through the existing `RemozioCore`
public names. `CommandElevationPolicy` also shares the existing canonical explicit
account grants and disclosure requirement. Parsing a grant does not prove protected
installation or authorize execution; the Mac adapter retains protected loading,
native target resolution and capture validation.

On Linux, `LinuxOwnAccountTargetResolver` resolves only the authenticated caller's
own non-root account through NSS. `LinuxCurrentCommandElevationPolicy` requires
explicit fresh policy-loading and retained-caller credential-reading closures.
Every operation reloads grants; final validation compares all captured UID/GID
roles and groups and resolves the target again. Neither closure establishes
protected provenance or caller identity. The service's UID, a capture's claims
and an unvalidated numeric PID cannot substitute for an authenticated caller.
Authority serialization, monitor binding and the final stopped handoff remain
the owner's responsibility. These helpers enable no production Linux admission.

Verification checks the exact request, current enrollment, capabilities, permitted
action, signing key and monotonic deadline. A `VerifiedDecision` is verification
evidence only. The authority must still revalidate and consume the decision under
its journal lock before considering dispatch.

`SleepInclusiveClock` reads `mach_continuous_time` on macOS and `CLOCK_BOOTTIME`
on Linux. It floors elapsed time to integer milliseconds and throws on unavailable
clock reads, invalid samples or overflow; it never substitutes another clock.
The Mac `AuthorityClock` wrapper retains its existing epoch ownership.
`LinuxAuthorityClock` creates a fresh authority epoch on each construction and
preserves it across copies. Share one instance across an authority's request
owners, and replace it after restart. Its epoch is not a boot identifier and must
not be restored from persisted requests.

The audit tables retain their schema, bounded reads, writer ownership and explicit
transaction requirements. They borrow an existing SQLite connection. Its owner
remains responsible for protected storage, connection lifetime, serialized access,
durability configuration, recovery and committing audit and consumption together.
An audit write or writer handle grants no execution authority.

`ConsumptionJournalTables` shares the Mac consumption and outcome schemas, record
encoding and lifecycle checks. Reads require an explicit transaction; writes require
an existing write transaction. Consumption and outcome mutations each use a savepoint
with the audit append, so catching an error cannot commit half of that operation.
The audit tables must belong to the exact same connection and account scope.
Receipts, outcomes and bounded page cursors contain historical evidence only.

The owner must load current enrollment and policy, validate the retained request and
sample authority time under its serialization boundary. Supplied trust snapshots and
clock values do not prove those checks happened. A successful table call still needs
the owner's durable outer commit and checkpoint coordination before admission can
advance. The Mac adapter retains its enrollment lookup, revision checks, transaction
failure and retirement behavior, SQLite configuration and protected-store recovery.

`CommandSubmissionReplayTables` shares the existing permanent submission-ID and
nonce reservations. It stores the supplied scope, caller binding and capture digest;
those values do not authenticate a caller or attest a capture. Reads require an
explicit transaction and reservations require a main-database write transaction.
Duplicate IDs or nonces fail before the per-account capacity check; capacity never
evicts old evidence. There is no expiry, replacement or deletion API.
The Mac owner retains policy prerequisites, schema-version migration, continuity
digests and checkpoint coordination. The shared table neither sets `user_version`
nor marks an outer transaction failed: its owner must roll back an admission batch
when any required operation fails. A reservation or absence observation grants no
admission, retry or execution authority.

Checkpoint and recovery APIs validate caller-supplied data only. They establish
neither provenance nor protected storage, and their results grant no admission,
replay or dispatch authority. The Mac adapter keeps lazy pending-first journal
reads and applies reconciliation inside its existing storage serialization
boundary. Its protected stores, commit coordination and startup gates remain
Mac-owned.

This package contains no protected database owner, caller monitor, TPM integration,
service installation or command execution. It introduces no Linux capture schema and changes no protocol bytes or production
authority policy.

The disposable [Linux command fixture](../../docs/experiments/linux-approval-command.md)
uses these consumption, outcome, replay and audit tables together around its fixed command.
Its connection owner and checkpoint adapter remain fixture-only; stored evidence never
recreates an old dispatch token. This does not implement a protected Linux authority.

Run the shared host tests with Swift 6.2 or later. Linux also needs SQLite development
headers and library (`libsqlite3-dev` on Ubuntu), discoverable through `pkg-config`.
macOS uses the SDK's SQLite module.

```sh
swift test --package-path host/shared-core --force-resolved-versions
```

The tests use disposable software keys through CryptoKit on macOS and Swift
Crypto on Linux, and temporary SQLite databases. They cover table transaction,
rollback, reopen and bounded-read behavior. Consumption tests also cover approval
and decline winners, competing write connections, replay, expiry, exact audit
connection/scope, caught write failures and terminal unknown outcomes across reopen.
Replay-table tests cover both identifier collisions across reopen, scope isolation,
capacity, competing connections, outer rollback, malformed rows, storage errors and
compatibility with the existing Mac table layout. Existing Mac tests retain replay
migration, failed-transaction retirement and checkpoint integration coverage.
Portable recovery tests cover data validation and selection. These results do not establish hardware custody, a
protected Linux installation or a complete host approval flow. Mac tests retain
audit signing integration with the shared table types and the existing store
transaction, reopen and storage-failure coverage. Clock tests cover integer
conversion, failure handling, live kernel samples and rejection of a replaced
authority epoch. They do not establish physical suspend/resume, reboot recovery
or a protected service's time-namespace policy.
