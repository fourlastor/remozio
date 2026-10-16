# Authority token proofs and control outbox

The root journal stores token candidates, desired token choices, consumed proofs, and signed gateway controls.
The gateway owns provider delivery.
The root decides whether an authenticated phone proof permits mapping activation.

```mermaid
flowchart LR
    Phone[Authenticated phone token update] --> Candidate[Generate candidate and fresh challenge]
    Candidate --> CTx[Commit candidate, desired token, counter and signed outbox]
    CTx --> Gateway[Gateway sends opaque provider challenge]
    Gateway --> Proof[Phone returns proof through authenticated channel]
    Proof --> Check[Recheck peer, enrollment, full binding and original deadlines]
    Check --> ATx[Commit proof consumption, counter and signed activation outbox]
    ATx --> Apply[Gateway applies matching unexpired activation]
    Restart[Root restart or expired candidate] --> Renew[Read current desired token and create fresh candidate]
    Renew --> Candidate
```

## Transaction boundary

Enable these APIs with `GatewayAuthorityPolicy` when opening `JournalDatabase`.
The policy fixes encoding limits, control capacity, candidate lifetime, and the current clock epoch.
An explicit `configureGatewayAuthority` call pins one registration to the journal's Mac and account.
It cannot replace an existing registration or initialize over orphaned gateway state.

`prepareGatewayCandidate` checks the separately authenticated phone identity and epoch against current durable enrollment.
Its public API requires the expected enrollment trust revision and reads the phone tag from the protected journal.
It generates a candidate ID, operation ID, challenge, and next control revision. It stores the token outside audit history.
The host supplies a local typed signer. The journal verifies its signature with the pinned root key before storing the control.
The candidate, desired-token pointer, signed outbox entry, and counter share the journal transaction.
A failed transaction publishes nothing. The host must never send a value captured inside the callback before commit.

`consumeGatewayProof` parses the bounded proof and compares its complete binding with the retained candidate.
The current phone epoch and tag, both original deadlines, current process, and latest desired token must still match.
It marks the candidate consumed and inserts one signed activation in the same transaction as the counter advance.
A unique index also prevents a second activation for that candidate. Swallowing a mutation error cannot commit the surrounding transaction.
The typed signing callbacks are root-local capabilities, not generic signing RPCs.

## Retry and recovery

`pendingGatewayControl` rechecks current durable enrollment, its trust revision, and control eligibility before returning the original signed envelope.
A candidate stops being eligible after consumption. A superseded token choice cannot be published or proved as current.
Provider acceptance alone never consumes a proof, activates a mapping, or changes enrollment.

Each journal owner uses a fresh run ID. Old candidates cannot accept proofs or publish controls after reopening, even with a reused clock epoch.
Retained desired tokens survive. `renewDesiredGatewayCandidate` reads only the latest desired token under current trusted enrollment.
It generates a fresh candidate, challenge, operation, revision, and deadline. It does not refresh an arbitrary old outbox entry.
Routine recovery needs no new phone biometric or operator prompt. The public renewal path rechecks the stored active epoch and trust revision. The service scheduler must call this path after establishing local continuity.

Historical signatures, token digests, counters, desired pointers, and proof-consumption links are checked when read.
Known inconsistency or a clock regression retires the journal owner. These checks do not detect restoration of a complete, internally consistent backup.
Protected local checkpoint recovery remains required before the root publishes controls or accepts phone operations. The [accepted whole-Mac restore limit](../../docs/design-decisions.md#whole-mac-backup-rollback) removes the independent witness prerequisite for that threat.

## Durable phone removal

`revokeGatewayEnrollment` signs one phone epoch removal with the pinned root key.
The signed row is both a permanent local revocation and a gateway delivery control.
Its insertion, matching desired-token removal, and shared counter advance commit together.
The host can append the enrollment audit event in that same transaction.
No result may be published before the transaction commits and continuity is established.

```mermaid
flowchart LR
    Remove[Authorized phone removal] --> Commit[Commit signed revocation, desired-token removal, counter and audit]
    Commit --> Reject[Reject late proofs and token renewal for that epoch]
    Commit --> Deliver[Send signed revocation to gateway]
    Deliver --> Clear[Gateway clears matching mapping and pending candidates]
    Restart[Restart or delivery expiry] --> Retained[Retained epoch remains revoked]
    Retained --> Refresh[Sign a fresh removal control after continuity checks]
    Refresh --> Deliver
```

Candidate creation, proof consumption, renewal, and pending candidate delivery consult the retained revocation.
A stale caller snapshot that still says “active” cannot bypass it.
Removal targets the exact phone epoch. It preserves other phones and a newly enrolled epoch of the same phone.
The protected host must still establish that new enrollment through the separate administrator flow.
This API does not enroll devices or replace approval trust with gateway state.

`gatewayEnrollmentRevoked` returns historical local state, including after delivery expiry and restart.
`pendingGatewayRevocation` requires an active gateway registration. It allows an inactive enrollment so removal can still reach the gateway.
An inactive gateway does not erase the local revocation or prevent recording a removal.
It returns only the latest control for that epoch, within its original wall and process deadlines.
Old controls cannot be sent after reopening. Repeating the removal creates a fresh signed control without restoring any authority.
The existing candidate lifetime also bounds each removal control's delivery window; the local revocation has no expiry.
Recovery of this retained removal needs no new biometric prompt. The initial removal still requires the agreed authorization.

Candidate, activation, and revocation rows share the control counter and storage limit.
A capacity or storage error rolls back the whole removal. The host must report failure, never a completed removal.
No pruning or acknowledgment compaction exists yet. A production host must handle this limit before enrollment removal is exposed.
Signatures and indexed metadata are checked when read. Detected corruption retires the journal owner.
These rows cannot detect a complete, internally consistent backup rollback. Whole-Mac backup restoration is outside the accepted guarantee; ordinary crash recovery, retained-state validation and replay prevention remain required.

## Schema and service integration

Root journal schema 12 retains gateway, [approval enrollment](enrollment-journal.md), and [routing state](routing-journal.md). It preserves historical gateway acknowledgments, recovered delivery receipts, and recovered revocations, and retains unknown trust restrictions. Schema 12 adds pairing commit transcripts.
Known migrations from versions 1 through 11 require the explicit source version. They preserve existing audit and consumption state.
A migration does not derive enrollment or gateway authority from audit records. Failed migration rolls back its table and version changes.
The separate gateway database remains at schema 3.

The service host must authenticate phone channels and administrator setup, and own protected gateway registration activity.
The public token APIs read phone enrollment from the journal inside their transaction. Their overloads accepting caller-supplied phone trust are internal.
It must provide the non-exportable root signer and establish continuity before publishing any signed control.
Neither a constructor nor a supplied phone ID proves authentication. These methods are not exposed as network endpoints.
The host may append metadata-only audit events in the same journal transaction. Tokens and challenges must never enter audit records.

The [enrollment journal](enrollment-journal.md) now owns approval keys and combines enrollment removal with the gateway outbox.
Authenticated enrollment setup, acknowledgment service wiring, counter reconciliation, and scheduling remain integration work.
The retained row limit is a storage bound; no history pruning or whole-backup recovery is implemented here.
Do not report registration as healthy until the actual gateway and phone flow provides the required evidence.

## Validation

Tests use protected normal-user SQLite fixtures and ephemeral signing keys. They perform no privileged installation or phone interaction.
They exercise atomic writes, injected failures, superseded proofs, expiry, restart renewal, signature checks, row limits, migration, and corrupted state.
A local integration test passes the stored candidate, activation, and revocation through the real gateway database and its provider-probe lifecycle.
Removal tests cover late proofs, stale active trust, old epochs, restart, expiry, audit atomicity, failed migrations, and storage faults.
The phone channel is a fixture in that test. It does not establish that authenticated transport or real FCM delivery works.

Public enrollment-bound token tests cover stored tags, exact epochs, removal, re-enrollment, inactive registration, wrong scope, restart renewal, and swallowed failures.

## Retained gateway acknowledgments

The root passes a `VerifiedGatewayHead` from its protected [query owner](../../docs/experiments/gateway-head-replies.md) to `acknowledgeGatewayHead`.
The transaction checks the pinned registration and compares the reported control with its retained local operation, revision, kind, and canonical body.
Both signatures were already verified by the query owner. Equivalent valid ECDSA signatures need not have identical bytes.
Only a known control can become the highest retained acknowledgment. The row contains its revision and operation ID, never a token.

| Result | Stored acknowledgment | Host meaning |
| --- | --- | --- |
| `recorded` | Advances to the known reported control | Historical acknowledgment committed |
| `alreadyRecorded` | Unchanged | Idempotent repeat |
| `olderThanRecorded` | Unchanged | An older known response cannot lower the recorded revision |
| `missingLocalHistory` | Unchanged | Reconcile missing history before enabling affected authority or publishing mappings |
| `conflictingLocalHistory` | Unchanged | Reconcile the conflicting signed control under the trust recovery rules |

The root checks receipt consistency before classifying a reply as older. A conflicting old receipt is not treated as harmless reordering.
The API does not infer why a known older head arrived. It can reflect reordered replies or a gateway recovery problem.
The stored acknowledgment is historical. It does not assert current connectivity, current phone delivery, or a rollback-free gateway.

An acknowledgment never changes the authority counter, desired token, enrollment, revocation, or outbox.
Unknown signed revocations require the host's trust recovery path; this API neither imports them nor permits ignoring them.
The host must reconcile that result before admitting affected phone operations. The acknowledgment API alone does not enforce that service gate.
Counter drift still needs sufficient signed history. The latest receipt alone cannot prove that an omitted intermediate control was delivery-only.
A missing-history result therefore does not implement automatic counter repair or require a new phone prompt.

The row survives restart. Schema-seven migration starts with no acknowledgment; it does not infer one from stored controls.
Storage failure rolls back the change. Corrupt retained acknowledgment references retire the database owner.
The host can append metadata-only audit events in the same transaction; service-level audit policy remains integration work.

Seven additional tests connect real root and gateway databases through fresh signed replies.
They cover all receipt kinds, replay and reordering, missing delivery and revocation history, conflicting controls, scope isolation, write failures, corruption, reopen, and migration.

See [gateway history recovery](gateway-history-recovery.md) for transactional counter repair and its trust boundary.

See [recovered gateway revocations](recovered-gateway-revocations.md) for permanent restrictions and atomic system audit events.
