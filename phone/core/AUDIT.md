# Audit page receipt

`AuditPageReceiver` limits and tracks one-use history queries for one enrolled Mac/account.
Construct it with trusted enrollment identities and the authority public key.
The enrollment owner must close the receiver when enrollment is revoked or the authority key changes.

Begin a query with an authenticated journal epoch, its immutable creation generation, and the exclusive sequence cursor. These values must come from trusted history state. Do not derive them from the page being checked. History status can authenticate the descriptor under the current trusted authority key. Authority migration and cache conflict checks remain separate work.

The receiver generates a fresh 32-byte nonce and retains each query by object identity.
Use the query fields in the authenticated history request.
The caller supplies a query lifetime and maximum pending count to limit resource use.
Those limits do not select history retention settings.

The elapsed clock must include sleep and use a new epoch whenever its origin changes. An expired query, a changed clock epoch, or observed clock regression invalidates the query permanently. Beginning another query releases expired slots. The receiver rechecks the clock after signature and schema validation.

Receipt checks the audit signature, batch schema, enrolled Mac/account, epoch, creation generation, cursor and query nonce. Failed signatures and bindings do not consume a live query. Successful receipt consumes it exactly once under the same lock. Cancellation and enrollment closure invalidate pending handles. Concurrent responses cannot both succeed.

`ReceivedAuditPage` retains immutable copies of the canonical bytes, signature and local receipt instant. It does not establish global freshness or update a cache. The cache must still compare overlapping records, generations and boundaries, preserve conflicting evidence, and reconcile epochs. A last-sync label must follow successful cache reconciliation, not signature verification alone.

The receiver does not authenticate a transport or grant history access on the Mac. Revoked-phone checks on the server, durable encrypted caching, durable epoch reconciliation, retention policy and the history UI remain pending. No history operation can authorize an approval.

Tests use disposable software keys and an injected elapsed clock. They cover altered bindings, wrong keys, domain substitution, replay, deadline boundaries, clock changes, validation delay, cancellation, closure, capacity, immutable evidence and concurrent receipt. No phone or live service is required.

## Discovery and reconciliation queries

`beginHistory(null, null)` asks for the current epoch. Supplying both an epoch and a cursor asks about retained phone history. `receiveHistory` verifies the separate history-status purpose and all pending-query bindings. It shares the page-query capacity, cancellation, closure and elapsed-time checks.

`ReceivedAuditHistory` preserves the signed response. Its current descriptor is authenticated under the pinned authority key, but it cannot replace conflicting cached evidence. Compare descriptors and prior boundaries with the cache before adopting the result. A current descriptor does not prove an uninterrupted chain through unavailable epochs.

An unavailable epoch or an ahead-of-head cursor returns explicit reconciliation data. Preserve the old cursor and evidence. A new page query must explicitly name the selected epoch and its retained boundary. Receipt never rewrites a cursor or starts an approval.

## Evidence store

`AuditEvidenceStore` holds bounded metadata and signed proofs for one trusted Mac/account/key. It re-verifies each imported proof under its own pinned key and fixed purpose, including imports from encrypted offline storage. Import grants no freshness and does not advance a last-sync timestamp.

Pages merge by epoch and sequence. Exact records deduplicate. A changed record, reused event ID, changed generation or descriptor, conflicting prior digest, or epoch cycle quarantines the whole incoming update. Its signed proof remains available, while accepted records stay unchanged. A later consumer must show conflicts rather than presenting the first accepted version as resolved truth.

Prior digests are checked when either the descriptor or its referenced record arrives. Missing prior records remain unknown. A verified prior boundary does not prove that no later records existed. Old and new epochs retain separate records and gaps.

Snapshots show missing sequence intervals, split at the highest observed retention boundary. A delayed lower-head response never lowers the known head or deletes records. Retention reports do not authorize pruning cached history. Explicit unavailable/cursor-ahead responses remain in the signed proofs for reconciliation; arrival order alone is not proof of rollback.

All configured capacities are hard resource bounds. At capacity, ingestion fails atomically and preserves prior evidence. The caller must surface that failure and stop ingestion until storage is available. No record is evicted. Duplicate proofs still verify their signatures before deduplication. Re-signing the same canonical payload does not create another proof.

Snapshots and proof bytes are immutable. The store does not select a globally current epoch, order different Macs by wall clock, persist plaintext, authorize actions or implement retention policy. The encrypted Android adapter is described below; history UI remains pending. A future sync coordinator must choose current-epoch and last-sync state after reconciliation.

## Encrypted persistence

`EncryptedAuditCache` serializes signed proofs in their original acceptance order and encrypts the archive with AES-256-GCM when supplied the Android adapter's key. The envelope has an eight-byte `RMZAUD01` header, a 12-byte provider-generated IV, and ciphertext with a 128-bit tag. Associated data binds the cache domain, schema, Mac/account and pinned authority key. Decryption under another enrollment fails.

The plaintext archive is canonical CBOR: schema 1 at key 0 and an ordered proof array at key 1. Each proof has kind 1 (page) or 2 (history status) at key 0, canonical signed bytes at key 1 and the raw signature at key 2. Unknown fields, schemas and kinds fail. Restoring re-verifies every signature into a new bounded evidence store before publishing it. Conflicting proofs remain in their original order, so quarantine decisions survive reload. Duplicate archive entries fail instead of hiding corrupt structure.

Writes build a candidate store, encode and encrypt it, replace ciphertext, then publish the candidate in memory. A failed write blocks further writes until the cache is reopened and verified. This handles uncertain commit outcomes without overwriting newly persisted evidence from an older in-memory snapshot. Encoding or encryption failures before storage leave the current store unchanged.

`AuditCiphertextStorage` accepts ciphertext only. It must enforce exclusive access, bounded reads and atomic replacement. No load error resets a cache. The storage owner closes a failed open; it must preserve the file for diagnosis or recovery. An encrypted file alone cannot prove that no older complete snapshot was restored.

The Android adapter stores files in `noBackupFilesDir`, with one lifetime OS file lock per Mac/account cache. It uses `AtomicFile`, checks the write and reads back ciphertext before reporting success. Operations block and must run off the main thread. The adapter never creates an approval key or changes enrollment.

Each cache has its own Android Keystore AES-256 key. Generation prefers StrongBox and falls back to a hardware TEE only when StrongBox is unavailable. Existing keys must pass the expected policy checks; they are never silently replaced. A missing key with an existing archive fails without resetting the archive. Reading history requires no extra biometric prompt. The key also permits background metadata sync after the Android user has unlocked credential-encrypted storage.

Host tests use disposable software AES keys only. They test randomized encryption, enrollment binding, tampering, invalid archives, conflict restoration, capacity and failures before or after replacement. The Android adapter is build-checked; hardware key behavior, file recovery and device lifecycle tests remain deferred. History UI, enrollment ownership and the sync coordinator still need integration.

Platform references: [Keystore AES example](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec), [key policy](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder), [AtomicFile ownership and writes](https://developer.android.com/reference/android/util/AtomicFile), and [private backup-excluded storage](https://developer.android.com/reference/android/content/ContextWrapper).

## History presentation model

`AuditHistory.list` returns separate Mac/account groups. Snapshot scope comes from the evidence store, including when the store is empty. Duplicate scopes are rejected instead of merging possibly different owners. Device names remain editable UI labels; this model uses stable identities.

Mac, category and outcome filters select records. They never remove gaps, epoch boundaries, conflict warnings or retained reconciliation reports. Null means all values; an empty filter set means none. Each epoch reports its total retained record count separately from the filtered list.

Within an epoch, the list uses descending sequence order. A request timeline uses ascending sequence order and ignores list filters. Timestamps, missing timestamps and unknown outcomes remain unchanged. No method infers a final outcome or offers an action.

Unambiguous signed predecessor links form chains. Each list chain runs newest first; each timeline chain runs oldest first. Missing predecessors and unknown descriptors remain explicit. Forks split into separate chains because sibling chronology is unknown. Mac/account groups and independent chains use stable identity order only; the UI must not present that order as chronology. A linked prior boundary does not prove that later records were never lost.

Conflicting proofs remain quarantined. The first accepted record is retained evidence, not a resolution of the conflict. Every group carries conflict classes and the number of conflicting proofs. Typed signed history reports retain their own conflict classes, including unavailable and cursor-ahead responses. Their arrival order does not select the current epoch or establish a current sync result.

All output collections are immutable. This model contains retained metadata only. UI navigation, enrollment labels, online state, last-sync state and the sync coordinator remain separate integration work.

## Serialized synchronization

`AuditSyncSession` takes exclusive ownership of an open encrypted cache. The caller must not append to or close that cache separately. Calls perform blocking verification and storage work off the main thread. Its read-only state flow retains history even after the session closes.

The enrollment transport calls `start`, obtains one query with `next`, then returns its signed response through `accept`. Only the current query object can advance the session. A late response or transport error cannot cancel a replacement query. The session verifies the response, commits encrypted evidence, then advances its plan. A storage failure requires closing the session and reopening the cache; an uncertain write never continues from stale memory.

```mermaid
stateDiagram-v2
    IDLE --> SYNCING: start and discover
    SYNCING --> SYNCING: verify, persist, advance
    SYNCING --> PAUSED: response budget exhausted
    PAUSED --> SYNCING: resume same plan
    SYNCING --> COMPLETE: observed bounds reached
    SYNCING --> FAILED: response, transport, conflict or storage error
    SYNCING --> CANCELLED: cancel
    PAUSED --> CANCELLED: cancel
    FAILED --> SYNCING: start after non-storage failure
    COMPLETE --> SYNCING: start fresh discovery
    CANCELLED --> SYNCING: start fresh discovery
```

Discovery prioritizes the reported current epoch. Cached old epochs receive explicit cursor checks. Ahead or unavailable old history remains visible while the new epoch can progress. A cached cursor above the reported current head also gets an explicit reconciliation query. Existing records never disappear because a restored Mac reports a lower head.

Each epoch fetch stops at the head observed when that epoch entered the round. Later growth remains a visible gap for the next round. The positive response budget pauses work without discarding the plan; `resume` continues it with fresh query nonces. Pagination fills the earliest available hole and skips already cached records. A head that falls during its own page fetch fails the round, preserving evidence for fresh discovery and reconciliation.

`COMPLETE` means this round reached its observed boundaries. It does not mean history has no gaps, outcomes are known, or the Mac is still online. Retention gaps, quarantined conflicts and signed history reports remain in the snapshot. Last-successful-sync advances only after the whole plan finishes. Failed or cancelled rounds retain its old value. Epoch observations carry their own receipt times; later page receipts do not refresh them. Reopening a cache restores evidence, never current-epoch or last-sync claims.

The caller must report transport failures, cancel abandoned work, and close the session on revocation or authority replacement. The channel still has to authenticate the phone, enforce revocation and negotiate protocol compatibility. This session supplies no channel, push service or enrollment. Those integrations and device lifecycle tests remain pending.
