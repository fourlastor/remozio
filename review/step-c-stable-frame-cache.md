# Step C: cutting repeated stable-frame reads in PreparationIntentStore

Base: upstream main `86a601ba` (FETCH_HEAD). Paths are under `macos/core/Sources/RemozioCore/` unless noted. `PIS` = `PreparationIntentStore.swift`.

## Recommendation

Add a frame cache that lives for exactly one read transaction on one connection (option a). Let it hit only when the transaction is a read transaction (`write: false`), the connection is still inside it (`sqlite3_get_autocommit(db) == 0`), and `sqlite3_total_changes64(db)` has not moved since the frame was stored. Write transactions never use it. Clear it at every `BEGIN`, `COMMIT`, `ROLLBACK` and `shutdown()`. Add a prepared-statement cache (option c1) as a second, independent PR only if the profile still shows `statement` high after that.

Expected effect: in the hot paths a read transaction loads the same frame 6 to 14 times (see section 2). With the cache it loads it once. That removes about 85-93% of frame work. With frames at 55-75% of CPU in the slow tests, those tests should lose roughly half to two thirds of their CPU time. No cross-transaction or cross-connection read is removed, so every check that is meant to see a concurrent change keeps seeing it.

## 1. What `loadStableMachineUpdateFrame` reads

`PIS:5712-5762`. Everything it reads is SQLite state on this store's own connection, plus pure decoding and validation.

- `observeStoreRead?(.frame)` (5716). A test-only hook.
- `identity(macID)` (5717, `PIS:7252`). Reads `PRAGMA user_version`, `sqlite_master`, the identity row and the application id.
- `PRAGMA user_version` again (5718). Pure format checks against the candidate's manifest follow (`requireFormats` / `requireReaderFormats`, 5726-5731).
- Rows: inventory, the update candidate, the activation record, admission registration, all preparation intents (`loadAll`), one `COUNT(*)` per `completionRetirementTables` entry, the stable release seal (`loadStableReleaseRecord`), and the installed-release rows. The rows are read twice: once by `requireFinishingActivation` (`PIS:3647`) and once at 5743.
- `installedCurrentSourceProjection` (`PIS:3570`). Reads `user_version` and the inventory once more, and computes digests of three historical singleton tables plus `machineEpochSourceDigest` (`PIS:6977`), which reads every source table.
- Retained policy, completion, promotion and ready intents. From schema 29 it also reads the maintenance windows.
- Decoding goes through `epochCaches` (#949, `PIS:29`, `PIS:5744`) and the canonical-bytes caches (#944).

It does not read the filesystem. It does not call `lease.validate()`, `requireUpdateAdmissionDirectory` (`PIS:2294`, which does the fstat/inode check), the clock, `getpid`, or any native ownership check. Those checks run in `transaction()` (`PIS:7365`, `7452`, `7465`) and in the authorization `capture` methods, both outside the frame. Every `statement` call runs `sqlite3_prepare_v2` and then `sqlite3_finalize` (`PIS:7522-7529`), with no statement reuse. That is the 24% `statement` share.

## 2. Callers and counts

Every caller runs inside a `transaction(...)`. The loaders nest, and each level re-reads its inner level and calls `requireSame`.

| loader | frames per call |
|---|---|
| `loadStableRuntimeSource` (`PIS:3703`, `3719`) | 2 |
| `loadStableRuntimePreparationSnapshot` (`PIS:5014-5023`): source + 1 | 3 |
| `loadStableServiceAccountSnapshot` (`PIS:3726`): source | 2 |
| `loadStableRuntimeActivationSnapshot` (`PIS:5032`): 2 x runtime | 6 |
| `loadRetainedSetupActivationSnapshot` (`PIS:5108-5123`): 2 x runtime | 6 |
| `loadRetainedSetupCompletionSnapshot` (`PIS:5131-5146`): 2 x activation + 2 | 14 |
| `loadRetainedSetupPromotionSnapshot` (`PIS:5154-5169`): 2 x completion + 2 | 30 |

The existing tests confirm this. `RetainedSetupInitialRuntimeTests.swift:165` and `RetainedSetupRuntimeSequenceTests.swift:399` both assert `counts[.frame] == 6`.

Each public entry point opens one read transaction: `stableServiceAccountSnapshot` (`PIS:3723`), `stableRuntimePreparationSnapshot` (`PIS:5007`), `retainedSetupCompletionSnapshot` (`PIS:5126`), `retainedSetupPromotionSnapshot` (`PIS:5149`), and the other direct callers at `PIS:2388`, `3354`, `3503`, `5464`, `5572`, `5609`, `5654`, `5920`, `5965`, `6014`, `6092`, `6129`, `6193` and `6231`. All of them are `write: false`. The frames inside one entry point therefore share one transaction.

The verify callbacks are a different matter. They do not reuse the caller's transaction:

- `MachineUpdateRetainedSetupPromotionNativeContext.readFresh` (`MachineUpdateRetainedSetupPromotionNativeContext.swift:240-252`) opens a new `PreparationIntentStore` connection for each verify. On that connection it runs `retainedSetupCompletionSnapshot` twice in two separate transactions, with `RuntimeStableCompatibilityCapture.capture` between them. That is about 28 frames or more per verify, spread over at least 2 transactions and 1 new connection.
- `withOwnedContext` (`same file:149-190`) calls `frame()` around every external read. `withPinnedPair.verify` (`MachineUpdateRetainedSetupPromotionSourceValidation.swift:28-34`), `validateRuntimeFiles` (`MachineUpdateRetainedSetupActivationSnapshot.swift:179-200`) and `RuntimePublishedArtifactValidation.validate` call `verifyCurrent` before and after every file read. So the number of transactions grows with the number of files, and each verify transaction itself repeats the frame 14 times.
- The writer path (`PIS:5310-5360`) verifies with `authorization.capture` through `RetainedSetupPromotionFrameLoan`. That runs in the writer's own transaction, which is a read transaction for `before` and a write transaction later.
- The second hot chain: `CompletionPublicationScope.read` (`PIS:6317`) runs `verifyCurrent`, which is `completionPublicationSnapshot` (`PIS:6379-6383`). It runs inside the single read transaction that `withCurrentMachineUpdateCompletionPublication` opens (`PIS:6342-6345`), and each call repeats `loadCompletionRecoverySnapshot` (`PIS:6710`), `requireCurrentConfigurationEpoch` (`PIS:2834`) and `machineEpochSourceDigest`. It mixes DB reads with native checks: `restart.validate()`, `requireUpdateAdmissionDirectory` and `restart.validateMachineBoundary`. `MachineUpdateCompletionPublicationFiles.requireEntry` (`MachineUpdateCompletionPublicationFiles.swift:72-86`) calls it before and after each file read.

## 3. Can a transaction-scoped cache be correct?

**Who writes the database.** The store opens with `journal_mode=DELETE` (`PIS:90`, checked at `PIS:98`). Other `PreparationIntentStore` connections in this process write it: `readFresh`, `openMachine`, the paired writers and test fixtures (`f.mutate`). Other processes may write it too (setup controller, app). In rollback-journal mode a deferred `BEGIN` takes a SHARED lock on its first read and keeps it until `COMMIT`/`ROLLBACK`. A different connection cannot commit while that lock is held: it needs EXCLUSIVE, so it waits out `busy_timeout(1000)` (`PIS:78`) and fails. Within one read transaction, the repeated frame reads therefore cannot see another connection's commit. They are self-consistency checks on the code path, not race detectors against other writers. The one thing that can change the data inside the transaction is a write on this same connection. That happens in write transactions, where the frame is re-read after the connection's own `INSERT`/`UPDATE`. It could also happen through a deferred-transaction upgrade if anything ran a write statement inside a `write: false` transaction.

**Checks that deliberately observe a racing write.** These are the main risk. Each must still do real reads:

1. `readFresh` (`MachineUpdateRetainedSetupPromotionNativeContext.swift:240`). It opens a new connection and runs two transactions for each verify. This is the check that sees a racing write to the machine store between file reads. It stays correct only if the cache never outlives one transaction and never crosses connections.
2. The repeated `retainedSetupCompletionSnapshot(...).requireSame` inside `readFresh` (line 249) comes after `RuntimeStableCompatibilityCapture.capture`. The two calls are separate transactions, so a write committed between them must be caught. A cache keyed on a store-lifetime identity (for example `data_version` alone, read outside a transaction) would be dangerous here. A per-transaction cache cleared at `COMMIT` is not.
3. `StableServiceAccountAuthorization.capture` (`PIS:3734-3746`) and the other authorization `capture`s run at the start of the body, after it, and again just before `COMMIT` in write transactions (`PIS:7432-7462`). They must observe the connection's own writes in the body. A cache must therefore never hit in a write transaction.
4. `CompletionPublicationScope.read` (`PIS:6317`). Its DB part cannot change inside the read transaction, but its native parts (`restart.validate`, the directory inode check in `requireUpdateAdmissionDirectory`, `validateMachineBoundary`) can, and they are the reason it runs before and after each file. Those calls must stay uncached.
5. `withOwnedContext.frame()` calls `controls.validateCustody()` (placement and code identity, fstat-based) before and after each read. That is native state and stays uncached.
6. The `requireSame` re-reads within one transaction (for example `PIS:5118`, `5140`, `5163`, `3719`, `5021`). They guard against a logic error in which one loader mutates through the connection. After the change, the second read returns the same value, which is correct because the connection made no change. The `total_changes` guard keeps this so if a write ever does happen.

**Is `PRAGMA data_version` the right key?** Not on its own. It changes only when another connection commits, and it does not change for this connection's own writes. Inside a held read transaction it is constant anyway. The correct key is: the store's own transaction serial, plus `sqlite3_total_changes64(db)` (which catches this connection's writes), plus the exact candidate canonical bytes. `data_version` can be added cheaply as a belt-and-braces term.

## 4. Options

### (a) Frame cache scoped to one read transaction (recommended)

- **Mechanism.** A private `var frameCache: (serial: UInt64, changes: Int64, candidate: Data, frame: Frame)?` in `PreparationIntentStore`. `transaction()` increments `transactionSerial` and sets `frameCache = nil` right after `BEGIN` succeeds (`PIS:7367`). It sets `frameCache = nil` in a `defer` next to `active = false` (`PIS:7372`), which covers commit, rollback and throws. `shutdown()` (`PIS:7531`) clears it too. `loadStableMachineUpdateFrame` hits only if all of these hold: `active`, the current transaction is `!write` (store a `transactionWrites` flag), `sqlite3_get_autocommit(db) == 0`, `serial` matches, `total_changes64` matches, and the candidate key equals `release`'s canonical bytes (CanonicalBytesCache from #944). It never caches a throw.
- **Observer.** Still call `observeStoreRead?(.frame)` on a hit, so the existing count assertions keep their meaning. Add a new case, `.frameCacheHit`, for the new tests. Alternatively, update the two assertions from 6 to 1. Either is acceptable; keeping `.frame` on hits is the smaller diff.
- **Savings.** Frames per read transaction drop from 2, 3, 6, 14 or 30 to 1. Around 85-93% of frame CPU goes, which is about 47-70% of the profiled slow tests' CPU. `statement` (24%) falls by roughly the same proportion, because most statements come from frames.
- **Behaviour preserved.** Every transaction still does at least one complete frame read and validation. Every new connection reads afresh. Every native and filesystem check (`lease.validate`, `requireUpdateAdmissionDirectory`, authorization `capture`, custody checks) still runs on every call, because none of them is inside the frame.
- **Exact invalidation rule.** Invalidate on transaction begin, transaction end (commit, rollback or throw), `shutdown`, any change of `sqlite3_total_changes64`, any write transaction (no lookups and no stores), and any change of candidate bytes.
- **Remains uncached.** The non-frame loaders: `loadAccountPreparations`, `loadInitialization`, `loadServiceAccountPlan`, `loadRuntimePreparation`, the retained policy and activation rows, and the whole completion-publication chain (`loadCompletionRecoverySnapshot`, `requireCurrentConfigurationEpoch`, `machineEpochSourceDigest`). Also anything in write transactions.
- **Risks.**
  1. If the store ever moves to WAL, a read transaction still pins one snapshot, so the cache stays correct. A switch to autocommit reads (no `BEGIN`) would break the premise. The `get_autocommit == 0` guard turns that into a miss, not a wrong hit.
  2. A future write statement inside a `write: false` transaction. Covered by `total_changes64`.
  3. Shared mutable state in the returned frame. The frame is made of value types; confirm there are no class references in `MachineUpdateStableReleaseSnapshot` or the intent records.
  4. Re-entrancy: `transaction()` refuses nesting (`PIS:7357`), so one cache slot is enough.

### (a2) Extend the same cache to the completion-publication chain

`completionPublicationSnapshot`'s DB part (`loadCompletionRecoverySnapshot` minus `requireUpdateAdmissionDirectory`, plus `loadCompletionPublication` and the plan fingerprint) could get the same per-read-transaction memo. The native calls would have to be split out so that they still run every time. This needs more care, because `loadCompletionRecoverySnapshot` and `requireCurrentConfigurationEpoch` interleave `requireUpdateAdmissionDirectory` with DB reads (`PIS:6712`, `PIS:2836`). Do it as a follow-up after (a), with the native calls hoisted out explicitly and kept on every call.

### (b) Memoize only the pure part

Keep every SQL read and memoize the decoding and validation by exact bytes. #944 and #949 already cover the expensive archive decoding (`epochCaches`). What remains is the SQL work itself (prepare, step, blob copies), `machineEpochSourceDigest` hashing, and the row decoders. Expected savings are small, perhaps 10-20% of the frame cost, because `statement` alone is 24% and stays. This option has no correctness risk, but it does not address the hot spot.

### (c1) Prepared-statement cache

Replace prepare/finalize per call (`PIS:7522`) with a per-connection dictionary of `sqlite3_prepare_v3(..., SQLITE_PREPARE_PERSISTENT)` statements, using `sqlite3_reset` and `sqlite3_clear_bindings` on reuse, finalized in `shutdown`. Every read still runs. It saves most of the prepare part of the 24% `statement` share, which matters for the short-query fan-out in `identity` and the `COUNT(*)` loops. Risks: the cache must stay out of `exec` and DDL (schema changes make SQLite re-prepare automatically), and statements must be reset on throw paths. It composes with (a).

### (c2) Pass the frame down explicitly

Refactor the nested loaders to accept an already-loaded frame instead of re-reading it. The effect equals (a), but the "re-read and `requireSame`" structure disappears from the code, and reviewers would read that as removing checks. (a) keeps the code shape and makes the equivalence explicit in one place, so I prefer (a).

## 5. Test plan

**Must stay green.** Run all of these with `swift test --filter`:

- Frame counts: `RetainedSetupInitialRuntimeTests`, `RetainedSetupRuntimeSequenceTests`, `RetainedSetupInitialRuntimeEntryTests`, `RetainedSetupInitialRuntimeNativeTests`, `RetainedSetupInitialPublicationNativeTests`, `RetainedSetupInitialCompletionNativeTests`, `RetainedSetupRuntimeNativeAuthorityTests`, `SetupRetainedCallerBindingTests`, `AuthorityMaintenanceCommandReaderTests` (transaction re-entry), `RetainedSetupImportAcknowledgementTests`, `RetainedSetupImportAcknowledgementOwnerTests`.
- Stale-revision and writer tests: `MachineUpdateRetainedSetupPromotionWriterTests`, `MachineUpdateRetainedSetupPromotionWritePreparationTests`, `MachineUpdateRetainedSetupMaterialWriterTests`, `StableAccountStorageCompletionWriterTests`, `RetainedSetupPolicyPreparedWriterTests`, `RetainedSetupPolicyTransitionWriterTests`, `RetainedSetupPolicyFrameTests`, `StableRuntimePreparationValueTests`, `StableRuntimeImportTests`, `MachineUpdateStableRuntimeViewTests`, `MachineUpdateStableAccountPreparationTests`, `RuntimeStableCompatibilityTests`, `MachineUpdateActivationTests`, `RetainedSetupInitialPublicationTransitionTests`, `FrozenMaintenanceWindowReader1`.
- Then the full `./scripts/check-local.sh` on the Mac, because macos/core does not run on Linux.

**New tests** (one new class, for example `PreparationStoreFrameCacheTests`):

1. *Racing write between two verify reads is detected.* Take a retained completion snapshot. Run a `withOwnedContext` verify whose `readMaterial` control commits a change to a frame table (for example the retained completion intent row) through a second connection, between two `frame()` calls. Assert `staleRevision`. Repeat with the write between the two `retainedSetupCompletionSnapshot` calls inside `readFresh`, injected through the `lookupOwner` control used by `RuntimeStableCompatibilityCapture`. Run both with and without the cache to show the result is identical.
2. *Cache does not cross transactions.* Call `stableRuntimePreparationSnapshot`, commit a change through a second connection, and call it again on the same store. The second call must throw or return the new value. Assert one `.frame` miss per transaction.
3. *Cache does not hit in write transactions.* In a stable-service-account writer test, assert via `.frameCacheHit` that there are zero hits for the authorization `capture` calls, and that a change made by the body is caught by the post-body `capture`.
4. *Own-connection write in a read transaction invalidates.* A test-only seam runs a write statement inside `transaction(write: false)` between two frame loads. Assert a miss, and assert the change is seen.
5. *Candidate key.* Two different candidates in one transaction: both miss and produce the right format errors.
6. *Throw is not cached.* Corrupt a row so that the first load throws `corruptRecord`. The transaction marks the store unavailable, which is the existing behaviour. No hit may follow.
7. *Hit count.* `retainedSetupCompletionSnapshot` performs exactly 1 miss and 13 hits.
8. *Blocked concurrent writer.* With a read transaction open (inside `observeStoreRead(.readTransaction)`), a second connection's write gets `SQLITE_BUSY` and the read result is unchanged. This pins the SHARED-lock premise of the design, so a journal-mode change shows up as a test failure.
