# Retain and publish explicit Gateway settings changes

A revision binds the selected policy and timings to the original activation and exact previous revision.
The machine store permits one pending successor per account.
The original journal, credentials, service identities, foreground startup files and pairing stay unchanged.

```mermaid
flowchart LR
    A[Completed activation] --> R[Retain exact successor]
    R --> Q[Verify native quiescence]
    Q --> P[Publish selected metadata]
    P --> C[Write final commit last]
    C --> O[Verify native consumer observations]
    O --> S[Complete current revision atomically]
```

The store records ordered progress. Those markers grant no runtime authority or current health claim.
The authorized owner must verify each external step independently.
Reads leave schema 10 unchanged. Explicit retention upgrades it to schema 11.
The table holds at most 64 accounts. Each revision has a 32768-byte limit.
Corrupt rows and uncertain commit replies make that store handle unavailable.
A new handle reads committed state without repeating an external action.

The publication plan lists previous and selected bytes for five fixed files.
The caller must hold its machine and release scopes and verify native quiescence before each operation.
All siblings must match their previous or selected bytes before publication starts.
Only the first revision file can be created without a predecessor.
A selected final commit requires every selected sibling to exist.
Replacement stages a new inode, validates its predecessor and exchanges them atomically.
It verifies the resulting inodes and synchronizes the directory.
Cleanup only removes the exact known staging inode. Unexpected displaced files remain for diagnosis.

Version 1 commit bytes and observation keys stay unchanged.
Version 2 binds the settings sequence, revision digest, Gateway configuration and original activation.
A service policy change also changes its observation key.
Both role loaders validate the selected revision, fixed paths, code pins and timings.
Signed declarations list exact readers and emitters for five retained record formats.
Setup is the sole emitter in this release. Root recovery emission needs its later capability declarations.
Debug and Release artifact checks compare declarations against compiled codec versions.

Focused controls cover stale predecessors, competing revisions, lost replies, interrupted files, symlinks and quiescence loss.
Public validation evidence records the exact promoted source and required native and typed ATC gates.
Prototype results do not replace those gates.

Native coordination, restart recovery and the authenticated app action follow separately.
Ordinary Root installation still rejects a changed commit identity.
No app action exposes these internal helpers yet.
No installed services, production credentials, physical devices or frozen recovery artifacts are used for these checks.
