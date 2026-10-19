# Retain service activity until asynchronous work settles

Gateway and Transport need scopes that their dedicated accounts can hold without opening the Root machine store.
Each role uses its own Root-owned group-readable lock file.
A reference binds the account, release, role and exact file identity.
Decoded metadata grants no lock, mutation permission or update authority.

```mermaid
flowchart LR
    S[Explicit scoped preparation] --> P[Provision exact role lock files]
    P --> R[Retain their validated identities]
    R --> H[Dedicated host acquires shared activity]
    H --> W[Authenticated work retains a child token]
    W --> J[Join asynchronous work]
    J --> C[Close the token]
    C --> U[Updater can attempt exclusive participation]
```

The barrier checks the dedicated UID and group, account identities and exact inode metadata.
Forked processes cannot reuse tokens. Closed tokens cannot validate.
Root can attempt an exclusive role lock; a service cannot authorize that operation through this helper.
The lock only represents participation. It does not prove every installed role participates or permit an update.

Native companion endpoints now retain an owned activity interface through disconnected asynchronous work.
Existing Root activity tokens implement that interface without changing their behavior.
The listener joins retired endpoints before it closes the host scope.

Runtime reference and private preparation codecs support versions 1 and 2.
Version 1 bytes stay unchanged when service activity is absent.
Version 2 retains the exact activity references.
Private material remains scoped to Root and Setup readers; Setup is its only emitter.
Signed declarations and actual bundle checks describe these nested codec versions explicitly.

Preparation only writes activity metadata after explicit opt-in. Ordinary reads and legacy preparation do not create these files.
Activity metadata cannot select jobs yet. Native host selection stays unavailable until both consumers retain their scopes.

Owned fixtures cover late token release, cancellation, changed file identities, provisioning and retained metadata.
An independent owned process tests the shared and exclusive lock boundary.
These controls do not prove production dedicated accounts, Developer ID admission or complete updater participation.
No installed services, production secrets, physical devices or frozen recovery artifacts are used for these checks.
