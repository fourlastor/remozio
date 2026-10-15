# Mac account preparation

The installed app can prepare command approval storage for its authenticated local Mac account.
The user selects target UIDs and accepts the separate Remozio command policy before administrator authorization.
This policy does not inherit sudoers restrictions.

```mermaid
sequenceDiagram
    participant App as Installed Mac app
    participant Setup as Root setup helper
    participant Machine as Protected machine store
    participant Key as Hardware key provider
    participant Stores as Journal and continuity
    App->>Setup: Enrollment hello, version 2
    Setup-->>App: Pinned Root peer, version 2
    App->>Setup: Read this caller's retained progress
    Setup-->>App: Progress or no reservation
    Note over App: Explicit user action opens native administrator UI
    App->>Setup: Selected targets, disclosure acceptance, native rights
    Setup->>Machine: Commit caller-bound account and initial epoch
    Machine-->>Setup: Retained account identity
    Setup-->>App: Saved progress
    App->>Setup: Resume exact setup and revision, native rights
    Setup->>Key: Restore or create the scoped hardware key
    Setup->>Machine: Retain its public pin
    Setup->>Stores: Resume the same initialization and checkpoint
    Setup->>Machine: Mark storage prepared
    Setup-->>App: Prepared storage, no runtime readiness claim
```

## Ownership and recovery

The endpoint derives the caller UID from its authenticated XPC invocation.
The helper queries `/Local/Default` for that UID and retains the directory UUID.
A replacement account with the same UID cannot claim the retained preparation.
A primary group change does not replace the account identity.
Each local account receives a separate random Remozio account ID and separate storage directories.

The reservation freezes the installation, release, command grants, initial epoch and current code policy.
It commits before key or journal creation.
Repeated preparation restores those inputs. It cannot replace the grants or create another epoch.
Different grants require a separate future policy-change operation.

The controller pins the key before it starts journal initialization.
Retained initialization checkpoints preserve the journal and continuity boundary across crashes.
Completed preparation never recreates a missing key or database.
A lost reply requires a fresh progress read before another mutation.
Refresh never opens administrator UI or retries a mutation.

## Storage and protocol versions

Explicit account preparation upgrades the machine store to schema 4.
Normal opening and progress reads preserve schemas 1 through 7 without upgrading them.
The added table retains the account reservation independently of the installed-service inventory.
Prepared storage can exist before account service declarations are installed.
It grants no service registration, pairing or command admission.
Existing runtime startup checks still require their complete installed declarations and protected configuration.

The existing storage interface keeps its version 1 hello and operations.
New enrollment operations require a separate version 2 hello.
The app verifies the Root peer before it exports native administrator rights.
Each mutation rechecks native rights, caller scope, current protected release and retained progress.
Signed manifests declare local interface versions 1 through 5, and machine schemas 1 through 7.

## Evidence and remaining gates

Ordinary-owner tests use actual protected leases, SQLite journals and continuity stores.
They cover account isolation, changed directory identity, stale revisions and five interrupted controller stages.
They also cover lost commit replies, a rejected native authorization form and the logical app-to-endpoint sequence.
The native directory lookup reads the current Mac account without changing it.

These controls do not prove Root hardware key provisioning, native XPC admission or an installed administrator approval flow.
Actual privileged installation and service tests remain in issues [#363](https://github.com/rock3r/remozio/issues/363) and
[#374](https://github.com/rock3r/remozio/issues/374).
The app reports storage preparation separately from service readiness.
Service account creation still needs the native installation test.
Runtime file publication and explicit service activation follow service account preparation. Their installed behavior still needs the interactive validation gate.
Real device and end-to-end checks still require the user's interactive session.

## Dedicated service accounts

After storage preparation, an explicit app action creates separate transport and gateway accounts.
The app discloses this action before native administrator authorization.
These accounts cannot log in. They have separate primary groups and no home directory with user data.

```mermaid
sequenceDiagram
    participant App as Installed app
    participant Setup as Root setup helper
    participant DB as Machine database
    participant OD as Local directory
    App->>Setup: Version 3 hello, then read progress
    Note over App: User selects Prepare service accounts
    App->>Setup: Exact progress and current administrator rights
    Setup->>OD: Check names, IDs and UUIDs
    Setup->>DB: Reserve both numeric IDs in one transaction
    DB-->>Setup: Retained claims and UUIDs
    Setup->>OD: Create disabled group/user records for each role
    Setup->>OD: Check exact identity and isolation
    Setup->>DB: Retain completion
    Setup-->>App: Accounts prepared, runtime still unconfigured
```

The allocator checks random candidates between 20000 and 60000, with at most 128 attempts for each role.
It excludes the interactive owner, retained reservations and existing directory records.
Native checks use both the local directory and POSIX lookups.
The database checks both roles together before it reserves either number.
This database belongs to one Mac. It does not introduce a shared registry or a special Mac.

An explicit reservation upgrades the machine database to schema 5.
The saved plan binds the account, release, installation, authority pin and directory UUIDs.
A restart keeps the plan, including partial group or user creation.
The helper reconciles exact records after an unknown write result. It never adopts an unclaimed record or deletes a conflicting record.
Completed setup does not recreate missing accounts or groups.
A lost reply requires Refresh before another action.

The native driver submits disabled authentication, a false shell, an empty home and hidden status in the user creation call.
It checks exact names, numbers and UUIDs before reading the claimed record's authentication policy.
It also checks primary groups, POSIX identity, and administrator and wheel membership.
No account creation runs during ordinary tests.
The [live XPC experiment](experiments/macos-xpc.md#service-account-setup-selectors) also checks the new selectors across separate ordinary-user processes.

The tests use real SQLite transactions and a logical directory fixture.
They cover cross-account reservations, lost commits, malformed records, every controller interruption and rejected administrator rights.
They do not prove native account creation, disabled login, installed XPC or process isolation.
Those checks remain part of the interactive installation gate.

## Runtime file preparation

After service accounts are prepared, the user selects **Prepare runtime files** and accepts private-file custody for the transport TLS key.
The helper requires fresh administrator rights. The authority key remains hardware-backed.
This step prepares files. It does not start services, activate pairing or enable command execution.

```mermaid
sequenceDiagram
    participant App as Installed app
    participant Setup as Root setup helper
    participant Material as Private identity record
    participant DB as Machine database
    participant Files as Runtime and client files
    App->>Setup: Version 4 hello, then read progress
    Note over App: User accepts transport file custody and authorizes preparation
    App->>Setup: Exact retained progress, custody acceptance, native rights
    Setup->>Setup: Verify caller, signed release, service accounts and authority key
    Setup->>Material: Restore or create scoped TLS identity and local gateway IDs
    Setup->>DB: Retain immutable identity reference
    Setup->>Files: Publish matching policy, runtime and client configurations
    Setup->>Material: Confirm retained identity still matches
    Setup->>DB: Record publication completion
    Setup-->>App: Files prepared, no runtime health assertion
```

The machine database advances to schema 6 only when it retains the identity reference.
The reference includes a digest and public TLS pin. It contains no private transport key.
The private identity record also preserves local gateway identifiers. It does not invent FCM credentials or configure push delivery.
The initial TLS certificate lasts one year. Renewal requires a separate protected transition; setup never replaces an established identity automatically.

Private command and policy files stay under the account's Root-owned runtime directory.
Service-readable files stay outside the private Accounts tree, under a Root-owned directory for that account.
The transport key file has mode 0600 and belongs to the reserved transport user and group.
Transport configuration and app/CLI metadata have mode 0644 and remain Root-owned.
The CLI selects `frontend-UID.cbor`. It uses the legacy shared configuration only when the scoped file does not exist.
Invalid or unreadable scoped configuration never triggers that fallback.

Exclusive publication refuses conflicting bytes, unsafe metadata and links. It never overwrites an existing conflict.
A retry after a lost reply restores the same identity and local gateway IDs.
A retained identity reference prevents regeneration if private material disappears.
Completed progress is historical. Reading it does not repair files, recreate keys or claim that services are healthy.
The command runtime file is a blueprint, not an installed service declaration.
The explicit activation step publishes the installed command-host wrapper and registers per-account jobs. Publication alone does neither.

Tests cover actual SQLite and owned-file recovery, four interrupted composition stages, authorization refusal, stale progress and explicit app consent.
The [live selector evidence](experiments/macos-xpc.md#runtime-preparation-selectors) covers separate ordinary-user processes.
Native Root ownership, real service account access, activation and Mac–Pixel approval remain interactive gates.

## Explicit service activation

After runtime files are prepared, **Start services** requires current administrator authorization.
**Restore services** repeats the same scoped operation. It retains the existing identities, account claims and configuration.
Refresh reads progress without starting jobs or importing administrator rights.

```mermaid
sequenceDiagram
    participant App as Signed Mac app
    participant Setup as Root setup helper
    participant DB as Machine store
    participant Files as Protected host and job files
    participant OS as launchd
    App->>Setup: Version 5 hello, then read scoped progress
    Note over App: Explicit Start or Restore and native administrator approval
    App->>Setup: Exact progress and current native rights
    Setup->>DB: Retain activation plan before job publication
    Setup->>Files: Verify existing keys/configs; publish exact host and job files
    Setup->>DB: Enroll only this account and its exact services
    Setup->>DB: Close machine writer
    Note over Setup,DB: Native registration never holds the machine writer
    Setup->>OS: Inspect matching authority job; bootstrap only if absent
    Setup->>OS: Inspect matching transport job; bootstrap only if absent
    Setup->>DB: Reopen scoped writer; retain registration marker
    Setup-->>App: Historical registration progress
    Note over App: Main window checks the live authority connection separately
```

The frozen plan advances the machine store to schema 7. It contains no private transport key.
The plan binds the retained material, signed release, installed command host and transport startup configuration.
Account and service enrollment preserves unrelated accounts and jobs.
Conflicting labels, declarations, files or loaded programs stop the operation. The helper never stops or replaces an unproven job.

Each job has a derived name under `/Library/LaunchDaemons` and points into the same signed app bundle.
The authority runs as Root. The transport runs as its reserved service user and group.
Both jobs start at system startup and use launchd restart behavior.
The app does not modify its signed bundle or require a central Mac.
Installed host format 1 retains bundled-job validation. Format 2 explicitly selects protected system jobs for the account.

Native commands receive a minimal environment, no caller descriptors, a time limit and bounded output.
The helper compares launchd's reported source path, program, arguments, user and group when it reconciles a lost registration reply.
It also requires the exact Mach service names, managed endpoint settings, and the saved startup flags.
These operational fields are not proof of complete loaded settings, process credentials or runtime health.
Actual request admission still requires protected metadata, the signed role, kernel credentials and the existing runtime checks.
Unknown inspection output fails without a mutation. A conflicting loaded job is not removed.

The [owned-job experiment](experiments/evidence/2026-10-15-owned-job-registration.json) confirms these fields across a real GUI-job registration.
It also confirms that changing the plist preserves the loaded program, endpoints and flags. A same-label bootstrap does not replace the job.
Wrong user/group declarations have fixture coverage; their system-domain behavior remains an installed test gate.
The probe removes its exact temporary job and retains no raw job environment.
The [version 5 selector evidence](experiments/macos-xpc.md#runtime-activation-selectors) checks the new XPC methods across separate ordinary-user processes.

Tests cover actual owned files and SQLite, six interrupted activation stages, writer release before registration, denied rights and stale progress.
They also cover passive app refresh and explicit restore after a lost reply.
They do not prove installed Root registration, dedicated-user access, hardware-key restoration or Mac–Pixel approval.
Those physical gates remain open. Push delivery remains unconfigured in this initial foreground LAN path.
