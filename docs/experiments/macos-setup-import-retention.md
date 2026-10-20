# Portable setup import recovery

The Core module can retain a reviewed import proposal and read back its recovery state.
The app still offers a read-only setup preview. No production import endpoint is exposed.
Retention does not apply settings, provision credentials, or activate services.

```mermaid
flowchart LR
    A[Encrypted setup file] --> B[Read-only preview]
    B -. Endpoint integration pending .-> C[Retain reviewed proposal]
    C --> D[Protected import journal]
    D --> E[Read back the exact operation]
    E -. Native integration pending .-> F[Verify outputs and apply]
```

## Recovery contract

The destination scope comes from the prepared local account and installation.
It includes the Mac, installation, release, account, owner UID, and account record binding.
The imported file cannot supply these identities.

The journal stores public choices and a digest of the complete decoded proposal.
It excludes provider credentials. Before using credentials, the caller must reopen an encrypted file with the exact reviewed proposal.
Matching public settings alone is insufficient when credentials differ.

The separate SQLite journal uses format version 2.
Its first record is committed before its directory receives the active name.
An unexplained partial directory is rejected. Existing files are never repaired through import retention.

Each operation has a stable identity and changing revisions.
Revision checks reject stale writers, replacement proposals, and skipped phases.
An unknown commit outcome retires the writer. The caller must read back the retained operation before continuing.

Pending import state blocks unrelated Gateway changes.
Completed import history can supply its retained Gateway defaults.
A completion marker does not grant administrator rights or establish current service health.

## Update compatibility

The update snapshot retains the journal's directory, database, and writer identities, plus complete record digests.
It includes both the original portable payload version and the version of the redacted recovery recipe.
It preserves the existing runtime material, reference, activation, pairing, and Gateway requirements.

The initial reader rejects unrecognized files in the active journal directory.
Future relay records must extend the snapshot and its format requirements together.

## Evidence and remaining work

All 76 focused tests passed on source `ab39f94b94ffae8390cfc0e36383db370c63ed66`.
They use owned files, synthetic credentials, and injected failures.
The command targets `arm64-apple-macosx26.0`; the test host runs macOS 27.0.1.
These results do not establish native Root admission, real power-loss recovery, or physical device interoperability.

Before native import is exposed, runtime preparation must join the reviewed recipe and journal revision.
Subsequent Gateway setup must preserve completed imported defaults.
The endpoint must authenticate the caller UID and obtain fresh administrator authorization.
Native and legacy transports need signed declarations and actual IPC evidence before advertising capability 10.
Native outputs, credential custody, independent relay resources, and final preference application still need integration and verification.

The setup IPC versions and signed release declarations remain unchanged in this slice.
The full local gate remains required before publication.
