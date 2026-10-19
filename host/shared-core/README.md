# Shared host core

`RemozioHostCore` contains the shared decision verifier and its retained-request,
trust and clock value types, continuity checkpoints, history-recovery intent
encoding and storage-reconciliation selection. The Mac authority uses these implementations through
the existing `RemozioCore` public names.

Verification checks the exact request, current enrollment, capabilities, permitted
action, signing key and monotonic deadline. A `VerifiedDecision` is verification
evidence only. The authority must still revalidate and consume the decision under
its journal lock before considering dispatch.

Checkpoint and recovery APIs validate caller-supplied data only. They establish
neither provenance nor protected storage, and their results grant no admission,
replay or dispatch authority. The Mac adapter keeps lazy pending-first journal
reads and applies reconciliation inside its existing storage serialization
boundary. Its protected stores, commit coordination and startup gates remain
Mac-owned.

This package contains no persistence, operating-system clock, caller monitor,
TPM integration, service installation or command execution. It introduces no
Linux capture schema or changes to existing protocol bytes.

Run the shared tests with Swift 6.2 or later:

```sh
swift test --package-path host/shared-core --force-resolved-versions
```

The tests use disposable software keys through CryptoKit on macOS and Swift
Crypto on Linux. Their results do not establish hardware custody or a complete
host approval flow. Portable recovery tests cover data validation and selection;
the Mac store suites retain transaction, reopen and storage-failure coverage.
