# Ubuntu foundation validation and operator handoff

This work implements experiments and protocol portability, not an installed Linux
host. The [Phase 0 proposal](linux-host-contract.md) keeps Ubuntu 25.10 compatibility
in scope and leaves the production caller guarantee open. Linux capture schema 4
and Android interpretation are now defined by the
[accepted contract](linux-capture-proposal.md); they do not enable host issuance.
The updated [contributor guide](https://gist.github.com/rock3r/ef069bbc6f931b83febf2e1c159cdbfa)
keeps the optional remote ADB bridge separate from the first approval flow.

## Recorded local checkpoint

On 17 October 2026, Ubuntu 25.10 x86_64, kernel `6.17.0-41-generic`:

| Check | Result |
| --- | --- |
| `scripts/check.sh`, system Python 3.13 | 165 repository tests, six explicit skips; 221 watcher tests passed. Run outside the socket-restricted execution sandbox. |
| Existing Swift protocol suite | 119 tests passed; all 25 shared fixture files unchanged. |
| Caller experiment | 31 observations and four cleanup checks passed; all nine focused tests passed with live checks enabled. |
| TPM/provider TLS and hardware-adapter control | Private simulator controls and eleven focused unit tests passed. Supervised `/dev/tpmrm0` create/reopen, signing and mutual TLS also passed, including the same keys after an operator reboot. |
| Linux-runnable Kotlin/Android tasks | Passed with JDK 21 and SDK 37; Gradle reused unchanged task results. Debug APK and lint tasks succeeded. |
| Original unconditional Gradle gate | Blocked on Linux by four absent Mac peers; replaced by the host-aware gate below. |
| Mac checks and remote CI | Not run; the added Linux protocol CI job is prepared only. |

The linked experiment reports bind their results to source hashes and record the
limits. These results do not establish a protected installation or real approval
execution. At this checkpoint the original unconditional local gate blocked Linux
pushes. The host-aware local gate below replaces that requirement while retaining
Mac CI checks before merge.

## Independent checks

Use Python 3.11 or later, Swift 6.2 or later, JDK 21, and an Android SDK containing
platform `android-37.0` and build tools `37.0.0`. The shared-host SQLite tests also
require development headers and library (`libsqlite3-dev` on Ubuntu), discoverable
through `pkg-config`. The shell's `python3` must select
the intended interpreter; this machine's `/usr/bin/python3` is 3.13, while another
Python earlier on its default PATH is older.

```sh
./scripts/check.sh
./scripts/check-linux-protocol.sh
./scripts/check-linux-host.sh
python3 scripts/run-linux-caller-experiment.py
./gradlew :protocol-kotlin:test :phone-core:test :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
```

The caller runner uses only disposable processes in the current account. Its live
checks need ordinary Unix sockets and tracing of its own children; restricted
execution sandboxes may deny those operations. Such a denial is a failed or
unavailable experiment, not successful identity validation. Do not change global
ptrace or security policy to obtain a pass.

The [Swift experiment](experiments/linux-swift-protocol.md) records an isolated
official toolchain and the additional userspace libraries needed on Ubuntu 25.10.
The [caller experiment](experiments/linux-caller.md) records exact positive checks,
timeouts, cleanup and untested cases. The [TPM/TLS experiment](experiments/linux-tpm-tls.md)
has separate dependency and invocation instructions; simulator results must remain
labelled as simulator results. None of these commands installs a production daemon.

The separate [controlled monitor experiment](experiments/linux-caller-monitor.md)
extends the caller work with supervised fixture launch, event invalidation and a
simulated stopped handoff. Its native fixture runs independently of a phone or
TPM; its successful controls still leave protected code and production admission
unsupported. Enable its live test explicitly as documented there. Existing
historical checkpoints above remain scoped to their original source revisions.

The [disposable approval-to-command experiment](experiments/linux-approval-command.md)
connects the shared verifier, fixture-only consumption, audit tables and checkpoint/recovery
selection to a fixed ordinary-user command. It runs automatically after the shared-host
suite in `check-linux-host.sh`, on both the local Linux gate and Linux Swift CI job.
Synthetic software keys and requester claims, a private fixture ledger and one fixed command
do not establish production authority, physical-phone approval or protected caller admission.

## Local gate and CI coverage

The [repository pre-push requirement](../AGENTS.md) is one manual command that
selects the checks executable on the current host. No Git hook is installed:

```sh
./scripts/check-local.sh
```

It runs `scripts/check.sh` first on both hosts. Linux also runs
`scripts/check-linux-protocol.sh` and `scripts/check-linux-host.sh`. Both run the
portable Kotlin/phone tests and Android unit tests, debug assembly and lint. macOS additionally runs
`:phone-core:approvalFlowTest` after `check.sh` has built its native peers.
Unknown platforms and any failed phase fail the gate immediately.

The [shared host core](../host/shared-core/README.md) contains the decision verifier,
its authority-owned request, enrollment and clock inputs, the sleep-inclusive clock
sampler, SQLite audit and consumption tables, consumption outcome transitions,
checkpoint and history-intent codecs, and pure storage-reconciliation selection. These tests run through the Linux host check and
native Mac check; Mac tests also retain audit signing integration. Mac consumers
use the same implementations through compatibility type aliases and a consumption
storage-error adapter. The table owner still supplies protected storage, durability
configuration and outer transactions.
Recovery selections are data-only recommendations; the Mac adapter retains its
serialized journal reads and protected-store transitions, with its existing store
integration tests. These extractions do not implement Linux protected persistence,
an authority or command dispatch. Shared consumption writes require an explicit
write transaction and the audit tables on the exact same connection and account.
Savepoints keep consumption/outcome mutations atomic with their audit append, even
if the caller catches an error and commits the outer transaction. Linux tests cover
competing write connections, replay across reopen, failure rollback and terminal
unknown outcomes; protected Linux connection ownership and durable commit/recovery
remain unimplemented. The Mac owner continues to load current enrollment and check
its revision in the write transaction, mark failures and coordinate checkpoints.
The disposable command experiment continues using its separate fixture-only ledger.

The complete Linux coordinator passed on 2026-10-18 for source revision `6984429`,
including the shared-source inventory fix and its regression controls, on this
Ubuntu 25.10 host with the prepared Swift 6.2.4 runtime, JDK 21 and Android SDK 37:
178 repository tests (six skips), 221 watcher tests, 130 Swift protocol tests,
eight shared verifier tests, and all portable Kotlin/Android tasks. The repository
tests include six controls for Linux/macOS command selection, running from another
directory, unsupported hosts and failure propagation. Stubbed macOS commands and
source-change controls test orchestration only; native Mac builds, interoperability
and live experiments were not executed on this Linux host. Their required Mac
validation remains separate from this result.

`ApprovalFlowPeer`, `TLSPeer`, `HPKEPeer` and `AuditFlowPeer` are macOS executables
built from `experiments/approval-flow`. Linux does not substitute or skip their
Gradle task: it runs the portable tasks locally, and the complete native
interoperability suite remains required in Mac CI before merge. Explicitly invoking
`:phone-core:approvalFlowTest` still fails when the peers are absent.

All automated local checks map to jobs in
[checks.yml](../.github/workflows/checks.yml), triggered on pull requests and pushes
to `main` without path filters:

| Local check | CI job and command |
| --- | --- |
| Repository Python and PR-watcher tests | **Python checks**: `./scripts/check.sh` on Ubuntu; also runs on Mac. |
| Linux Swift protocol and shared host tests | **Linux Swift protocol**: `./scripts/check-linux-protocol.sh` and `./scripts/check-linux-host.sh` on Ubuntu 24.04. |
| Mac native builds, experiments, Swift protocol, shared host and core tests | **Mac build**: the complete Darwin branch of `./scripts/check.sh` on macOS 26. |
| Portable Kotlin protocol and phone tests | **Kotlin protocol**: `:protocol-kotlin:jvmTest :phone-core:test :phone-ui:jvmTest :dev-invitation:test`. |
| Native Swift/Kotlin interoperability | **Mac interoperability**: builds all four peers from the checkout, then runs `:phone-core:test :phone-core:approvalFlowTest`. |
| Kotlin tests on the iOS simulator (macOS only) and the iOS app build | **iOS build**: `:protocol-kotlin:iosSimulatorArm64Test :phone-ui:iosSimulatorArm64Test`, then an unsigned simulator build of `ios/Remozio.xcodeproj` on macOS 26. |
| Android unit tests, debug assembly and lint | **Android build**: `:android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug`, plus the additional CI-only `:android-app:assembleRelease`. |

The PR watcher's `local_gate` uses the same coordinator and its `required_checks`
includes all seven job names. The original five jobs passed in upstream
[Checks run 39034970117](https://github.com/rock3r/remozio/actions/runs/39034970117)
for base revision `2d00126c8ce010f356a5de0db8e432dd37b504cc`. This branch's added
Linux Swift job has been validated locally but has not yet run remotely.
CI configuration and historical base results do not establish a pass for this branch.

Mac automated validation therefore does not require a friend's machine before a
Linux push; it remains a merge gate on the PR revision. The XPC GUI checks and
device-dependent experiments still require their specified interactive operator
sessions. A passing local Linux gate does not establish Mac runtime compatibility.

## Human testing boundary

Supervised `/dev/tpmrm0` creation, fresh-process reopen, signing and mutual TLS,
including reuse of the same keys after the operator's reboot,
passed with the operator's temporary per-user device ACL. The
[device checkpoint](experiments/linux-tpm-tls-device-evidence.json) records all negative
controls, unchanged retained records and unchanged persistent/NV handle listings.
The boot identifier changed, and all retained records matched their original hashes
before and after the reboot test. The same two keys signed and verified, and mutual
TLS plus all negative controls passed. No replacement keys were generated.
Protected service access, resource contention and physical cross-machine controls
remain separate device-dependent checks.
The [operator procedure](experiments/linux-tpm-tls.md#prepared-human-hardware-gate) requires
explicit hardware mode, authorized ordinary-user resource-manager access and
known-empty owner authorization for this provider adapter. Unknown or nonempty
owner authorization is unsupported by this adapter; do not guess it or reset it.
It must use disposable objects and verify the expected public identities. Do not
clear the TPM, reset ownership, evict unrelated handles, or automatically replace
an existing trusted host identity. Simulator keys and state are disposable fixtures;
they must never be enrolled as a production identity.

Record create/reopen, signing, mutual authentication, negative peers, unavailable
hardware and bounded resource behavior. The recorded reboot retention applies only
to the disposable fixture on this selected device. Protected service access and
physical cross-machine copied-record rejection still need explicit controls. A real TPM
result does not establish a protected Linux installation or a phone approval flow.
Using `/dev/tpmrm0` is device-path evidence, not physical-hardware attestation;
the operator must identify the test platform accurately, including any virtual TPM.

For future repeats, the retained fixture is under the operator's private user state directory,
`~/.local/state/remozio-experiments/tpm-tls-fixture`. Keep it through the reboot;
reuse must not regenerate either key. Sibling files retain the before-boot identity
hashes and boot comparison metadata. The `runtime-debs` sibling preserves the
isolated runtime packages and `runtime-package-hashes.json` records their checksums
so the same runtime can be restored if `/tmp` is cleared. After returning, re-establish
the temporary device ACL if needed, verify the public prerequisites and package
hashes, compare the boot identity, and run the documented `--reuse-fixture` invocation
with `--operator-phase after-reboot`. Publish comparison booleans only, never
the raw boot identifier or retained key records. Remove the temporary ACL after
the supervised tests finish.

Physical Pixel pairing and biometrics become actionable after the Linux services,
negotiated capture contract and executor are implemented. The current experiments
are not ready to approve or run real user commands. Privileged installation,
service activation, reboot and phone interaction remain supervised milestones.

## Review boundaries

Keep the design proposal, caller experiment, TPM experiment and shared protocol
portability independently reviewable. Coordinate shared schema work before assigning
wire tags; the [capture proposal](linux-capture-proposal.md) gives the concrete
upstream decisions and required fixtures. Submit implementation PRs sequentially and use the repository PR watcher
for readiness. Hardware results, Mac validation and schema agreement remain explicit
gates rather than implied consequences of unit-test success.
