# Ubuntu foundation validation and operator handoff

This work implements experiments and protocol portability, not an installed Linux
host. The [Phase 0 proposal](linux-host-contract.md) keeps Ubuntu 25.10 compatibility
in scope and leaves the production caller guarantee and Linux wire extension open.
The updated [contributor guide](https://gist.github.com/rock3r/ef069bbc6f931b83febf2e1c159cdbfa)
keeps the optional remote ADB bridge separate from the first approval flow.

## Recorded local checkpoint

On 17 October 2026, Ubuntu 25.10 x86_64, kernel `6.17.0-41-generic`:

| Check | Result |
| --- | --- |
| `scripts/check.sh`, system Python 3.13 | 165 repository tests, six explicit skips; 221 watcher tests passed. Run outside the socket-restricted execution sandbox. |
| Existing Swift protocol suite | 119 tests passed; all 25 shared fixture files unchanged. |
| Caller experiment | 31 observations and four cleanup checks passed; all nine focused tests passed with live checks enabled. |
| TPM/provider TLS and hardware-adapter control | Both passed against private simulators; eleven focused unit tests passed. No physical TPM execution. |
| Linux-runnable Kotlin/Android tasks | Passed with JDK 21 and SDK 37; Gradle reused unchanged task results. Debug APK and lint tasks succeeded. |
| Full required Gradle gate | Blocked by the four absent Mac peers described below. |
| Mac checks and remote CI | Not run; the added Linux protocol CI job is prepared only. |

The linked experiment reports bind their results to source hashes and record the
limits. These results do not establish a protected installation or real approval
execution. The current work stays local until the full pre-push gate is satisfied.

## Independent checks

Use Python 3.11 or later, Swift 6.2 or later, JDK 21, and an Android SDK containing
platform `android-37.0` and build tools `37.0.0`. The shell's `python3` must select
the intended interpreter; this machine's `/usr/bin/python3` is 3.13, while another
Python earlier on its default PATH is older.

```sh
./scripts/check.sh
./scripts/check-linux-protocol.sh
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

## Required upstream gate

The shorter Gradle command above is the Linux-runnable subset. It does not replace
the [repository pre-push requirement](../AGENTS.md):

```sh
./scripts/check.sh
./gradlew :protocol-kotlin:test :phone-core:test :phone-core:approvalFlowTest :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
```

On this Linux checkout the full Gradle command stops because `ApprovalFlowPeer`,
`TLSPeer`, `HPKEPeer` and `AuditFlowPeer` are absent from `.build/approval-flow`.
Those are current Mac interoperability executables. Do not substitute empty files,
skip the task in the required gate, or report it as passed. The Darwin branch of
`scripts/check.sh` also requires actual Mac execution. Arrange a Mac validator for
the exact shared-source revision before pushing. No local Linux result establishes
Mac runtime compatibility.

## Human testing boundary

The next device-dependent evidence is physical TPM signing and mutual TLS, using
the prepared TPM experiment procedure under the intended access configuration.
The [operator procedure](experiments/linux-tpm-tls.md#prepared-human-hardware-gate) requires
explicit hardware mode, authorized ordinary-user resource-manager access and
known-empty owner authorization for this provider adapter. Unknown or nonempty
owner authorization is unsupported by this adapter; do not guess it or reset it.
It must use disposable objects and verify the expected public identities. Do not
clear the TPM, reset ownership, evict unrelated handles, or automatically replace
an existing trusted host identity. Simulator keys and state are disposable fixtures;
they must never be enrolled as a production identity.

Record create/reopen, signing, mutual authentication, negative peers, unavailable
hardware and bounded resource behavior. Reboot persistence, protected service
access and copied-record rejection need their own explicit controls. A real TPM
result does not establish a protected Linux installation or a phone approval flow.
Using `/dev/tpmrm0` is device-path evidence, not physical-hardware attestation;
the operator must identify the test platform accurately, including any virtual TPM.

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
