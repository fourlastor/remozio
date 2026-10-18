# Linux host contract: Phase 0 proposal

Status: proposed, 17 October 2026. This document selects an initial experiment
profile and its admission gates. It does not approve a production wire schema,
enable command execution, or claim a supported Linux release. The starting
reference is the [contributor guide](https://gist.github.com/rock3r/ef069bbc6f931b83febf2e1c159cdbfa)
and its merged baseline `2d00126c8ce010f356a5de0db8e432dd37b504cc`.
Experiments must report their actual revision and results separately.

## Initial platform and scope

| Property | Proposed initial requirement |
| --- | --- |
| Distribution | Ubuntu only; begin by testing Ubuntu 25.10 compatibility. Other distributions, including Omarchy, are outside this work. Compatibility on this machine is not a security-maintenance or release-support claim. |
| Architecture | Native x86_64 userspace and kernel; no x32/compat caller ABI initially. |
| Kernel | Proposed floor 6.17, with required capabilities checked at runtime. The development machine reports Ubuntu 25.10 and `6.17.0-41-generic`; that observation alone proves no security property. No claim is made for older kernels or all newer configurations. |
| Service manager | systemd system services with distinct protected authority, transport, and execution identities; separate unprivileged session component. |
| Local IPC | Protected filesystem Unix-domain `SOCK_SEQPACKET` endpoints, bounded messages, kernel credentials and retained process handles. No public abstract socket as the sole installation boundary. |
| Hardware keys | Physical TPM 2.0 supporting NIST P-256 signing and the required key attributes; protected metadata and explicit device access. No software-key fallback. |
| Desktop | No desktop environment requirement for the first foreground CLI/LAN experiment. Presence, tray UI, locked-session inference and remote-desktop integration remain unavailable until an Ubuntu desktop profile is selected and measured. |
| First command target | The requesting user's current account, with an explicit local caller-to-target grant. Root and other-account execution remain disabled for the first useful milestone. |
| First phone path | Existing Android app, open in foreground, physical Pixel, authenticated LAN. No background delivery or remote-relay prerequisite. |

The kernel floor deliberately matches the first experiment family rather than
claiming an untested oldest compatible kernel. Required primitives include
`pidfd_open`, pidfd lifetime observation, `SO_PEERCRED`, per-message credentials,
kernel-provided peer/message pidfds where used, `PTRACE_SEIZE`, interrupt/exec/exit
events, descendant tracing, and `CLOCK_BOOTTIME`. Probe the exact operations and
security policy as the actual service identity. Header constants, kernel version,
or a successful root probe cannot substitute for that check. Missing operations,
denied access or unsupported semantics make the affected capability unavailable.
Do not silently substitute PID polling for a required retained process handle.

## Caller assurance: what must be established

The local caller is the submitting frontend process, not its shell, a named
application, the human, or an AI model. Ancestry is descriptive evidence only.
Authentication must distinguish three separate assertions:

1. **Sender and lifetime:** the bounded request came from the observed local
   account and the retained process instance remains alive.
2. **Executable observation and continuity:** a stopped process has the observed
   executable object and no unhandled transition occurred in the monitored
   interval through the dispatch decision.
3. **Trusted executing code:** the frontend's running code and relevant loader
   inputs satisfy a protected code policy and were not substituted or injected.

The first two assertions do not imply the third. `SO_PEERCRED` describes the
connection peer; a socket can subsequently be inherited or passed to another
process. A pidfd retains process identity across PID reuse but is not an exec
generation counter. `/proc/<pid>/stat` start time does not change on exec and
must never be truncated into the Mac `pidVersion` field. A hash of `/proc/<pid>/exe`
observes a file, not every byte currently mapped or executed in that process.
These distinctions follow the [Unix socket API](https://man7.org/linux/man-pages/man7/unix.7.html)
and [ptrace API](https://man7.org/linux/man-pages/man2/ptrace.2.html).

### Candidate strict admission profile

The following is a proposed production gate, not a description of a completed
caller experiment. A test harness may deliberately exercise rejected cases.

| Case | Required initial behavior |
| --- | --- |
| Caller creation | Admit only a protected frontend whose launch, code policy and trace ownership were established before untrusted execution. Attaching to an arbitrary already-running process provides observations only; it does not retroactively establish trusted code. The protected-launch mechanism remains to be implemented and validated. |
| Threads | Initially require one native thread from controlled launch. Reject pre-existing multithreaded callers. Trace clone/fork/vfork events from the start and invalidate the request on any new task. A `/proc/.../task` count before attach is insufficient to exclude a racing thread or a shared address space established earlier. |
| Exec | Establish the approved frontend image while stopped. Treat later exec events as terminal invalidation, including exec back to the same pathname. Do not resume a changed image as the approved caller. Non-leader exec/TID changes are negative controls, not an admitted multithreaded path. |
| Final decision | The monitor must own and confirm the caller's ptrace stop while checking the final caller state and committing the dispatch handoff. Define an acknowledged monitor/executor handshake so queued events, monitor death or release of that stop cannot silently cross the handoff. A last `/proc` read followed by an unconstrained runnable interval is insufficient. |
| Socket transfer | Enable per-message kernel credentials and require the message sender to match the retained admitted process, even if connection credentials match. Bind one submission nonce and retained channel to that process. A different process using an inherited or transferred endpoint fails. Extra descriptors, missing credentials, ancillary truncation, message truncation and unexpected control messages fail. |
| Streams | Retain and classify the actual received descriptors, enforce access and semantic flags, and recheck before dispatch. Descriptor passing shares an open file description: it does not freeze file offsets, flags, input contents or other holders. The phone must disclose caller-controlled streaming. |
| Credentials | Require the expected real/effective/saved/filesystem IDs and group set, with no unexpected capabilities or privilege transition. Detect and reject changes during pending admission. Initial same-account target resolution and current grants still use trusted OS/protected state. |
| Namespaces | Initially require the host's selected namespace identities, including user, PID, mount, network, IPC, UTS, cgroup and time namespaces, with no pending child-namespace change. Reject containers, user namespaces and namespace transitions. Compare retained namespace objects rather than caller-provided names; an inaccessible namespace check fails. |
| Tracer and LSM | Existing debugger, unavailable trace ownership, denied ptrace, blocked proc access, unsupported LSM combination or lost event ownership means unavailable. Never lower Yama, AppArmor, seccomp or other system policy to make admission pass. |
| Exit and monitor loss | Caller exit invalidates a pending request. Monitor failure invalidates its generation; no PID-based reconnect can resurrect it. After dispatch, the captured disconnect/termination contract and durable outcome rules apply. |

Per-message credentials must be interpreted according to their kernel semantics,
including the privilege checks on explicitly supplied credentials. The initial
caller has no capability that permits impersonating another sender. A forwarded
request sent by the admitted process itself is still that process's request;
neither IPC nor ancestry authenticates its human origin.
Use the kernel-supplied message process handle to close receive-to-lookup PID
reuse races, with its association to the traced task checked while live. Opening
a new pidfd from an unretained numeric PID after receipt is not equivalent. The
experiment must establish that association; unavailable ancillary pidfd support
must not fall back to a numeric comparison.

`ptrace` can hold an observed task at a stop and report exec transitions. It does
not by itself authenticate the machine code that brought that task to the stop.
A process can retain the same executable object after pre-attach injection,
load attacker-controlled code without exec, or receive writes through other
memory-access mechanisms. Existing shared writable mappings and inherited
`/proc/.../mem` access need explicit treatment. Exclusive ptrace attachment alone
does not prove exclusion of all such writes. Root/kernel compromise is outside
this proposal; a malicious ordinary process in the requesting account is not.

Before describing a caller as **trusted code**, prove a protected launch path,
immutable-by-unprivileged-users frontend/loader dependencies, controlled loader
environment and file descriptors, and an enforced policy preventing unwanted
code loading, writable executable mappings, external memory modification and
unmonitored tasks throughout the interval. A small native frontend with a tight
system-call policy is a candidate. Merely hashing an executable, setting
`PR_SET_DUMPABLE` after an ordinary user launch, or enabling exec tracing is not
that proof. A ptrace stop cannot erase earlier manipulation.

This is the largest open design gate. If the launch/code policy cannot be shown
to satisfy the claim on Ubuntu, report the capability as unsupported. Do not
enable production execution by relabelling an observed executable as trusted or
silently weakening the Mac guarantee. Any narrower product guarantee requires a
separately reviewed contract decision before integration.

Yama modes and other active LSMs constrain tracing independently of an intended
service layout. Record their effective settings in non-secret evidence, including
negative controls for denied access. A dedicated monitor with narrowly scoped
privilege might be needed; its privilege and IPC attack surface require their
own review. [Kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html).

## Hardware identity and actual TLS come first

Use separate purpose-bound authority and transport identities with TPM-backed
P-256 private operations. Provision non-duplicable device-bound objects with
validated public attributes and protected authorization/metadata. A disk file
containing a TPM-wrapped object is not evidence that an exportable software key
was never used; key origin, attributes, selected provider and exercised signing
path must be recorded. No TPM clear, ownership reset, persistent-handle eviction
or modification of unrelated objects is part of an unattended experiment.

The first candidate bridge is OpenSSL 3 with the maintained TPM2 provider and a
small native adapter. [The provider documents TPM-backed TLS and resource limits](https://github.com/tpm2-software/tpm2-openssl).
Measure the actual selected TCTI/resource manager, P-256 signature representation,
certificate/key binding, restart reopening, timeout and bounded concurrency.
Kernel TPM resource management alone must not be presumed sufficient for the
chosen TLS workload. A software provider may perform hashing, public verification
and symmetric TLS operations; it must never replace the hardware identity's
private signing operation.

Acceptance requires an actual mutually authenticated TLS handshake using the
hardware host identity, pinned peer verification and exchanged application data.
Also test wrong host pin, wrong client pin, unavailable TPM, wrong key metadata,
signing denial, restart, and failed handshake without application delivery.
Software TPM and software peer keys can be explicitly labelled test fixtures;
they do not establish physical key custody or a physical-phone result.

Keep the network-facing transport outside authority signing, policy and dispatch
privileges. Its narrowly scoped TLS key operation cannot become arbitrary
authority signing. A TPM key alone is not platform attestation, proof of trusted
boot, proof of caller code, or protection against an already-authorized malicious
signing client. Missing hardware/private-key access blocks this gate; it never
triggers a file-key fallback or automatic identity reset.

## Protected installation and durable authority precede execution

Before enabling even a same-user production command, establish:

- Protected service users, unit definitions, executable paths and all parent
  directories; root-controlled package/update trust, release manifests and code
  policy. The authority, transport and execution roles have separate credentials
  and the least required access. Session UI cannot modify authority state.
- Protected IPC endpoint creation and ownership checks, bounded parsers, retained
  handles, and authenticated service-to-service messages. Service startup must
  reject a replaced binary, symlink/path substitution or unexpected ownership.
- Hardware identities and enrollment, current grants, journal, audit metadata,
  authenticated policy revisions and security floors outside replaceable binaries.
  Protected checkpoints and recovery markers survive service replacement.
- Atomic first-valid-decision consumption, crash reconciliation and an explicit
  consumed-but-dispatch-uncertain state. Restart never retries an uncertain
  external action. Partial state replacement, corruption or contradictory
  evidence blocks permissive operation rather than clearing trust/history.
- Boot-scoped lifetime observations and suspend-inclusive expiry using
  `CLOCK_BOOTTIME`; pending work is reconciled after reboot. Wall-clock changes,
  suspend/resume and monotonic time from another boot cannot extend approval.

The independent grant policy applies from the first own-account command.
Administrator membership, sudoers and possession of an enrolled phone create no
implicit grant. Reload grants at admission and immediately before execution;
missing, changed or unreadable policy blocks. Resolve and bind target UID, GID
and supplementary groups through the OS. An imported configuration must not copy
machine identity, private keys or local elevation grants.

The [accepted pathname limit](design-decisions.md#command-execution-by-pathname)
is explicitly carried into this Linux proposal: use the captured pathname after
a final identity/content and directory recheck, with captured argv, environment
and retained streams and without an implicit shell. A replacement between that
check and execution remains possible. Approval does not freeze scripts,
interpreters or transitive dependencies. This accepted target-command race does
not excuse a missing caller-monitor or protected-service-code boundary.

The [accepted whole-backup limit](design-decisions.md#whole-mac-backup-rollback)
is also proposed for Linux: an internally consistent complete restoration of old
host state is outside the guarantee. It can restore old policy, revocations and
consumption state. Ordinary crash consistency, partial-replacement detection,
retained floors, protected checkpoints, replay prevention and device-bound
identity remain mandatory. No independent online rollback witness is introduced.
Lost hardware identity requires explicit recovery/re-enrollment, never silent
creation of a replacement trusted host.

## Protocol and shared-source boundary

Keep existing Mac schemas, role names, field tags and canonical bytes unchanged.
[Issue #441](https://github.com/rock3r/remozio/issues/441#issuecomment-6253309933)
approved Linux capture schema 4, its closed requester/credential field allocation,
and the desktop-host interpretation of existing role 1 and `macID` without changing
negotiation or pairing bytes. The [protocol contract](../protocol/command-capture.md)
defines codec and Android interpretation; it does not approve production issuance.
The [capture proposal](linux-capture-proposal.md) retains the design history and
fixture matrix.
Linux process handles, start times, namespaces and package provenance must not
masquerade as Mac PID versions, Apple signing identities, team identifiers or
cdhashes. Unknown/disjoint contracts must fail explicitly per enrolled host.

Portable Swift protocol work may proceed without this extension, using a portable
public/software crypto implementation for existing fixture semantics. That work
does not implement TPM custody. Extract narrow verification/state components only
as needed; Mac must consume the same extracted implementation and retain its
tests. Do not move all of `macos/core` or replace Darwin adapters speculatively.
The same Android application must continue supporting multiple independently
enrolled Mac and Linux hosts, without global compatibility or trust fallbacks.

The updated contributor guide's remote ADB design is a separate optional
workstream, with separate bridge keys, per-pair grants and the shared Android
bridge protocol. Approval enrollment does not grant ADB access. That work does
not block the first ordinary-user command demo and is not implemented here.

## Evidence and implementation gates

| Gate | Completion evidence | Still not proved by that gate |
| --- | --- | --- |
| Caller experiment | Retained process lifetime, exec races including same-path exec, exit/PID reuse, threads, transferred/inherited sockets, credential/namespace changes, denied LSM access and monitor failure; exact supported and rejected cases. | Protected launch/code integrity unless separately exercised; installed authority or real command approval. |
| TPM/TLS experiment | Physical TPM P-256 create/reopen/sign, actual pinned mutual TLS, failure controls and bounded resource behavior. | Phone pairing, installed service access controls, complete recovery. |
| Portable protocol | Existing shared bytes and rejection fixtures pass on Linux; Mac runs the same source with its full checks. | Approved Linux wire schema or hardware private-key use. |
| Protected services | Installation/permission negatives, role isolation, journal/checkpoint/floor recovery and consumption/dispatch crash boundaries. | Physical phone interaction or privileged target support. |
| First phone flow | Physical Pixel pairing and synthetic approve/deny with current trust, lost replies and reconnect. | A real command until the executor gate also passes. |
| First useful command | Explicit own-account grant, exact displayed request, biometric approval, streamed result; deny/expiry/replay/revocation/caller exit/disconnect/crash controls. | Root targets, general threads/namespaces, background wake, presence, remote delivery or arbitrary desktop adapters. |

Evidence must distinguish measured behavior, source analysis, simulated controls,
unsupported cases and unrun tests. Record OS/kernel/architecture, relevant library
versions, configuration, source revision, operation/result and negative controls.
Do not commit private keys, key authorization, device identifiers, tokens,
personal paths, command contents or unfiltered environment output.

Prepare and run unprivileged isolated experiments independently. Stop at the
first required operator gate: protected installation, hardware provisioning or
privilege changes, physical Pixel biometrics/pairing, reboot, or supported Mac GUI
checks. Retain the prepared commands, expected outcomes and non-secret evidence;
notify the owner with the exact remaining action. Do not change system security
policy to make a test work.

## Pre-push validation and unresolved ownership

Every push requires the repository's host-aware local gate, with JDK 21 and
`ANDROID_HOME` pointing to an SDK with platform 37.0 and build tools 37.0.0:

```sh
./scripts/check-local.sh
```

The coordinator runs portable checks on both hosts, adds Swift protocol tests on
Linux, and retains the full native checks plus Swift/Kotlin interoperability on
macOS. The [CI coverage table](linux-validation.md#local-gate-and-ci-coverage) maps
every automated gate to its required PR job. A Linux contributor can push after the
Linux local gate passes; the Mac build and interoperability jobs must pass on the
PR revision before merge. Success on Linux does not establish a Mac pass. When
the XPC experiment changes, run its live checks in a supported Mac GUI session
and retain the evidence; CI and unit tests do not replace it. See
[AGENTS.md](../AGENTS.md) and the
[PR watcher workflow](../.agents/skills/babysit-pr/SKILL.md).

**Unresolved owner:** protected installation, physical phone tests and any required
Mac GUI checks still need an interactive operator. Automated Mac validation uses
the existing CI jobs. Phase 0 also requires review of caller code assurance and the
eventual Linux schema. Do not treat unavailable interactive checks as passed.
For any open PR, the repository watcher remains
the readiness authority. Keep experiments and shared-source changes focused and
retain their actual validation limits in each review.
