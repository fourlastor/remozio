# Composed Linux caller/command fixture

This opt-in experiment composes the earlier Linux components into one disposable
flow. A ptrace monitor holds a controlled, stopped native frontend. The frontend's
actual stdin, stdout and stderr pipes reach a Swift owner. The owner observes the
stopped caller independently and admits a schema-4 capture through the current
own-account grant. It verifies a software-signed decision, consumes it once in the
shared SQLite tables, and spawns one fixed `tee` command with those pipes.

It proves this fixture composition and its refusal controls at named barriers.
It does not establish protected code, production caller admission, an atomic
monitor/SQL/spawn handoff, credential elevation, an installed service, device
approval, hardware keys or rollback resistance. Reports keep `trustedCode`,
`productionAdmission`, `productionAuthority` and
`actualCredentialTransitionTested` false. The code policy digest is synthetic.

## Topology

| Role | Process | Owns |
| --- | --- | --- |
| R | Python supervisor (`composed.py`) | Subreaper, pipes, sockets, fault injection at barriers, freezing the monitor, independent marker count, final reaping |
| M | Python ptrace monitor, reusing the [monitor experiment](linux-caller-monitor.md) event handling | Trace of C from before its first exec, the kernel-checked submission carrier, the retained bundle sent to A |
| C | Native fixed frontend (`frontend.c`) | Sends one fixed submission with exactly its three stream descriptors, then stops |
| A | Swift owner (`LinuxComposedCallerCommand`) | Independent observation, grants, capture, decision, store, one-use launch permit, the command child |
| E | `tee -a command.marker` | Only the retained streams and directory, a fixed argument list and `LANG=C`; every other descriptor of A is close-on-exec |

M accepts the carrier only with one kernel pidfd, one `SCM_CREDENTIALS` record
and exactly three `SCM_RIGHTS` descriptors. The pidfd and credentials must match
the traced process. While C is live and in M's stop, M opens C's procfs directory,
`exe` and `cwd`. It sends A an eight-descriptor bundle: C pidfd, M pidfd, procfs
directory, executable, directory, stdin, stdout, stderr.

A reads C's `status` and `stat` through that retained directory, never by a fresh
numeric-PID lookup and never from its own task. Only M's frozen state is read through
`/proc/<pid>`, accepted while M's retained pidfd stays live before and after the read. It reads credential roles, groups,
capabilities, session, state and tracer this way. Raw `readlinkat` bytes name the
executable and directory, and the retained descriptors must match them. The
report's `remoteObservation` check confirms that A's own process, executable and
working directory all differ from C's.

## Transaction and barriers

1. **B0, after capture.** A resolves the target through
   `LinuxCurrentCommandElevationPolicy`, records the exact canonical grant bytes,
   builds the capture and completes the monitor's nonce-bound acknowledgment.
2. **B1, after the final monitor state.** R advances M (injecting any event case),
   M reports its final state, and R freezes M. A requires a matching nonce, binding
   and generation, `held_stop`, a frozen monitor and C in M's trace stop.
3. **Consume.** Under one SQLite write transaction, A re-verifies the decision
   (signature, current trust and authority time) and rechecks everything:
   - C, its executable, directory and streams;
   - the command executable;
   - exact grant bytes, read before and after current authorization;
   - freshly resolved NSS target;
   - A's own credentials and capabilities.

   Then it reserves the submission, consumes the decision, appends audit and
   finalizes the checkpoint. A refusal rolls everything back.
4. **B3, after finalized consumption.** A repeats every check above, including
   the decision's trust and time. On failure it records `proveNoDispatch`
   (cancelled) and never spawns.
5. **B4, after the durable `beginDispatch`.** The permit is taken once, then every
   check is repeated. A failure records `loseOutcome` (unknown) without a spawn.
6. **B4L, after the last check.** A spawns E with the retained streams and
   `fchdir` to the retained directory, then observes whether C and M are still
   held. It records success only when E exits 0, the marker holds exactly the
   input line, and the requester was still held.

## Contract line 67 and the dispatch race

[Contract line 67](../linux-host-contract.md#candidate-strict-admission-profile)
remains unproven by this fixture. No primitive here spans monitor liveness, the
SQLite commit and `posix_spawn` atomically. After B1, C can only stay stopped or
die, so it never runs unmonitored. But C or M can die after A's last check and
before or during the spawn.

The `dispatch-race-limitation` case is an explicit negative control for that
interval. R kills M at B4L, EXITKILL ends C, and A still spawns. A then detects
the loss and records the outcome as `unknown` with
`requesterLostDuringDispatch: true` and `strictAdmission: false`. The control
shows the loss is detected and recorded, not prevented, and it never counts as
successful strict admission. The production handoff contract is unchanged. This
reading was agreed with rock3r's agent on 27 October 2026.

## Capability policy

A refuses any nonzero permitted, effective or ambient capability set, for both
the caller and its own spawning task. It also refuses a set-ID or
`security.capability`-bearing command executable. An absent attribute must be an
explicit `ENODATA`.

The inheritable set is recorded as `callerInheritableCapabilities` but not
refused. Desktop sessions can pass a nonzero inheritable mask to ordinary
processes. Without ambient or file capabilities, that mask grants nothing.

## Cases

| Case | Fault | Expected outcome |
| --- | --- | --- |
| `healthy-approve` | none | succeeded, 3 audit records, one marker line; decision replay and permit replay refused |
| `healthy-decline` | software decline | declined, 1 record, no spawn |
| `carrier-missing-stream`, `carrier-extra-stream` | two or four descriptors | rejected by M before capture; M closes every imported descriptor before reporting |
| `fork-before-final`, `stop-release` | C forks, or M releases the stop | refused at the final phase, no rows |
| `grant-revoked-B0` | revoked grant at B0 | refused inside consume, rolled back |
| `monitor-death-B1` | M killed at B1 | refused inside consume, rolled back |
| `monitor-death-B3`, `grant-changed-B3`, `command-changed-B3`, `cwd-replaced-B3`, `stream-flags-B3` | the fault at B3 | consumed, then cancelled with no spawn |
| `monitor-death-B4` | M killed after `beginDispatch` | unknown, no spawn |
| `dispatch-race-limitation` | M killed after the last check | spawned once, then recorded unknown; not strict admission |

The changed grant at B3 still authorizes the same target; only its canonical bytes
differ. The stream case sets `O_NONBLOCK` through R's own handle to the caller's
stdout description. The command specimen is a disposable copy of `/usr/bin/tee`.

## Run

Use an ordinary Linux x86_64 session with Python 3.11 or later, `cc`, Swift 6.2
or later, `libsqlite3-dev`, procfs task-child enumeration, kernel message pidfds
(Linux 6.5 or later) and permission to trace owned children:

```sh
python3 scripts/run-linux-composed-caller-command-experiment.py
```

`--timeout` (default 30 seconds per case, at most 60) and `--work-dir` (an
absolute, reusable build directory) are optional. `--case` runs a subset and
produces a report that does not pass as the complete matrix. The portable report
validation runs in the repository Python tests. The live matrix is opt-in, like
the monitor experiment, and is not part of `check-linux-host.sh`.

Reports name each case's boundary, stage, durable phase, audit and reservation
counts, spawn, marker count, output byte count on the caller's stdout and cleanup. They omit paths, user names, IDs, input
text and environment values.

## Recorded evidence

On 27 October 2026, all 15 cases passed in an Ubuntu 24.04 container on a Linux
6.17 host: rootless Docker, Yama ptrace scope 1, seccomp filter mode, AppArmor
enabled, Python 3.12.3 and Swift 6.2.4. The run was an ordinary account in that
container's user namespace, not a protected installation.

## Remaining work

The preparation plan's control table is larger than this first matrix. Not yet
exercised through the composed path:

- decision controls: bad signature, expiry at consume, at its second clock
  sample and at the final check, and trust revocation (the rechecks exist, but
  no injected clock or trust change exercises them here);
- monitor controls: same-path exec, vfork, thread clone, caller exit, and the
  bad, duplicate, wrong-capture and wrong-generation acknowledgments;
- carrier controls: a separate sender, truncation and duplicate metadata;
- object controls: identical-bytes replacement of the requester or command
  executable, directory mode changes, invalid stream access or kind;
- store controls: audit-append, checkpoint-prepare and checkpoint-finalize
  failures, and crash/reopen around consume and dispatch;
- permit controls: cross-owner permits and same-submission ID or nonce reuse
  (decision and permit replay are covered in `healthy-approve`);
- injected credential, capability and NSS mismatches, and a deliberate
  self-observation negative control;
- cleanup controls: worker failure and cancellation with a live descendant.

The existing approval-command and monitor experiments cover several of these in
isolation. The in-memory permit binds the owner and capture digest; the one-use
gate is the store's dispatch token. Non-refusal failures after `beginDispatch`,
such as a command timeout, leave the request `executing` and fail the run.
Production monitor/executor ownership, protected launch, durable layout and
service activation remain separate reviewed designs.
