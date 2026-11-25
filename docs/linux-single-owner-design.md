# Linux single owner for the caller stop and the spawn

Status: **design for review**, 25 November 2026. Issue #988. No code yet.

[Decision 1](linux-activation-proposal.md#decisions) chose reading B: one owner
holds the caller's ptrace stop and spawns the command, so the stop cannot be lost
in the dispatch handoff ([contract](linux-host-contract.md#candidate-strict-admission-profile),
Final decision row, line 67). This document says which process is that owner,
what happens when it dies at each step, how the design is measured, and what stays
unverified. Production execution on Linux stays off (see [Gate](#gate)).

## The problem in the composed fixture

In the [composed fixture](experiments/linux-composed-caller-command.md#contract-line-67-and-the-dispatch-race)
two processes share the handoff. M holds the caller's stop and A spawns the
command. If M dies after A's last check, `PTRACE_O_EXITKILL` ends C, but A still
spawns. The fixture records that case as `unknown` with
`requesterLostDuringDispatch: true`. It detects the loss but cannot prevent it,
because no primitive spans M's liveness and A's `posix_spawn`.

## Design

### One owner process

The owner O is one process that is both the ptrace tracer of the frontend C and
the parent of the command. It takes the place of M and of the spawning part of A.

| Role | Process | Owns |
| --- | --- | --- |
| Authority | `remozio-authority.service`, no capabilities (unchanged) | Decision verification, atomic consumption, durable `beginDispatch`, one-use dispatch permit, outcome record |
| Owner O | `remozio-exec.service`, the execution identity of decision 2 | Trace of C from protected launch, the submission carrier, the final check, the spawn, the report to the authority |
| Frontend C | `/usr/libexec/remozio/remozio` (decision 5, unchanged) | One bounded submission with its streams |
| Command E | Started by O as the caller | Only the retained streams and directory |

The authority still decides and consumes. O cannot start a command without an
authority permit that is bound to O's generation, the submission nonce and C's
pidfd.

### Capabilities

O needs `CAP_SYS_PTRACE` to trace C under a separate UID (decision 2 text) and
`CAP_SETUID` and `CAP_SETGID` to start the command as the caller. One process must
hold all three, because a ptrace stop cannot move to another tracer and a child
cannot gain capabilities that its parent does not have.

This changes the layout of decision 2: the monitor candidate identity and the
execution identity become one identity. It does not change the risk that decision
2 accepted. A compromised execution service is already equal to Root, because
`CAP_SETUID` allows `setuid(0)`. `CAP_SYS_PTRACE` adds nothing to that case. The
protection stays the authority's one-use permit. **This is a decision for the
Linux host owner** (see [Open decision](#open-decision)).

The [monitor confinement](experiments/linux-monitor-confinement.md) AppArmor
profile still limits ptrace to the frontend label. O starts through `aa-exec`, as
the measured candidate does. For decision 3 (unsandboxed commands) the profile
must let O execute commands unconfined (`ux`), so a command does not inherit the
ptrace profile. That rule is not measured yet.

No capability reaches a command. The unit sets no `AmbientCapabilities=`, and the
command child calls `setgid`, `initgroups` and `setuid` before `execve`.

### Sequence

C stays in O's ptrace stop from S0 until S5. O never releases the stop before the
command has started or the dispatch is proven not to happen.

1. **S0, admission.** O seizes C with `PTRACE_O_EXITKILL` and the clone, fork,
   vfork and exec events, as in the [protected launch](experiments/linux-protected-launch.md)
   design, and holds a `PTRACE_INTERRUPT` stop. It receives the carrier and sends
   the retained bundle to the authority.
2. **S1, consumption.** The authority verifies and consumes the decision, writes
   the durable `beginDispatch`, and sends O a one-use permit.
3. **S2, final check.** With the stop still held, O repeats the checks of the
   Final decision row: C is in O's stop, one thread, the approved image, the
   credentials, the namespaces, the streams and the command executable.
4. **S3, prepared child.** O forks the command child K. K calls `setgid`,
   `initgroups` and `setuid` for the caller, `fchdir` to the retained directory,
   moves the retained streams to 0–2 and closes every other descriptor except two
   pipes: a **go pipe** (read end) and a close-on-exec **status pipe** (write
   end). K then blocks on one read of the go pipe. K does not use
   `PR_SET_PDEATHSIG`: the kernel clears it when K changes credentials, and once
   set again it would kill the command when O exits later.
5. **S4, go.** O checks once more that C is still in its stop and that the permit
   is unused, then writes one byte to the go pipe and closes it. K calls `execve`.
   O reads the status pipe: end of file means the exec succeeded, an errno record
   means it failed.
6. **S5, report.** O reports `dispatched` (with the command pidfd) or
   `execFailed` (with the errno) to the authority. Only then does the
   [post-dispatch contract](linux-host-contract.md#candidate-strict-admission-profile)
   (Exit and monitor loss row) apply to C. That contract is not changed here.

### When the owner dies

O dies means any end of O: crash, kill, unit stop or out of memory. C always dies
with it, through `PTRACE_O_EXITKILL`, so C never runs outside a stop after its
final check.

| O dies | C | Command | Authority outcome |
| --- | --- | --- | --- |
| Before S1 (no permit) | Killed | Never starts | Refused or rolled back, as today |
| After S1, before S3 | Killed | Never starts: only O can spawn, and the permit is bound to O's generation | `unknown` (the authority cannot see that no fork happened) |
| During S3 or S4 before the go byte | Killed | Never starts: K reads end of file on the go pipe and exits without `execve` | `unknown`, no command ran |
| After the go byte, before the S5 report | Killed | May have started, once | `unknown`, the same ambiguous dispatch as on the Mac |
| After S5 | Killed or under the post-dispatch contract | Running or finished | `dispatched`, then the post-dispatch rules |

The rows marked `unknown` before the go byte never start a command. The authority
records them as `unknown` because it cannot prove that from its own state. A later
change can let a restarted O prove "no go byte written" through a durable marker,
but that is not needed for line 67.

The case that the fixture could not prevent, a spawn after the requester is gone,
is now limited to the last row before S5. There the go byte was written while O
still held the stop, so the final check and the start of the command were not
separated by any interval in which C could run.

### When other processes die

- **Authority dies after S1.** O holds the permit. O may finish S2–S5 and keep the
  report until the authority returns, or abandon before S4. An abandoned dispatch
  never writes the go byte. O never retries after an uncertain go.
- **K dies before the go byte.** O sees end of file on the status pipe without an
  exec and reports `execFailed`. No command ran.
- **C exits or changes during S2–S4.** O sees the ptrace event, never writes the go
  byte and reports a refusal. The permit stays consumed and unused.

## Gate

There is no runtime flag today because there is no Linux production executor. The
repository has only opt-in experiments, and their reports keep
`productionAdmission` and `strictAdmission` false. The activation proposal (decision
1) states that production execution stays off until this design is measured.

The first production executor change must keep execution off by default: the
installer does not install or enable `remozio-exec.service` until the measurement
below passes and the Linux host owner turns it on. That change names the setting
in the installer and in this document.

## Measurement

A new opt-in experiment, built from the composed fixture, with O written in C next
to the protected launch monitor:

1. Replace M and the spawn in A with O. A keeps decision verification, the SQLite
   transaction and the permit.
2. Fault injection by R at named barriers: kill O at S1, S2, after the fork,
   before the go byte, after the go byte and after S5; kill the authority after S1;
   kill K before the go byte; make C fork or exec during S2–S4.
3. For every case, check: C never left the stop between S2 and its death (R samples
   `/proc/<pid>/stat` state and the tracer field), the marker count is 0 for every
   death before the go byte and at most 1 after it, and the authority outcome
   matches the table.
4. AppArmor: O under the confinement profile with the `ux` rule. Check that the
   command runs unconfined, that `sudo` works inside it (no `no_new_privs`), and
   that the command starts with an empty capability set.
5. Repeat the `dispatch-race-limitation` case. With O it must now end with no
   command for every death before the go byte. The report sets `strictAdmission`
   to true only when all cases pass.

## Not verified

- Every result comes from one host and one kernel until a second host repeats it.
- The `ux` rule in the AppArmor profile and the stacked label under systemd.
- An installed systemd unit, the installer setting and upgrade from an older unit.
- More than one local account (decision 7) and TPM use (decision 4).
- The limit accepted in decision 2: a Root process that runs the installed frontend
  also gets the frontend label.
- The post-dispatch contract for C after S5.

## Open decision

For the Linux host owner: approve one execution identity with `CAP_SYS_PTRACE`,
`CAP_SETUID` and `CAP_SETGID`, in place of a monitor identity and an execution
identity. Reading B needs one process that holds the stop and spawns, and the
kernel does not let a ptrace stop move between processes.

## Alternatives not chosen

- **Separate monitor and executor with a handshake.** This is reading A. The stop
  can still be lost between the two processes.
- **A set-user-ID helper started by the monitor.** It adds a new privileged
  executable on the host.
- **The monitor also traces the prepared command child.** The confinement profile
  allows ptrace only to the frontend label, and the child would need a second peer
  rule.
