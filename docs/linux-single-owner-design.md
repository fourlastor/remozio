# Linux single owner for the caller stop and the spawn

Status: **approved design**, revision 3, 25 November 2026. Issue #988. Revision 2
answers the review of revision 1 (`dd8288eb`). Revision 3 adds the five items of
the approval of revision 2 (`44fb61bf`) and the split of the measurement.

[Decision 1](linux-activation-proposal.md#decisions) chose reading B: one owner
holds the caller's ptrace stop and spawns the command, so the stop cannot be lost
in the dispatch handoff ([contract](linux-host-contract.md#candidate-strict-admission-profile),
Final decision row, line 67). This document says which process is that owner,
how it starts the command, what happens when a process dies or is signalled at
each step, how the design is measured, and what stays unverified. Production
execution on Linux stays off (see [Gate](#gate)).

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
| Command child K, then command E | Forked by O; E is K after `execve` | Only the retained streams and directory |

The authority still decides and consumes. O cannot start a command without an
authority permit that is bound to O's generation, the submission nonce and C's
pidfd.

O is **single-threaded**. It is a C program with no thread library, and the one
thread that seizes C is the thread that forks K and reads the result.
`PTRACE_O_EXITKILL` is tied to that tracer thread, so it stays alive until S6.
Before the fork, O reads its own `Threads:` count from `/proc/self/status` and
refuses the dispatch if the count is not 1.

### Capabilities of O

O holds `CAP_SYS_PTRACE` to trace C under a separate UID (decision 2 text), and
`CAP_SETUID` and `CAP_SETGID` to start the command as the caller. One process must
hold all three, because a ptrace stop cannot move to another tracer, and a child
cannot gain capabilities that its parent does not have. The Linux host owner makes
the final call on this identity (see [Open decision](#open-decision)).

How O gets them:

1. The unit runs O as its dedicated service user with
   `AmbientCapabilities=CAP_SYS_PTRACE CAP_SETUID CAP_SETGID`. The ambient set
   survives the `aa-exec` step of the [monitor confinement](experiments/linux-monitor-confinement.md)
   candidate, because neither executable has file capabilities.
2. At the start of `main`, before it opens a socket, O calls
   `PR_CAP_AMBIENT_CLEAR_ALL` and `capset` with the inheritable set empty and the
   permitted and effective sets equal to exactly the three capabilities. It then
   reads the sets back with `capget` and `/proc/self/status` and exits if any set
   differs. From then on no `execve` by O or its children can pass a capability
   through the ambient or inheritable sets.
3. The unit does not reduce `CapabilityBoundingSet=`. The bounding set is inherited
   by the command, and a reduced set would break `sudo` inside the command, which
   decision 3 requires to work. The bounding set limits what a process can gain; it
   grants nothing by itself.

A compromised O is equal to Root, because `CAP_SETUID` allows `setuid(0)`.
Decision 2 already accepts that for the execution identity, and `CAP_SYS_PTRACE`
adds no new risk. The protection stays the authority's one-use permit. The
AppArmor profile still limits ptrace to the frontend label. For decision 3 it must
also let O execute commands unconfined (`ux`), so a command does not inherit the
ptrace profile. That rule is not measured yet.

### Identity of the command

O computes the target identity **before** the fork, from the approved and bound
state: the UID, the primary GID and the complete supplementary group list that the
authority resolved through `LinuxOwnAccountTargetResolver` and recorded with the
decision. K makes no user or group lookup and calls no function that is not
async-signal-safe. K uses only `setgroups`, `setresgid` and `setresuid` with the
values that O computed.

### Generation of O

The permit binds one O instance through its generation:

- the boot ID from `/proc/sys/kernel/random/boot_id`;
- O's PID and its start time (field 22 of `/proc/self/stat`);
- a 128-bit random value that O draws at start and never writes to disk.

The authority receives O's pidfd through `SO_PEERPIDFD` on O's connection and
checks that it names the PID and start time of the generation. It issues a permit
only while that pidfd is live. A restarted O has a new PID, start time and random
value, so no permit of an earlier generation is valid for it.

### Inherited state of the command

K does not pass the unit's state to the command:

- **Environment.** K calls `execve` with the environment from the approved capture,
  and nothing from O's environment. The PR1 fixture uses a fixed `LANG=C` and a
  fixed `PATH`.
- **umask.** O reads C's `Umask:` from `/proc/<pid>/status` while C is in its stop,
  and K sets that value. Commands keep the caller's file modes, as decision 3
  requires.
- **Resource limits.** O reads C's limits from `/proc/<pid>/limits` while C is in
  its stop, and K sets each soft and hard limit to the caller's value with
  `setrlimit` before the credential change. If a caller's hard limit is above O's
  own hard limit, K cannot raise it without `CAP_SYS_RESOURCE`: K then exits with a
  reserved code and O reports `notStarted`. The unit therefore sets
  `LimitNOFILE=` and the other `Limit*=` settings to the system maximum.
- **Task limit.** All commands share the unit's cgroup, so `TasksMax=` limits all
  running commands together. The unit sets `TasksMax=infinity`.
- **Session and terminal.** K calls `setsid`, so a command never shares O's
  session or process group. K cannot take the caller's terminal as its controlling
  terminal: that terminal is already the controlling terminal of the caller's
  session, and `TIOCSCTTY` refuses it. A program that opens `/dev/tty`, such as
  the `sudo` password prompt, then has no terminal. PR2 measures this case. A fix
  needs a decision (for example a terminal that the frontend relays), and this
  document does not choose one.

### Unit options

Commands inherit the unit's execution environment, so the unit must not use an
option that sets `no_new_privs` or that creates a mount namespace:

- `NoNewPrivileges=yes` breaks `sudo` inside a command. For a service user that is
  not Root, systemd also sets `no_new_privs` for `SystemCallFilter=`,
  `SystemCallArchitectures=`, `RestrictSUIDSGID=`, `RestrictNamespaces=`,
  `RestrictRealtime=`, `RestrictAddressFamilies=`, `MemoryDenyWriteExecute=`,
  `LockPersonality=`, `ProtectKernelTunables=`, `ProtectKernelModules=`,
  `ProtectKernelLogs=`, `ProtectClock=` and `ProtectHostname=`.
- `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`,
  `ReadOnlyPaths=` and the other mount options put every command in the unit's
  mount namespace.

The unit uses only `User=`, `Group=`, `AmbientCapabilities=`, `KillMode=process`,
`OOMPolicy=continue`, `TasksMax=infinity`, the `Limit*=` settings above,
`Restart=` and `ExecStart=`. PR2 measures from inside a command that `NoNewPrivs:`
in `/proc/self/status` is 0 and that the mount namespace is the host's.

### Pipes

O creates two pipes before the fork, both with `O_CLOEXEC`:

- the **go pipe**: O keeps the write end, K keeps the read end;
- the **status pipe**: K keeps the write end, O keeps the read end.

Right after the fork, O closes its copies of the go read end and the status write
end, and K closes its copies of the go write end and the status read end. Every
other descriptor of O is `O_CLOEXEC` and K closes every descriptor above 2 except
its two pipe ends. With two dispatches at the same time, each K holds only its own
pipe ends and streams. O ignores `SIGPIPE`, so a write to the go pipe of a K that
is gone returns `EPIPE` and O stays alive.

### Sequence

C stays in O's ptrace stop from S0 until S6. O never resumes C before the command
has started or the dispatch has ended without a command. Every ptrace restart call
that O makes (`PTRACE_CONT`, `PTRACE_LISTEN`, `PTRACE_DETACH` and the injection
of a signal) goes to an append-only log with a timestamp and the step, so the
measurement can read it.

1. **S0, admission.** O seizes C with `PTRACE_O_EXITKILL` and the clone, fork,
   vfork and exec events, as in the [protected launch](experiments/linux-protected-launch.md)
   design, and holds a `PTRACE_INTERRUPT` stop. It receives the carrier and sends
   the retained bundle to the authority.
2. **S1, consumption.** The authority verifies and consumes the decision, writes
   the durable `beginDispatch`, and sends O a one-use permit with the target
   identity.
3. **S2, final check.** With the stop still held, O repeats the checks of the
   Final decision row: C is in O's stop, one thread, the approved image, the
   credentials, the namespaces, the streams and the command executable.
4. **S3, prepared child.** O forks K. K, in this order:
   1. resets every signal handler to the default and clears its signal mask;
   2. calls `PR_SET_DUMPABLE(0)`;
   3. closes the descriptors described above, moves the retained streams to 0–2
      and calls `fchdir` to the retained directory;
   4. calls `setgroups` with the computed list, `setresgid(gid, gid, gid)` and
      `setresuid(uid, uid, oUid)`, where `oUid` is O's service UID. The saved UID
      lets O send K a signal before the go byte without `CAP_KILL`;
   5. calls `PR_SET_DUMPABLE(0)` again, because a credential change resets the
      flag to the value of `fs.suid_dumpable`;
   6. calls `PR_CAP_AMBIENT_CLEAR_ALL` and `capset` with every set empty, reads
      the sets back with `capget`, and exits with a reserved code without
      `execve` if any set is not empty. A UID change between two non-zero UIDs
      clears no capability by itself, so this step is required;
   7. blocks on one `read` of the go pipe.
5. **S4, go.** O waits for K to be blocked on the go pipe or gone, with a deadline.
   It checks once more that C is still in its stop and that the permit is unused,
   then writes one byte with the expected value to the go pipe and closes it.
   - If the write returns `EPIPE`, K is gone: O reports `notStarted`.
   - If the deadline passes before the write (K is stopped, slow or hung), O sends
     `SIGKILL` to K through K's pidfd, which the saved UID allows, and reports
     `notStarted`.
6. **S5, exec.** In K, only a read that returns exactly one byte with the expected
   value lets K continue. Any other result (end of file, a different byte,
   `EINTR`, an error) makes K exit with a reserved code without `execve`. K then
   calls `setresuid(uid, uid, uid)` and `execve`. If `execve` fails, K writes the
   errno to the status pipe and exits with a reserved code.
7. **S6, result and report.** O waits on the status pipe and K's pidfd together,
   with a deadline, and decides:

   On end of file, O calls `waitid` on K's pidfd with `WEXITED | WNOHANG |
   WNOWAIT`, which reads K's state without reaping it. Before `execve`, K exits
   only with its reserved codes, so:

   | Status pipe | K | Result |
   | --- | --- | --- |
   | End of file | Still alive | `dispatched`: the close-on-exec write end closed, so `execve` succeeded |
   | End of file | Exited normally with a code that is not reserved | `dispatched`: the command ran and already exited |
   | Errno record | Exited with the reserved code | `execFailed` with that errno |
   | End of file, no errno record | Exited with a reserved code, or killed by a signal | `unknown`: K died between the go byte and `execve`, or the command used that code or died by a signal |
   | Nothing before the deadline | Alive | `unknown`; O cannot signal K after the last `setresuid` |

   A K that dies also closes the write end, a short time before its exit status is
   ready, so "still alive" alone does not prove `execve`. O therefore compares
   `/proc/<pid>/exe` of K with its own image. A different image means `execve`
   succeeded. The same image, or none (K is exiting), makes O wait for K's exit
   status until the deadline and use the other rows.

   After the result, O checks C again. If C is gone, O records
   `requesterLostAfterCheck: true` with the result. Then O reports to the
   authority, and only then does the
   [post-dispatch contract](linux-host-contract.md#candidate-strict-admission-profile)
   (Exit and monitor loss row) apply to C. That contract is not changed here.

### The requester can still be lost

C's real UID is the caller, so a process of the caller can send `SIGKILL` to C at
any time, also while C is in O's stop. If that happens after the S4 check, the
command still starts. This is not a loss of the stop: O never resumed C, and C
never ran after its final check. It is the caller ending its own frontend at the
moment of dispatch. O detects it in S6 and records `requesterLostAfterCheck: true`.
The design does not prevent it, because no process can block `SIGKILL` to its own
UID's processes.

### The command's cgroup

Every command runs in the cgroup of `remozio-exec.service`. With the default
`KillMode=control-group`, a unit stop, a restart after O dies, or
`OOMPolicy=stop` would kill every running command. The unit sets:

- `KillMode=process`: a unit stop or restart ends only O. Running commands keep
  running, and systemd reports them as left-over processes of the unit.
- `OOMPolicy=continue`: an out-of-memory kill of one process does not stop the
  unit or kill the other commands.

Commands then share the unit's cgroup and its resource accounting. A separate
scope per command needs PID 1 and changes the decision 3 design, so it is not
proposed here.

### When the owner dies

O dies means any end of O: crash, kill, unit stop or out of memory. C always dies
with it, through `PTRACE_O_EXITKILL`. The authority records each case below as
`unknown` unless O reported first, because it cannot see O's local state.

| O dies | C | Command |
| --- | --- | --- |
| Before S1 (no permit) | Killed | Never starts; the authority refuses or rolls back, as today |
| After S1, before the fork | Killed | Never starts: only O can spawn, and the permit is bound to O's generation |
| After the fork, before the go byte | Killed | Never starts: K reads end of file on the go pipe and exits without `execve` |
| After the go byte, before S6 | Killed | May have started, once; the same ambiguous dispatch as on the Mac |
| After S6 | Killed, or already under the post-dispatch contract | Keeps running (`KillMode=process`) |

### When other processes die or receive signals

- **Authority dies after S1.** O holds the permit. O may finish S2–S6 and keep the
  report until the authority returns, or abandon before S4. An abandoned dispatch
  never writes the go byte. O never retries after an uncertain go.
- **K dies or is signalled before the go byte.** A `SIGSTOP` makes O miss the
  deadline and kill K. A `SIGTERM` or `SIGUSR1` ends K, because its handlers are
  the defaults. In every case O reports `notStarted` and no command runs.
- **K is signalled between the go byte and `execve`.** A fatal signal gives
  `unknown` (row 3 of the S6 table). A `SIGSTOP` gives `unknown` at the deadline.
- **C exits during S2–S4.** O sees the exit through ptrace before the go byte,
  never writes it and reports a refusal. The permit stays consumed and unused.
- **C exits after the S4 check.** See [The requester can still be lost](#the-requester-can-still-be-lost).

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
to the protected launch monitor. A keeps decision verification, the SQLite
transaction and the permit. R injects the faults. Every case records the authority
outcome, the marker count and O's restart log.

| Case | Expected result |
| --- | --- |
| Kill O at S1, after the fork, before the go byte | C killed, no command, marker count 0 |
| Kill O after the go byte, after S6 | C killed; marker count at most 1; after S6 the command keeps running |
| Kill the authority after S1 | No go byte without a permit; no retry |
| `SIGCONT` from the caller's account to C during the stop | C stays in the stop; the command starts once |
| `SIGKILL` to C from the caller's account just after the S4 check, and just after the go byte | Command starts once; `requesterLostAfterCheck: true` |
| `SIGSTOP`, `SIGTERM`, `SIGUSR1` from the caller's account to K before the go byte | `notStarted`, no command |
| The same signals to K between the go byte and `execve` | `unknown` (fatal signal, or `SIGSTOP` at the deadline) |
| Kill K before the go byte | `notStarted`, no command |
| Kill K between the go byte and `execve` | `unknown`, no command |
| A K that hangs before the go byte | O kills K at the deadline, `notStarted`; C stays stopped until then |
| A multi-threaded O (a test build that starts a thread) | O refuses before the fork |
| Attach to K from the caller's account with `fs.suid_dumpable=1` and Yama `ptrace_scope=0` | Refused, before and after the go byte |
| `CapPrm`, `CapEff`, `CapInh`, `CapAmb`, `CapBnd` of the command under the installed unit, and of a `sudo` child of the command | Command: all empty except `CapBnd`, which is the full system set; the `sudo` child gets Root's normal sets |
| O's descriptor table after the fork, with two dispatches at the same time | Each K holds only its streams and its own two pipe ends; O holds only its own ends |
| Unit stop, unit restart and an out-of-memory kill while a command runs after S6 | The command keeps running |
| AppArmor: O under the confinement profile with the `ux` rule | The command runs unconfined, and `sudo` works inside it |
| The fixture's `dispatch-race-limitation` case | No command for every O death before the go byte |

C cannot fork or execute during S2–S4, because it does not run in the stop. The
`SIGCONT` row replaces the earlier row about a fork or `execve` by C: a
`SIGCONT` is the one signal from the caller's account that could end a group stop,
and it must not end O's ptrace stop.

### Cases in PR1

`scripts/run-linux-single-owner-experiment.py` runs these rows with the stub
authority. It needs Root through `sudo`, but no systemd unit, no AppArmor profile
and no sysctl change by default. The
[experiment document](experiments/linux-single-owner.md) lists each case.

- Kill O at S1, after the fork, before the go byte, after the go byte and after S6.
- Kill the authority after S1.
- `SIGCONT` from the caller's account to C during the stop.
- `SIGKILL` to C from the caller's account before the S4 check, just after it, and
  just after the go byte.
- `SIGSTOP`, `SIGTERM` and `SIGUSR1` from the caller's account to K, before the go
  byte and between the go byte and `execve`.
- Kill K before the go byte, and between the go byte and `execve`.
- A K that hangs before the go byte.
- A multi-threaded O.
- A caller hard limit above O's own: K reports the limit step and nothing starts.
- The capability sets, `NoNewPrivs:`, the identity, the supplementary groups, the
  umask, every limit and the session of the command, with O started through `setpriv` with the three
  capabilities in its ambient set, as `AmbientCapabilities=` would. The `sudo`
  child is PR2.
- Attach to K from the caller's account: only with `--allow-sysctl`, which saves
  both values, sets `fs.suid_dumpable=1` and `ptrace_scope=0`, and restores them.
  Without the flag the report says `not-run`.
- Three more controls: a command that exits before O looks, a command that is still
  alive at S6, and a command that `execve` cannot find.

PR2 runs the other rows: the descriptor table with two dispatches at the same
time, the unit stop, restart and out-of-memory kill, AppArmor, the composed
fixture's `dispatch-race-limitation` case and the `sudo` child.

O's restart log is the evidence that C never left its stop between S0 and the go
byte: the check requires no restart call for C in that interval. A `/proc` sample
cannot prove "never". The tracer PID, when the experiment reads it as a second
check, comes from `TracerPid:` in `/proc/<pid>/status`. The report sets
`strictAdmission` to true only when every case passes.

## Not verified

The measurement is split in two pull requests. PR1 uses a stub authority (a
one-use permit bound to O's generation and the nonce, and `beginDispatch` and the
outcome in a file), so its report keeps `strictAdmission` and `productionAdmission`
false. PR2 composes O with the Swift authority of the composed fixture and adds the
systemd unit. Only PR2 can set `strictAdmission` to true. Until PR2:

- the signed decision, the SQLite transaction and the real authority;
- the unit options, `NoNewPrivs:` and the mount namespace inside a command;
- `sudo` with a password prompt, and the controlling terminal;
- the AppArmor `ux` rule, `KillMode=process` and `OOMPolicy=continue`.

Also not verified, in either pull request:

- Every result comes from one host and one kernel until a second host repeats it.
- The `ux` rule in the AppArmor profile and the stacked label under systemd.
- An installed systemd unit, the installer setting and upgrade from an older unit.
- `KillMode=process` and `OOMPolicy=continue` with real commands that run for a
  long time, and the left-over process warnings on restart.
- A target identity of Root. The command then gets Root's normal capability sets
  through `execve`, as any Root process does.
- More than one local account (decision 7) and TPM use (decision 4).
- The limit accepted in decision 2: a Root process that runs the installed frontend
  also gets the frontend label.
- The post-dispatch contract for C after S6.

## Open decision

For the Linux host owner: approve one execution identity with `CAP_SYS_PTRACE`,
`CAP_SETUID` and `CAP_SETGID`, in place of a monitor identity and an execution
identity. Reading B needs one process that holds the stop and spawns, and the
kernel does not let a ptrace stop move between processes. The review of revision 1
accepts this identity.

## Alternatives not chosen

- **Separate monitor and executor with a handshake.** This is reading A. The stop
  can still be lost between the two processes.
- **A set-user-ID helper started by the monitor.** It adds a new privileged
  executable on the host.
- **The monitor also traces the prepared command child.** The confinement profile
  allows ptrace only to the frontend label, and the child would need a second peer
  rule.
- **`PR_SET_PDEATHSIG` in K.** The kernel clears it on a credential change, and
  once set again after the change it would kill the command when O exits later.
- **O started as UID 0 that drops to its service UID with `PR_SET_KEEPCAPS`.** It
  gives the same result as the ambient set that O clears at start, but O would run
  as Root for its first instructions.
