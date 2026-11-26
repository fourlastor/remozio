# Linux single-owner experiment

This experiment is PR1 of the measurement in the
[Linux single-owner design](../linux-single-owner-design.md) (issue #988). One
owner process O holds the caller's ptrace stop and starts the command through a
prepared child K. PR1 uses a stub authority. It does not install a service,
approve a real decision, change the [contract](../linux-host-contract.md), or turn
on production execution. Its report keeps `strictAdmission` and
`productionAdmission` false.

**Recorded result: passed on one host, 2026-11-25** (see
[Recorded result](#recorded-result)). CI compiles the fixtures and runs the tests
that need no Root.

## Fixtures

The fixtures are in `experiments/linux-single-owner/`:

- `owner.c` is O. It is single-threaded. At start it clears its ambient and
  inheritable sets and checks with `capget` and `/proc/self/status` that its
  permitted and effective sets are exactly `CAP_SYS_PTRACE`, `CAP_SETUID` and
  `CAP_SETGID`. Its generation is the boot ID, its PID, its start time and a 128-bit
  random value. It seizes C with `PTRACE_O_EXITKILL` and the clone, fork, vfork and
  exec events, holds a `PTRACE_INTERRUPT` stop, and writes every ptrace request and
  the go byte to an append-only log. K follows the S3 to S5 steps of the design. O
  reports to the runner on stdout, one JSON line for its start and one for the
  dispatch, with closed-set values only.
- O logs `GO` only after the go byte reached the pipe. A failed or short log write
  sets `restartLogComplete` to `no`, and every admitted case then fails: an
  incomplete log proves nothing about the stop.
- If K fails a setup step before it reports ready, it writes the step (limits,
  credentials, capabilities, other) to the status pipe before it exits. O reports
  it as `kSetup`, so a refused limit is a visible setup failure and not a silent
  `notStarted`.
- `frontend.c` is C. It sets umask `027` and a soft `RLIMIT_NOFILE` of 777, sends a
  fixed hello and its three standard descriptors, and blocks until O closes the
  connection.
- `probe.c` is the command. It appends one line to a marker file and prints its
  capability sets, `NoNewPrivs:`, IDs, supplementary groups, umask, all 16 limits,
  session and dumpable value. The runner reduces these values to booleans: the
  groups must equal the permit's groups, and the limits must equal C's limits as
  the runner read them at `s1`.

O stops at named barriers and waits for the runner on a control socket: `start`,
`s1`, `after-fork`, `k-ready`, `before-go`, `after-check`, `after-go`, `k-paused`
(K, between the go byte and `execve`), `after-s6` and `end`. At a barrier the
runner injects the fault of the case.

Two build options exist for tests only. `RMZSO_TEST_THREAD` starts a second thread
in O, so O must refuse before the fork. `RMZSO_FIXTURE_UNPRIVILEGED` (O) and
`RMZSO_FIXTURE_PTRACER` (C) let the tests run every case as one account, without
capabilities. Those runs prove the protocol and the evaluation. They do not measure
the design. The tests also start the measurement build of O without capabilities,
so `owner-without-capabilities` runs without Root too. `RMZSO_LIMITS_SELFTEST` adds
a mode that parses a saved `/proc/<pid>/limits` file, so a test compares O's parser
with the runner's on a captured sample.

## Stub authority

The runner is the authority. It accepts O's hello only when the pidfd from
`SO_PEERPIDFD` names the PID of the generation and that PID has the generation's
start time and boot ID. It issues one permit per case, bound to that connection's
generation and to the nonce, and records `beginDispatch` and the outcome in a
file. A second outcome for the same permit is refused.

## Run

```sh
sudo python3 scripts/run-linux-single-owner-experiment.py [--timeout 15] [--allow-sysctl]
```

The runner refuses to run unless it is Root through `sudo` from an ordinary
account. It creates a disposable system user `rmzso<tag>` and a directory under
`/var/lib`, starts O as that user through
`setpriv --reuid --regid --clear-groups --inh-caps --ambient-caps` with the three
capabilities (this emulates `AmbientCapabilities=`), and starts C and the
caller-side faults as the operator account. Before `setpriv`, Root sets every limit
of O to its maximum (unlimited, and `RLIMIT_NOFILE` at `fs.nr_open`), as the unit's
`Limit*=` settings will. O has no `CAP_SYS_RESOURCE`, so K can set a caller limit
only when O's hard limit is at least as high. Each case records
`ownerLimitsCoverCaller`. Cleanup runs in `finally` blocks, also
when a case fails or the operator cancels: it kills every process of the
disposable user and waits until none is left, removes the directory, the user and
its group, and restores any sysctl that it changed.

`--allow-sysctl` runs the attach case. The runner saves `fs.suid_dumpable` and
`kernel.yama.ptrace_scope`, sets them to 1 and 0, and restores them after the case.
Without the flag the case reports `not-run` and no sysctl changes.

## Cases

| Case | Fault | Expected |
| --- | --- | --- |
| `dispatch-normal` | None | `dispatched`, marker 1, capability sets empty, `NoNewPrivs: 0`, caller IDs, umask and `RLIMIT_NOFILE` inherited, session leader |
| `dispatch-short-command` | The command exits at once | `dispatched`, marker 1 |
| `dispatch-command-alive-at-s6` | The command sleeps | `dispatched`, marker 1 |
| `exec-fails` | The command path does not exist | `execFailed` with `ENOENT`, marker 0 |
| `k-hangs-before-go` | K never reports ready | O kills K at the deadline, `notStarted`, marker 0 |
| `kill-k-before-go` | Root kills K at `k-ready` | `notStarted`, marker 0 |
| `caller-sigstop-k-before-go` | `SIGSTOP` from the caller to K at `k-ready` | Killed at the deadline, `notStarted` |
| `caller-sigterm-k-before-go` | `SIGTERM` from the caller to K at `k-ready` | `notStarted` |
| `caller-sigusr1-k-before-go` | `SIGUSR1` from the caller to K at `k-ready` | `notStarted` |
| `kill-k-after-go` | Root kills K at `k-paused` | `unknown`, marker 0, K ended by `SIGKILL` |
| `caller-sigstop-k-after-go` | `SIGSTOP` from the caller to K at `k-paused` | `unknown` at the deadline, K stopped |
| `caller-sigterm-k-after-go` | `SIGTERM` from the caller to K at `k-paused` | `unknown`, K ended by `SIGTERM` |
| `caller-sigusr1-k-after-go` | `SIGUSR1` from the caller to K at `k-paused` | `unknown`, K ended by `SIGUSR1` |
| `caller-sigcont-c-during-stop` | `SIGCONT` from the caller to C at `s1` and `before-go` | C stays in the stop, `dispatched` once |
| `caller-kills-c-before-check` | `SIGKILL` from the caller to C at `before-go` | Refusal, `requesterLostBeforeCheck`, marker 0 |
| `caller-kills-c-after-check` | `SIGKILL` from the caller to C at `after-check` | `dispatched` once, `requesterLostAfterCheck` |
| `caller-kills-c-after-go` | `SIGKILL` from the caller to C at `after-go` | `dispatched` once, `requesterLostAfterCheck` |
| `kill-owner-at-s1` | Root kills O at `s1` | C killed, no outcome, marker 0 |
| `kill-owner-after-fork` | Root kills O at `after-fork` | C killed, K ends without `execve`, marker 0 |
| `kill-owner-before-go` | Root kills O at `before-go` | C killed, K exits with a reserved code, marker 0 |
| `kill-owner-after-go` | Root kills O at `after-go` | C killed, marker at most 1 |
| `kill-owner-after-s6` | Root kills O at `after-s6` | C killed, the command keeps running |
| `kill-authority-after-s1` | The runner closes O's authority connection at `s1` | O holds the permit, the command starts once, no report |
| `runner-lost-before-go` | The runner stops answering at `before-go` | O kills K, `notStarted`, no `PTRACE_DETACH`, O exits and C dies with it |
| `runner-lost-after-go` | The runner stops answering at `after-go` | `dispatched` once, no `PTRACE_DETACH`, O exits and C dies with it |
| `owner-thread-refused` | O built with a second thread | `ownerThreads` before the fork, marker 0 |
| `caller-limit-above-owner` | O's hard `RLIMIT_NOFILE` below the caller's | `ownerLimitsCoverCaller` no, `kSetup` limits, `notStarted`, marker 0 |
| `owner-without-capabilities` | O started with no ambient capabilities | O refuses at start |
| `caller-attaches-to-k` | `PTRACE_ATTACH` from the caller to K before and after the go byte; `--allow-sysctl` only | `EPERM` both times, K not dumpable at each attempt |

Every case records O's exit, C's exit, the marker count, the authority's
`beginDispatch` and outcome, and whether O's restart log shows a restart call
before the go byte.

In `kpause` mode K pauses after the go byte, so `unknown` and marker 0 hold whether
or not a signal acted. Two values make those four cases able to fail: `kEnd`, how
K ended as O sees it at the end of the dispatch, and `kStateAfterSignal`, which the
runner reads from `/proc` just after the signal (`stopped` for `SIGSTOP`, `gone` for
a fatal signal). A test sends no signal and checks that each case then fails.

"C never left the stop" does not rest on O's log only. At `s1` and at `after-go` the
runner reads C's run time (`/proc/<pid>/schedstat`), its context-switch counts and
its `TracerPid:` from `/proc/<pid>/status`. Every case that writes the go byte
requires the counters to be unchanged and O to be the tracer at both reads
(`cRunUnchanged`, `cTracerOwner`). The `SIGCONT` case passes this check. When O is
killed it cannot report its log writes, so the runner checks that every log line is
whole and well formed (`restartLogComplete`); the cases that kill O require it.

The report splits the loss of C: `requesterLostBeforeCheck` when C left the stop
at or before the last check, and `requesterLostAfterCheck` when C was gone after
the go byte. The design's other rows (two dispatches at the same time, the
unit, AppArmor, the `sudo` child and the composed fixture's race case) are PR2.

## Recorded result

**Passed on one host, 2026-11-25**
([evidence](linux-single-owner-evidence.json)): Ubuntu 25.10, kernel `6.17.0-41`,
x86_64, `ptrace_scope` 1, `suid_dumpable` 2, AppArmor enabled with its unprivileged
user namespace restriction on. The Linux host owner was present, and the runner ran
as Root through classic sudo with `--allow-sysctl`. Every setup check, all 29
cases and every cleanup check passed, and both sysctls were restored
(`sysctlsRestored`). The source, binary and script hashes in the evidence match the
fixtures and the runner in this change. `strictAdmission` and `productionAdmission`
are false.

- **Dispatch:** `dispatch-normal`, `dispatch-short-command`,
  `dispatch-command-alive-at-s6` and `caller-sigcont-c-during-stop` gave
  `dispatched`; `exec-fails` gave `execFailed`. In every case that wrote the go
  byte, C's run time, context switches and `TracerPid` were unchanged between `s1`
  and `after-go`, and the restart log was clean and complete.
- **Refusals before the go byte:** the K signal and kill cases, `k-hangs-before-go`,
  `runner-lost-before-go` and `caller-limit-above-owner` gave `notStarted` with no
  go byte written. `owner-thread-refused` gave `ownerThreads`, and
  `owner-without-capabilities` refused at start.
- **After the go byte:** each K signal case ended K with that signal (`SIGSTOP`
  left K stopped), and the owner, authority and runner loss cases reported as
  required.
- **Attach (`caller-attaches-to-k`):** with `ptrace_scope` 0 and `suid_dumpable` 1
  set for the case, the caller's attach failed with `EPERM` before and after the go
  byte, and K was not dumpable at both attempts.

A first run on the same day measured every case as required except the attach
case's dumpable sample, which read 1 while both attach attempts failed with `EPERM`.
The runner read the owner of the `/proc/<pid>` directory, which always shows the
task's effective UID. It now reads `/proc/<pid>/stat`, which belongs to root when
the task is not dumpable. The recorded evidence is the second run.

## Implementation notes

- O ends its dispatch with `PTRACE_DETACH` after S6 when C is still there and the
  runner answered the `after-s6` barrier. The post-dispatch contract is not part of
  PR1.
- If the runner does not answer a barrier, O is no longer supervised. Before the go
  byte it kills K and reports `notStarted`. After the go byte it cannot stop the
  command. In both cases it makes no further restart call and exits, so C dies with
  it through `PTRACE_O_EXITKILL`.
- Every path of a dispatch ends at one cleanup step. It sends the outcome once when a
  permit exists and closes every descriptor that the dispatch opened.
- O's socket for C is mode `0660` and belongs to the operator's primary group, so
  only that group can connect. The permit carries at most 64 supplementary groups;
  the runner refuses an operator account with more before it changes anything.
- A cancel (Ctrl-C, `SIGTERM`, `SIGHUP`) during a case still kills and reaps O, C,
  K and the command, also when the command runs as the operator account.
- The S6 end-of-file row checks `/proc/<pid>/exe` of K before it accepts "still
  alive" as `dispatched`, as the design now states. Without that check a K that
  dies between the go byte and `execve` could be read as `dispatched`.
- O's stop check does not take a queued stop report from C. It calls `waitid` with
  `WNOWAIT`, which shows a pending event and leaves it queued. It takes (reaps) the
  event only when C has exited. Then it reads `/proc/<pid>/status`: state `t`, O as
  `TracerPid` and one thread.
- O also checks that the pidfd from `SO_PEERPIDFD` names the PID from
  `SO_PEERCRED`, as the protected launch does, and refuses the connection if not.
  O seizes by PID number, so after the interrupt stop it sends signal 0 through the
  pidfd. Success, or `EPERM` (O has no `CAP_KILL` over C), proves that the connected
  process still lives and so still holds the PID. `ESRCH` means the PID could have
  been reused, and O refuses. No test makes a PID reuse happen.
- Right after `useradd`, the runner refuses to continue when a process already runs
  with the new UID (for example a container without a user namespace). Cleanup then
  kills nothing by UID.
- The runner reads files in directories that the operator or the caller can write
  (the markers, and also the restart log) with `O_NOFOLLOW|O_NONBLOCK`, accepts only
  a regular file, and reads at most 64 KiB.
- If the attach sysctls cannot be set (no Yama, `ptrace_scope` 3, a refused write),
  the runner restores what it wrote, records the attach case as `not-run` with the
  reason, and keeps every other result.
- The runner compiles a private copy of each source and reports the SHA-256 of that
  copy and of each built binary (`builds`), plus the hashes of the two runner
  scripts at start (`scripts`).
- When O reports `dispatched` for a command that is still running, the runner waits
  until the command ends before it reads the marker.
- Cleanup kills K through a pidfd that the runner opens when K's PID first reaches
  it, and also ends O's session. Before its `setsid()` K is still in O's session,
  so killing only K's own session would miss a K that stops there.
- O's listening sockets are bound at mode `0600`, given their group, and only then
  set to `0660`.
- After the result, O also checks C again. A dispatch that ends without a command
  (`notStarted`) also releases C after S6.
- The report publishes booleans, categories and errno names only. PIDs, UIDs and
  paths go only between O and the runner.

## Not verified

- Every item that the design lists for PR2: the Swift authority, the systemd unit,
  AppArmor, `sudo` and the controlling terminal.
- One Root run on one host and one kernel. Other kernels and distributions are not
  measured.
- Cleanup also kills by session ID (K's and O's), after a pidfd kill of K. If the
  session leader was reaped first, a kill by that session ID could reach a new
  session only after a PID wrap. This risk is accepted.
