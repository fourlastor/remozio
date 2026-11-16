# Linux monitor confinement experiment

This experiment measures a confinement for the monitor of the adopted
[decision 5 design](../linux-activation-proposal.md#decisions). That monitor keeps only
`CAP_SYS_PTRACE`, and the capability can trace any process on the host, Root processes
included. The candidate for
[decision 2](../linux-activation-proposal.md#decisions) needs a confinement to the
frontend peer before production. This experiment measures one: an AppArmor policy.
It does not choose decision 2, install a service, approve or execute a command, or
change the [contract](../linux-host-contract.md). Production execution stays off.

**Recorded result: not yet run.** The fixtures, the policy and the runner are ready;
the supervised Root run is pending (see [Recorded result](#recorded-result)).

## Question

Can an AppArmor policy limit a process that holds `CAP_SYS_PTRACE` so that:

- its ptrace-mediated access (`PTRACE_SEIZE`, `process_vm_readv`/`writev`,
  `pidfd_getfd`, ptrace-checked procfs entries) reaches only processes that run the
  installed frontend image;
- it cannot create or write files, execute a program or open an IP socket;
- the #728 monitor still admits the installed frontend with every check passing?

**The known limit.** AppArmor attaches the frontend profile to the installed path, so
the policy confines by program, not by user. Every process that runs the installed
frontend carries the frontend label: the operator's, another user's, and one that
Root starts. A confined monitor can trace all of them. Case N7c records this with a
Root-started frontend. Candidate mitigations (the frontend exits at once when its
real UID is 0, and an operator rule) are for the Linux host owner to decide; this
experiment measures the limit only.

## Why AppArmor

- **Yama** adds an ancestry rule for tracers without `CAP_SYS_PTRACE`; with the
  capability it does not restrict the target.
- **Landlock** lets a sandboxed tracer reach only processes in its own or a nested
  Landlock domain. The frontend is in neither, and the rule cannot name a target
  program.
- **seccomp** filters system calls by number and argument, not by target process.
- **AppArmor** mediates ptrace in `ptrace_may_access` for both sides: the tracer's
  profile needs `ptrace (read, trace) peer=<label>` and a confined tracee's profile
  needs `ptrace (readby, tracedby) peer=<label>`. That hook covers `PTRACE_SEIZE`,
  `/proc/<pid>/mem`, `process_vm_readv`/`writev`, `pidfd_getfd` and the
  ptrace-checked procfs entries. Ubuntu enables it by default.

Host facts read before the design (Ubuntu 25.10, kernel `6.17.0-41`): the LSM list is
`lockdown,capability,landlock,yama,apparmor,ima,evm`; the ptrace mediation mask is
`read trace`; `af_unix` and signal mediation are present; the parser is
`5.0.0~alpha1`; `/sys/kernel/security/apparmor/.remove` exists. Kernel audit lines
reach the kernel log (`journalctl -k`); `auditd` does not run.

## Policy

The template is [`profiles.in`](../../experiments/linux-monitor-confinement/profiles.in).
The runner replaces `@@TAG@@` with a random 8-hex tag and `@@BASE@@` with the run's
root-owned directory, and loads each profile into the kernel only
(`apparmor_parser -a -K`: no cache, nothing under `/etc/apparmor.d`). No profile
includes an abstraction.

- **`rmzmc-frontend-<tag>`**, attached to `<base>/run/remozio`, the installed
  frontend. It may map its own image, connect to the command socket, be read and
  traced by the monitor and probe labels, and receive their signals. The unconfined
  runner may only stop it (`kill`, `term`, `int`, `hup`).
- **`rmzmc-monitor-<tag>`** (launch shape A). `capability sys_ptrace`, plus
  `setuid`, `setgid` and `setpcap` for the monitor's own self-drop, after which its
  bounding set holds `CAP_SYS_PTRACE` alone. `ptrace (read, trace)` and
  `signal (send)` to the frontend label only. The `af_unix` operations the monitor
  uses on the inherited listener and the accepted connection. `deny network inet`
  and `inet6`. File rules: map its own image and the probe image (no `x` rule
  anywhere, so no exec after the start), read the installed frontend (it opens it
  through `/proc/<pid>/exe` and stats the path), the command socket, the last
  capability number, and the procfs entries in the
  [#728 audit table](linux-protected-launch.md#implementation-notes).
- **`rmzmc-probe-<tag>`** (launch shape B): the monitor profile without `setuid`,
  `setgid` and `setpcap`.
- **`rmzmc-complain-<tag>`**: the monitor profile under another name, in complain mode,
  for case F1. The runner derives it from the monitor block.

Differences from the reviewed plan, found while writing the policy:

- **The socket needs a file rule.** AppArmor mediates a pathname `AF_UNIX` socket
  through file rules, so the frontend, monitor and probe profiles have
  `<base>/s/*.sock rw`. It is the only `w` rule in the monitor and probe profiles.
  The `s/` directory is `root:root` `0755`, so the rule cannot create a file.
- **`environ` needs a read rule.** The monitor only stats `/proc/<pid>/environ` (its
  owner shows dumpability), but AppArmor mediates `getattr`. The content stays
  ptrace-checked and mode `0400`.
- **No `mem` rule.** `/proc/<pid>/mem` is mode `0600`, owned by the target's UID or,
  for a task that is not dumpable, by Root. The monitor identity is never the owner
  and holds no DAC capability, so the open fails with `EACCES` in the permission
  check, before AppArmor or the ptrace check sees it, for every target in this
  experiment. The rule could not show ptrace mediation, and the monitor reads memory
  with `process_vm_readv`, so the profiles grant nothing for `mem`. The cases require
  `EACCES` there and take reach from the seize, `process_vm_readv` and `pidfd_getfd`.
- **The ABI is pinned.** Each profile declares `abi <abi/4.0>,`. Without it the parser
  falls back to its default feature set and warns that network rules are not
  enforced. The tests compile every rendered profile with `--warn=all` and require
  no output.
- **Removal by name.** The runner removes each profile through
  `/sys/kernel/security/apparmor/.remove`, the interface `apparmor_parser -R` uses,
  and only names it loaded in this run.

## Launch shapes

- **Shape A:** the unchanged #728 monitor (and the probe) started as Root with
  `aa-exec -p rmzmc-monitor-<tag> --`, then the program's own self-drop to the
  disposable monitor user.
- **Shape B:** the probe in a transient systemd service: `User=` the monitor user,
  `AmbientCapabilities=CAP_SYS_PTRACE`, `CapabilityBoundingSet=CAP_SYS_PTRACE`,
  `NoNewPrivileges=yes`, `AppArmorProfile=rmzmc-probe-<tag>`, `RuntimeMaxSec=`,
  `--collect`. This is the shape a production unit would use. AppArmor allows a
  transition from an unconfined label under `no_new_privs`; if the unit still does
  not start, N2c records it and fails.

## Run

The privileged part is a **supervised step** under the
[human testing boundary](../linux-validation.md#human-testing-boundary). Run it once,
as Root through `sudo`, from the operator's own session in a checkout of this branch:

```sh
sudo python3 -I scripts/run-linux-monitor-confinement-experiment.py > linux-monitor-confinement-evidence.json
```

Requirements: everything the [protected launch run](linux-protected-launch.md#run)
needs, plus AppArmor enabled with ptrace mediation, `apparmor_parser`, `aa-exec`,
`systemd-run`, `systemctl` and `journalctl`. The runner refuses before it changes
anything when it does not run as Root, when `SUDO_UID` and `SUDO_GID` do not name an
ordinary account, when `/var/lib` does not qualify, when a tool is missing, when
AppArmor is off or has no ptrace mediation, or when any `rmzmc-` profile is already
loaded.

The runner:

1. builds the #728 frontend (static, non-PIE), the #728 monitor and the probe (static)
   as Root in a new root-owned directory
   `/var/lib/remozio-monitor-confinement-experiment-<random>`;
2. creates a disposable group with no members and a disposable monitor user, as #728
   does;
3. installs the frontend as `root:<group>` `2755` (the attached path), a second
   set-group-ID copy that no profile attaches, a copy without set-ID bits, and the
   monitor and probe as `root:root` `0755`, and a directory that only the monitor user
   can write (for the file-creation check);
4. renders and loads the four profiles and checks that each is loaded in its mode. If
   any setup check fails, no case runs and the report does not pass;
5. runs each case with its own targets. Every fixture gets pipes for its standard
   streams, so no inherited descriptor is revalidated against a profile at exec. Each
   case has a deadline (15 seconds by default, 5 to 60 with `--timeout`), after which
   the runner kills its process groups and stops its transient unit;
6. reads this run's AppArmor lines from the kernel log and reduces them to closed
   fields (result, profile role, operation, class, mask, peer role, signal, a
   sanitized target) and counts;
7. cleans up in this order, also after a failure or `SIGTERM`: transient units (stop,
   then an empty cgroup), profiles (every fixture process is already reaped), files,
   the user, the group. It reports whether each step is complete, and prints the
   manual steps when one is not.

If the runner itself is killed, its profiles stay loaded until reboot (`-K` writes no
cache). Remove them by name: list the `rmzmc-` names in
`/sys/kernel/security/apparmor/profiles` and write each name to
`/sys/kernel/security/apparmor/.remove`.

The report holds booleans, errno names, outcome categories, capability categories,
labels with the run tag replaced by `<tag>`, the settings and AppArmor host facts above,
source hashes, build flags, the hash of the installed frontend image and the denial
summary. It holds no UIDs, GIDs, user or group names, paths (other than `<base>` and
`/proc/<pid>` forms), addresses, canaries, host names or boot identifiers. A fixture
report with an unknown key or value is dropped, not published.

Unit tests (any host):

```sh
python3 -m unittest discover -s tests -p test_linux_monitor_confinement_experiment.py
REMOZIO_LINUX_MONITOR_CONFINEMENT_LIVE=1 python3 -m unittest discover -s tests -p test_linux_monitor_confinement_experiment.py
```

They cover the case table, the exact rendering of the profiles, the rule constraints
(ptrace rules name only the experiment labels and never `unconfined`; no `x` rule and
one `w` rule in the monitor and probe profiles; exact capability sets), a compile of
every rendered profile with `--warn=all` where the parser and the 4.0 ABI exist, the
report validation and sanitizing, the denial summary, the transient unit properties,
the refusals and the cleanup order. With `REMOZIO_LINUX_MONITOR_CONFINEMENT_LIVE=1` on
Linux x86_64 they also build the probe and the frontend and check their unprivileged
mechanics. They do not load a profile; that is the supervised run.

## The probe

[`probe.c`](../../experiments/linux-monitor-confinement/probe.c) has three modes. It
prints one JSON object of closed-vocabulary values.

- `sleeper`: a target. It holds 16 random bytes and one pipe descriptor, prints their
  address, the descriptor number and the bytes for the runner, and waits.
- `probe drop|nodrop`: the subject. `drop` performs the #728 self-drop (shape A);
  `nodrop` keeps the identity that systemd gave it (shape B). It reports its
  credentials and capability categories, whether it can regain Root, then on the
  runner's go byte runs the actions against each target: against a sleeper, the seize,
  `/proc/<pid>/mem`, `process_vm_readv` of the random bytes, `pidfd_open`,
  `pidfd_getfd` of the pipe and a `status` read; against a frontend in `hold` mode, the
  seize, a `PTRACE_INTERRUPT` stop, `process_vm_readv` of the frontend's marker,
  `/proc/<pid>/mem` and the detach. With a directory it also tries to create a file
  there, to execute `/bin/true` and to open an `AF_INET` socket.
- `userns-bind`: as the operator, a new user and mount namespace, then a bind mount of
  another image over the installed path.

## Cases

| Runner | Case | Required result |
| --- | --- | --- |
| `p1c` | The #728 monitor, shape A, admits the installed frontend | Accepted. Every #728 monitor check passes; the monitor is confined, the frontend has the frontend label |
| `n1c` | Shape A probe against a Root sleeper and the installed frontend | Sleeper: seize, `process_vm_readv` and `pidfd_getfd` refused with `EPERM`. Frontend: seized, stopped, marker read, detached |
| `n2c` | Shape B probe against the same targets, plus the side actions | As N1c; file creation, exec and the IP socket refused. A unit that does not reach the probe's handshake is recorded (`unitStart`) and fails the case |
| `n3c` | Shape A probe against an operator sleeper and the copy without set-ID bits | Both refused as in N1c |
| `n4c` | Shape A probe, side actions only | File creation, exec and the IP socket refused |
| `n5c` | The monitor against the second set-group-ID copy, which no profile attaches | It connects (it has the group); the seize is refused with `EPERM`; rejected |
| `n6c` | The operator bind-mounts another image over the installed path in a user namespace | Namespace refused, or the mount refused (`EPERM`/`EACCES`) |
| `n7c` | The limit: shape A probe against the installed frontend started by Root | Reached: the Root process has the frontend label |
| `c1` | Control: the shape A probe without a profile | The Root sleeper is reached; the side actions work |
| `c2` | Control: the shape B unit without `AppArmorProfile=` | As C1 |
| `f1` | The monitor profile in complain mode | The Root sleeper is reached: complain mode does not confine |
| `f2` | `aa-exec` with a profile name that is not loaded | `aa-exec` fails and the probe never runs |
| `k1` | A confined probe that waits past the case deadline | The runner's `SIGKILL` ends it |
| `f3` | The frontend profile removed, then the P1c launch | The frontend is unconfined; the seize is refused; rejected |

In every case `/proc/<pid>/mem` must fail with `EACCES` (see [Policy](#policy)), the
probe's identity must be exact, and the labels the runner reads must match. The
runner runs F3 last because it removes the frontend profile.

## Recorded result

Not yet run. The Linux host owner runs the supervised step; the evidence file and the
result go here in this change.

## What this experiment does not establish

- **The Root-instance limit** (N7c). A decision for the Linux host owner.
- **The socket surface.** The `unix` rules carry no peer or address limit, so the
  policy does not restrict which seqpacket sockets the monitor can use. The review
  of the IPC surface that #728 defers still applies.
- **A host with AppArmor off**, or another LSM. The runner refuses such a host; a
  production installer must refuse it too.
- **The production refusal code.** A production monitor must read its own label and
  require the exact enforce-mode label at start, and the installer must load the
  profiles before the services and refuse when AppArmor is off, a profile is missing,
  or it is in complain mode (F1).
- Procfs entries that are not ptrace-checked (`status`, most of `stat`) stay readable,
  as they are for every user.
- The production monitor and frontend, installed units, the stopped handoff
  (decision 1), the executor, other kernels and AppArmor versions.

## Kernel references

- `security/apparmor/lsm.c`: `apparmor_ptrace_access_check`; `security/apparmor/task.c`:
  `aa_may_ptrace`, the tracer and tracee checks, the unconfined tracer exemption.
- `security/apparmor/domain.c`: `change_onexec` (`aa-exec`), the `no_new_privs` rule
  for transitions from a confined label.
- `kernel/ptrace.c`: `__ptrace_may_access`, `ptrace_attach` (`EPERM` for any refusal);
  `mm/process_vm_access.c` (`EACCES` from `mm_access` becomes `EPERM`);
  `kernel/pid.c`: `pidfd_getfd`.
- `fs/proc/base.c`: owner and mode of `/proc/<pid>/mem`, `proc_mem_open`.
