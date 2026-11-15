# Linux protected launch experiment

This experiment measures a candidate design for the
[activation proposal's decision 5](../linux-activation-proposal.md#decisions),
protected frontend launch and code policy, on Ubuntu. The Linux host owner chose
"strict first": the Linux host keeps the Mac guarantee, and production execution
stays off until a protected-launch experiment passes. This is that experiment. It
does not install a service, approve a command, execute a user command, change the
[contract](../linux-host-contract.md), or select the open line 67 handoff
(decision 1).

**Recorded result: passed on one Ubuntu host on 2026-11-13** (see
[Recorded result](#recorded-result)). Production execution stays off: the result
covers the measured properties only.

## Candidate design

- **Frontend.** A static, non-PIE executable with no program interpreter, installed
  as `root:<frontend group>` mode `2755`. The frontend group has **no members**:
  no account lists it as a supplementary or primary group. At the start of `main`
  (after the static C library startup), before it reads its arguments or creates a
  socket, the frontend reads its personality (a query only), closes every
  descriptor above 2, resets every signal disposition and the signal mask, sets
  `no_new_privs`, and installs one seccomp filter. The filter kills the process on another
  architecture, on an x32 system call number, and on any system call outside a
  fixed list taken from the full protocol path: `read`, `write`, `close`,
  `connect`, `sendmsg`, `recvmsg`, `exit`, `exit_group`, `rt_sigreturn`,
  `rt_sigprocmask`, `restart_syscall`, `brk`, `munmap`, `mmap`, `mprotect` and
  `socket`. It allows `mmap` only for private anonymous memory without
  `PROT_EXEC`, `mprotect` only without `PROT_EXEC`, and `socket` only for one
  close-on-exec `AF_UNIX` `SOCK_SEQPACKET` socket. It has no `execve`, `clone`,
  file `open` or `poll` (the path does not wait on more than one descriptor).
  Descriptors 0–2 stay open as the caller's standard streams. The fixture uses
  them only in the N1 `hold` mode, for a readiness line and one byte; the product
  frontend must not take input from them.
- **Socket gate.** Root binds the command socket as `root:<frontend group>` mode
  `0660` in a `root:root` `0755` parent, as a systemd socket unit with
  `SocketGroup=` and `SocketMode=` would. Only a process whose effective or
  supplementary groups include the frontend group can connect. With no members,
  that is only the set-group-ID frontend.
- **Monitor.** A dedicated system user that keeps only `CAP_SYS_PTRACE` (effective
  and permitted; bounding set reduced to it; no inheritable or ambient
  capabilities; `no_new_privs`), with the listening descriptor inherited from Root.
  It requires `SO_PEERPIDFD` and refuses without it. It checks that the
  `SO_PEERCRED` effective GID is the frontend group and that the hello is exact
  (`RMZPL1`, the frontend's personality as 8 hex digits, a newline), then seizes the peer with
  `PTRACE_O_EXITKILL` and the clone, fork, vfork and exec events, confirms that the
  peer pidfd still names the seized PID, and holds a `PTRACE_INTERRUPT` stop while
  it checks the frontend from outside:
  - real GID is not the group; effective, saved and filesystem GIDs are; the group
    is not in the supplementary list;
  - one thread, `Seccomp: 2`, `Seccomp_filters: 1`, `NoNewPrivs: 1`, the monitor as
    tracer, no ignored or blocked signals, not dumpable (read from the owner of
    `/proc/<pid>/environ`, which is Root only when the dumpable value is not 1);
  - `AT_SECURE` 1, read from the auxiliary vector that exec wrote on the stopped
    frontend's stack, and personality 0, as the frontend reported it in the hello
    (see [Implementation notes](#implementation-notes));
  - `/proc/<pid>/exe` is the same device and inode as the installed file, which is
    still `root:<group>` `2755` with one link;
  - every file-backed mapping is that inode, no mapping is writable and executable,
    anonymous mappings are only the heap, stack, vDSO, vvar, vsyscall or unnamed
    regions, and only the vDSO and vsyscall pages among them are executable;
  - every namespace equals the monitor's;
  - listing `/proc/<pid>/fd` is refused, and the inventory finds descriptors 0–2 and
    the socket at 3, and nothing else.

  A procfs file that does not fit the monitor's buffer fails its check, so no check
  passes on a partial view.

## Why set-group-ID

A set-ID exec gives kernel-enforced properties that an ordinary executable lacks
(`fs/exec.c` `bprm_fill_uid` and `begin_new_exec`, `security/commoncap.c`
`cap_bprm_creds_from_file`, Linux 6.17):

- The process is not dumpable (it takes the `suid_dumpable` value, 2 on the target
  host). Same-UID `ptrace`, `/proc/<pid>/mem`, `process_vm_readv`/`writev` and
  `pidfd_getfd` then need `CAP_SYS_PTRACE`, so the user's other processes cannot
  inspect or change it.
- `AT_SECURE` is set, and the personality flags in `PER_CLEAR_ON_SETID` are cleared.
- The kernel does not grant the elevation when the launch is traced by a tracer
  without `CAP_SYS_PTRACE`, when `no_new_privs` is set, or when the filesystem state
  is shared with another process (`CLONE_FS`). A launch an attacker controls before
  exec therefore cannot reach the socket.

The last rule applies only when the exec changes credentials. If the group is
already one of the caller's groups (`in_group_p`), the kernel treats the exec as no
change and a tracer keeps the elevation. That is why the group must have no members,
and why the monitor also refuses a caller whose supplementary list holds the group.
Case N9 measures that control.

Why the monitor's `Seccomp_filters: 1` is the frontend's own filter: an inherited
filter needs `no_new_privs` or `CAP_SYS_ADMIN` in the installer's user namespace.
`no_new_privs` before exec removes the elevation (N3). A new user namespace does not
map the root-owned file or the group, so the kernel ignores the set-ID bits, and the
monitor also requires the host namespaces (N12). So an elevated frontend that
connects started with no filter, and the one filter it has is the one it installed.

## Run

The privileged part is a **supervised step** under the
[human testing boundary](../linux-validation.md#human-testing-boundary). Run it once,
as Root through `sudo`, from the operator's own session in a checkout of this branch:

```sh
sudo python3 -I scripts/run-linux-protected-launch-experiment.py > linux-protected-launch-evidence.json
```

Requirements: Ubuntu x86_64, Python 3.11 or later, `cc` with static glibc
(`libc6-dev`), `groupadd`, `useradd`, `userdel`, `groupdel`, and a `/var/lib` on a
filesystem mounted without `nosuid`, with every path component owned by Root and
not writable by group or others. The runner refuses before it changes anything when
it does not run as Root, when `SUDO_UID` and `SUDO_GID` do not name an ordinary
account, or when `/var/lib` does not qualify.

The runner:

1. builds the three fixtures from `experiments/linux-protected-launch/` as Root, in a
   new root-owned directory `/var/lib/remozio-protected-launch-experiment-<random>`;
2. creates a disposable system group with a random name and checks that it has no
   members and is no account's primary group, and a disposable system user for the
   monitor. Each name must be free before creation;
3. installs the frontend as `root:<group>` `2755` (owner first, then mode), a copy
   without set-ID bits as the control, and the monitor, a second monitor build
   (N13) and the attacker as `root:root` `0755`. If any setup check fails, no case
   runs and the report does not pass;
4. runs each case with a fresh socket. The attacker runs as the operator (the
   `SUDO_UID` account, with its normal group list) and launches the frontend itself,
   so it is the frontend's parent. The monitor starts as Root and drops to the
   disposable user before it accepts. Each case has a deadline (15 seconds by
   default, 5 to 60 with `--timeout`), after which the runner kills its process
   groups. The monitor uses `PTRACE_O_EXITKILL`;
5. removes the files, then the user, then the group, also after a failure or
   `SIGTERM`, and reports whether each removal is complete. It removes an account
   whose creation it started even when the tool timed out, and never one that
   existed before. If a removal is not complete, it prints a warning on standard
   error.

The report holds booleans, errno names, outcome categories, the OS release and
numeric kernel version with the distribution revision (for example `6.17.0-41`),
the settings `ptrace_scope`, `suid_dumpable`,
`protected_hardlinks`, AppArmor's status and its unprivileged user namespace
restriction, the AppArmor label categories of the monitor and the frontend, source
hashes, the hash of the installed frontend image and the hash of the seccomp filter
that it dumps. It
holds no UIDs, GIDs, user or group names, paths, host names or boot identifiers. A
fixture report with an unknown key or value is dropped, not published.

Unit tests (any host):

```sh
python3 -m unittest discover -s tests -p test_linux_protected_launch_experiment.py
REMOZIO_LINUX_PROTECTED_LAUNCH_LIVE=1 python3 -m unittest discover -s tests -p test_linux_protected_launch_experiment.py
```

They cover the case table, the report validation and sanitizing, the setup gate,
the refusal paths and the cleanup order, including an interrupted account creation.
With `REMOZIO_LINUX_PROTECTED_LAUNCH_LIVE=1` on Linux x86_64 they also build the
fixtures and check their unprivileged mechanics: the seccomp self-tests are killed,
the dumped filter, decoded and run in the test, allows exactly the listed calls and
arguments, the hello carries the measured personality, and the same-UID attacks
work against a copy without set-ID bits. The monitor
refuses to run without Root, so its refusal of a missing `SO_PEERPIDFD` is measured
by case N13 in the supervised run, with the real monitor code. These checks do not
replace the supervised run.

## Cases

| Runner | Plan | Case | Required result |
| --- | --- | --- | --- |
| `p1` | P1, P2, P3, N11 | Clean launch by the operator | Frontend accepted. Every monitor check above passes; listing `/proc/<pid>/fd` is refused (the reason for the `FDSize` and `pidfd_getfd` inventory) |
| `n1` | N1 | The launching parent attacks the frontend in its wait before connect, then the same attacks on the copy | Installed: `/proc/<pid>/mem` open refused, `process_vm_readv`/`writev`, `pidfd_getfd` and `PTRACE_SEIZE` refused with `EPERM`. Copy: all succeed, including a read and a same-bytes write of a known data symbol |
| `n2` | N2 | The parent traces the launch (`PTRACE_TRACEME`) | No elevation at the exec stop; connect fails with `EACCES` |
| `n3` | N3 | `no_new_privs` before exec | No elevation; connect fails with `EACCES` |
| `n4` | N4 | The frontend starts from a `CLONE_FS` child | No elevation; connect fails with `EACCES` |
| `n5` | N5 | `READ_IMPLIES_EXEC` and `ADDR_NO_RANDOMIZE` before exec | Personality 0; accepted |
| `n6` | N6 | Inherited descriptors 7 and 40, `SIGINT` ignored, `SIGTERM` blocked | Closed and reset; accepted |
| `n7` | N7 | Self-tests: `execve`, `PROT_EXEC` `mprotect`, `PROT_EXEC` `mmap`, `MAP_SHARED`, `clone`, an x32 call | Each killed by `SIGSYS` |
| `n9-untraced`, `n9-traced` | N9 | Control: the operator holds the group as a supplementary group, untraced and traced before exec | Elevation kept in both; the monitor refuses on the supplementary list only |
| `n10` | N10 | Control: the monitor without `CAP_SYS_PTRACE` | Seize refused with `EPERM`; rejected |
| `n12` | N12 | `unshare(CLONE_NEWUSER)` before exec | Namespace refused with `EPERM` or `EACCES` (the report keeps the errno; any other errno fails), or no elevation and connect fails with `EACCES` |
| `n13` | Added | Control: a clean launch against a monitor build that asks for an unknown socket option in place of `SO_PEERPIDFD` | `ENOPROTOOPT`; no seize attempt; rejected |
| `n8` | N8 | The parent keeps an `O_PATH` descriptor, the runner replaces the installed file, the parent runs the old inode with `execveat` | The kernel elevates the old inode; the monitor refuses on the executable identity only |

In the controls (N8, N9) every other monitor check must pass, so the report shows
which single check refuses. The runner runs N8 last because it replaces the
installed file.

## Recorded result

**Passed on one host, 2026-11-13**
([evidence](linux-protected-launch-evidence.json)): Ubuntu 25.10, kernel
`6.17.0-41`, x86_64, `ptrace_scope` 1, `suid_dumpable` 2, AppArmor enabled with its
unprivileged user namespace restriction on. The Linux host owner ran it as Root
through classic sudo 1.9.17. Every setup check, all 14 cases and every cleanup
check passed. The source hashes in the evidence match the fixtures and the runner
in this change.

- **P1, N5, N6:** accepted. Every monitor check held, including `AT_SECURE` from the
  stack, not dumpable, the executable identity, the mappings, the namespaces and
  the descriptor inventory. Listing `/proc/<pid>/fd` failed with `EACCES`. AppArmor
  confined neither the monitor nor the frontend.
- **N1:** on the installed image, opening `/proc/<pid>/mem` failed with `EACCES`,
  and `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` and `PTRACE_SEIZE`
  failed with `EPERM`. On the copy without set-ID bits, all of them succeeded.
- **N2, N3, N4:** no elevation; connect failed with `EACCES`.
- **N12:** the user namespace was created (the AppArmor restriction does not refuse
  the call); the kernel did not elevate, and connect failed with `EACCES`.
- **N7:** all six self-tests were killed by `SIGSYS`.
- **N8:** the kernel elevated the replaced inode; the monitor refused on the
  executable identity and the mappings only.
- **N9:** with the operator in the group, the kernel kept the elevation, traced and
  untraced; the monitor refused on the supplementary list only.
- **N10:** without `CAP_SYS_PTRACE` the seize failed with `EPERM`; rejected.
- **N13:** without `SO_PEERPIDFD` (`ENOPROTOOPT`) the monitor did not seize;
  rejected.

A first run on the same day measured every case as required except N7. Classic
sudo gives the command a hard core limit of 0 (`rlimit_core`), so the attacker could
not set the limit of 1 that its self-tests used, and they did not start. The
attacker now keeps 0 in that case, and the recorded evidence is the second run.

On this host the candidate meets every property that the experiment measures. That
does not make production execution available (see
[What this experiment does not establish](#what-this-experiment-does-not-establish)),
and adopting the candidate for decision 5 is the Linux host owner's decision.

## Implementation notes

- The monitor drops its own privileges (bounding set, groups, IDs, capabilities,
  `no_new_privs`) instead of starting under `setpriv`, so it can verify and report
  its own credentials in the same run.
- The monitor confirms the pidfd-to-PID association from the pidfd's `fdinfo`
  (`Pid:` shows `-1` once the task is gone). It does not use
  `pidfd_send_signal(…, 0)`: that call checks kill permission, which needs
  `CAP_KILL` across UIDs.
- A process that is not dumpable has root-owned procfs entries. `CAP_SYS_PTRACE`
  passes the ptrace checks but grants no file access, so the monitor uses only
  entries that the mode allows (measured on the target host): `status`, `stat` and
  `maps` (`0444`), `ns` (`0511`), `exe`, and the `attr` labels. It does not open
  `fd` (`0500`), `personality`, `auxv` or `environ` (`0400`):
  - for descriptors it reads `FDSize` and calls `pidfd_getfd` for each number below
    it;
  - for `AT_SECURE` it takes the stack start and the start of the argument strings
    from `stat`, reads that range with `process_vm_readv`, and walks argc, argv,
    envp and the auxiliary vector that exec wrote there. It requires an `AT_NULL`
    and exactly one `AT_SECURE`;
  - for the personality no such path exists. The frontend reads its personality
    before its filter forbids the call and sends it in the hello. The monitor uses
    the value only together with the identity, mapping and memory checks of the
    same stop, which tie the hello to the installed image, whose memory the
    operator cannot change (N1);
  - for dumpability it uses only the owner of `environ`, which `stat` reports
    without opening the file.
- `PTRACE_SECCOMP_GET_FILTER` needs `CAP_SYS_ADMIN`, so the monitor does not dump
  the running filter. It relies on the executable identity, `Seccomp_filters: 1`
  and the argument above. The runner records the hash of the filter that the
  installed image dumps.
- The N13 monitor is the same source built with `-DRMZPL_PEERPIDFD_OPTION=32767`,
  an option number the kernel does not know. The kernel then answers as it does
  without `SO_PEERPIDFD`, so the case runs the real refusal path.
- A fixture whose report does not fit its buffer prints `{"error":"overflow"}`
  instead of a truncated report, so the failure stays attributable.

## What this experiment does not establish

- **Monitor confinement.** `CAP_SYS_PTRACE` can trace Root processes. Before
  production the monitor needs confinement to the frontend peer (for example an
  AppArmor `ptrace (trace) peer=` rule) and a review of its IPC surface. That is a
  separate experiment and a decision for the Linux host owner.
- **An outside reading of the personality.** The monitor relies on the value that
  the verified frontend reports. The `AT_SECURE` and dumpability results come from
  the kernel's own records.
- **The production frontend.** The fixture is C. The product frontend must also be
  static, with no loader and the same kind of allowlist. A Swift static executable
  is possible but unmeasured.
- **The identity of descriptor 3.** The inventory checks that descriptor 3 is a
  socket, not that it is the end of the connection that the monitor accepted. The
  verified frontend closes every inherited descriptor above 2 and opens one socket,
  so in this fixture it is. The production monitor should tie that descriptor to the
  accepted connection.
- The composition with the stopped handoff, the executor, installed services and
  packaging, update serialization (decision 6), TPM roles (decision 4) and a real
  phone approval.
- Other kernels and distributions. The evidence records the kernel version; a later
  change to set-ID exec semantics needs a new run.
- An administrator who adds a member to the frontend group. The monitor refuses
  such a caller, but that member's other processes lose the tracer protection. The
  installer and the monitor must report any member.

## Kernel references

- `fs/exec.c`: `bprm_fill_uid` (set-ID bits, `PER_CLEAR_ON_SETID`, unmapped IDs),
  `begin_new_exec` (dumpability, personality), `check_unsafe_exec` (`CLONE_FS`).
- `security/commoncap.c`: `cap_bprm_creds_from_file` (`in_group_p`, the downgrade
  under an unprivileged tracer or `no_new_privs`, `AT_SECURE`).
- `kernel/ptrace.c`: `__ptrace_may_access` (credentials, dumpability,
  `CAP_SYS_PTRACE`); `security/yama/yama_lsm.c` (relational scope).
- `fs/proc/base.c` and `fs/proc/fd.c`: owner of a non-dumpable task's entries,
  `proc_fd_permission`.
- `kernel/pid.c`: `pidfd_getfd`; `fs/pidfs.c`: pidfd `fdinfo`.
- `kernel/seccomp.c`: filter installation requires `no_new_privs` or
  `CAP_SYS_ADMIN`.
