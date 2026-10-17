# Linux caller identity experiment

This experiment establishes a few Linux caller primitives with disposable, ordinary-user processes.
It does **not** establish a complete production caller identity mechanism, current executable
incarnation guarantee, or parity with the macOS audit-token checks.

## Reproduce

The measured configuration is Ubuntu 25.10, x86_64, Linux 6.17.0-41-generic, without elevation.
Python 3.10 or later, glibc's `pidfd_open`, procfs, Unix `SOCK_SEQPACKET`, kernel
`SO_PEERPIDFD`/`SO_PASSPIDFD`, and permission to trace cooperative owned children are required.
These are runtime requirements; a distribution name alone does not guarantee availability.
The runner refuses other operating systems, other architectures, root, and differing real/effective
UIDs or GIDs. Missing features, sandbox restrictions, or denied tracing fail the experiment;
there is no weaker identity fallback. This does not certify the distribution's security support lifecycle.

```sh
python3 scripts/run-linux-caller-experiment.py
REMOZIO_LINUX_CALLER_LIVE=1 python3 -m unittest discover -s tests -p test_linux_caller_experiment.py
```

Run directly in an ordinary-user session when a build sandbox denies sockets or ptrace.
No root privilege, installation, persistent service, system setting, network connection, or physical
device is needed. The fixture executes `/usr/bin/true` only in its own child.
`--timeout 15` is the default per-case outer deadline; values above 60 seconds are refused.
A nonzero exit means the fixture did not establish all its declared observations.

## Observations and retained evidence

The [sanitized report](linux-caller-evidence.json) binds the runner and probe source hashes to the
measured OS, kernel, architecture and Python version. It contains boolean checks, stable failure
categories, and error numbers rather than process IDs, numeric credentials, paths, usernames,
hostnames, boot identifiers, device identifiers, or environment contents.

| Case | Observed result | Boundary |
| --- | --- | --- |
| Direct Unix IPC | Kernel connection pidfd and message pidfd both identify the owned sending child; credential metadata matches the fixture's UID/GID. False identity text in the payload is ignored. | Same account and namespace; no hostile credential-forgery claim. |
| Socket transfer | A connector passes its connected socket using `SCM_RIGHTS` to a different owned child. `SO_PEERCRED` and `SO_PEERPIDFD` continue identifying the connector; received `SCM_CREDENTIALS` and `SCM_PIDFD` identify the actual sender. | Retaining a connection peer is insufficient to identify subsequent senders. |
| Same-PID exec | A cooperative single-threaded child enters an initial ptrace stop, then an exec event stop. Its PID and retained pidfd remain the same while `/proc/PID/exe` changes inode and resolves to the expected fixture. The pidfd becomes readable after exit. | pidfd lifetime readiness does not detect exec. Executable metadata at a stop does not prove code provenance. |
| Monitor failure | The fixture kills an owned tracer with `SIGKILL`. `PTRACE_O_EXITKILL` kills its stopped tracee; pidfd exit readiness and adopted-child reaping are observed. | Tests failure after tracing and the option are established, while the tracee is stopped. It does not validate admission or continued production monitoring. |

Both IPC cases check `FD_CLOEXEC` on imported pidfds, absence of exit readiness while their peers
are alive, exit readiness afterwards, and reaping of every owned peer. Kernel-provided socket and
message pidfds avoid converting message credential PIDs through a later `pidfd_open` lookup.
The exec and monitor fixtures do use `pidfd_open` for their own already-stopped cooperative children;
this is not evidence that numeric lookup after an arbitrary caller observation is race-free.

The report's successful `passed` value means these exact fixture checks passed on this host.
The tests also exercise malformed/incomplete reports, integer values masquerading as booleans,
failed worker exits, sanitized failures, refused hosts/elevation, and timeout cleanup of a worker
that forks a descendant. Set the live-test environment variable explicitly to run real kernel cases.

## Lifetime, deadlines and cleanup

The runner launches each case in a separate session and temporarily becomes a child subreaper.
Every case has an outer deadline; socket and wait operations also have deadlines. Each fixture closes
descriptors and kills/reaps its remaining owned children in `finally` blocks. On completion, invalid
output, cancellation through a Python exception, or timeout, the runner retires remaining owned members
of the fixture process group and reaps adopted descendants. Before signaling, cleanup checks that the child is still owned;
after worker reaping, it drains exited group members and requires an owned live member before
signaling the group. Regression tests cover already-reaped children, terminal group members,
and a surviving adopted descendant. Failure to finish reaping makes the report fail. The runner owns the
temporary directory, so worker termination also removes pathname sockets. It restores its prior
subreaper setting after the cases. The timeout test exercises the same group-kill/reap path.

These cleanup observations cover this fixture topology, whose children never change sessions or
escape the process group. External `SIGKILL` of the runner, an uninterruptible kernel task, malicious
descendants, and arbitrary production process trees are not covered by the cleanup claim.

## Required contract decisions and untested cases

A prospective authority must bind each request to its actual message sender and define which
executable transitions invalidate approval. A stable pidfd alone cannot satisfy an unchanged-executable
requirement. This experiment provides no deployable solution for tracing an arbitrary unrelated
unprivileged caller, establishing the initial tracing relationship without a race, or proving all relevant
exec/clone events are monitored until dispatch. Unsupported admission must be refused in any future
implementation; successful IPC metadata is insufficient to accept it.

The following remain untested and unsupported by this evidence:

- Non-leader thread exec, multithreaded clone/exec races, and tracer replacement/detachment.
- PID/user namespaces, containers, nested namespace PID interpretation, and namespace transitions.
- Differing real/effective/saved credentials, supplementary groups, credential changes, and privileged or set-ID executables.
- Forced PID reuse. The fixture tests exec with the same live PID, which is a different event.
- Immutable executable content, signing or package provenance, scripts/interpreters, loaded libraries, and attacker-modified files.
- Continuous final-dispatch identity rechecks, installed service isolation, policy and approval enforcement, phone integration, and privileged command execution.

No global ptrace policy is changed, and no account, namespace or privilege transition is attempted.
The thread/namespace/credential cases require a separately designed fixture and explicit support policy;
their omission must not be read as a positive result or a recommendation to permit them.

## API references

The [Linux Unix socket manual](https://man7.org/linux/man-pages/man7/unix.7.html) describes
connection-time peer credentials, per-message credential handling and open-file-description transfer.
The [pidfd_open manual](https://man7.org/linux/man-pages/man2/pidfd_open.2.html) describes process
descriptor lifetime and exit polling. The [ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html)
describes exec event stops, threading complications, permission checks and `PTRACE_O_EXITKILL`.
The recent pidfd socket UAPI constants are declared in the installed Linux
`asm-generic/socket.h` and glibc `bits/socket.h`; the fixture records observed runtime behavior
rather than inferring availability from those declarations.
