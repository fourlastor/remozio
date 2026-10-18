# Controlled Linux caller monitor experiment

This experiment exercises controlled fixture launch, continuous task-event
monitoring, and a simulated dispatch handoff with disposable processes in the
current account. It does not install a service, issue an approval, execute a user
command, or establish the protected-code guarantee required by
`linux-protected-single-thread-v1`.

The [earlier caller experiment](linux-caller.md) established individual IPC,
exec-event and tracer-failure primitives. Its recorded evidence remains unchanged.
This experiment combines those operations across a pending request and tests
invalidation before a simulated executor accepts a handoff.

## Run

Use an ordinary Linux x86_64 session with Python 3.11 or later, a C compiler at
`cc`, procfs, Unix sequenced-packet sockets, kernel-provided message pidfds, and
permission to trace owned children. The runner rejects root and differing real
and effective IDs. Cleanup also requires readable procfs task-child enumeration
at `/proc/self/task/<pid>/children`, an optional kernel facility. The runner checks
this prerequisite before starting the compiler or any fixture. If the entry is
missing or inaccessible, it exits with status 2 and a fixed prerequisite message;
it does not attempt the experiment or publish a passing report. Successful reports
record `prerequisites.procTaskChildrenReadable: true`. A mounted procfs alone does
not establish this requirement.

It builds the native fixture in a private temporary directory
using a fixed compiler invocation, then runs each case with a deadline:

```sh
python3 scripts/run-linux-caller-monitor-experiment.py
REMOZIO_LINUX_CALLER_MONITOR_LIVE=1 python3 -m unittest discover -s tests -p test_linux_caller_monitor_experiment.py
```

`--timeout` defaults to 15 seconds per case and is limited to 60 seconds. No
existing process, command path, TPM device or installation is accepted as a test
target. Only the disposable fixture executables run. A denied kernel operation,
invalid report, exceeded deadline, or incomplete cleanup is not a successful
experiment. Run outside a socket/ptrace-restricted build sandbox when necessary;
do not alter system security policy.

Portable runner tests participate in the normal Python gate on Linux and Mac.
The live kernel experiment is explicitly enabled and its results apply to its
recorded host. Its regression test uses a temporary root containing spaces and a
newline to exercise mapping identification without pathname parsing. A passing
Mac test of report validation does not establish Linux
kernel behavior, and a Linux fixture run does not replace required native Mac CI.

## Acceptance controls

| Case | Required observation |
| --- | --- |
| Healthy handoff | The monitored fixture submits as the retained process; a fresh acknowledgment is accepted with the caller stopped. |
| Same-path exec | A later exec event invalidates the request even when the executable pathname is unchanged. |
| Fork, vfork and thread clone | Each task-creation event invalidates the single-thread profile before acceptance. |
| Sender mismatch | The actual message sender differs from the retained admitted process, so connection identity cannot rescue the submission. |
| Caller exit | Pending work loses its caller and cannot authorize the simulated handoff. |
| Stop release | Releasing the observed stop invalidates the handoff. |
| Bad or duplicate acknowledgment | A mismatched nonce or repeated acknowledgment invalidates the pending handoff. This is not a consumed-command replay test. |
| Monitor failure | Monitor death during the handoff prevents acceptance and exercises owned-tracee termination. |
| Memory modification | A separate non-admitted bootstrap demonstrates the precise memory-integrity limit described below. |

Reports contain exact boolean check sets and fixed observation categories, with
bounded output and source hashes. They exclude process IDs, credentials, memory
addresses, paths, nonces, environment dumps and raw compiler/worker diagnostics.
The runner owns a separate process group for each worker and uses a subreaper to
retire and reap its fixture descendants on completion, timeout and report failure.
It establishes that a group still has owned children before signaling it after
the worker exits. Fixtures stay in that process group; malicious group escape,
external termination of the runner, and uninterruptible kernel tasks are outside
the cleanup claim.

## Recorded result

The [retained report](linux-caller-monitor-evidence.json), measured on 2026-10-18 UTC,
passed all 12 controls on Ubuntu 25.10 x86_64 with Linux 6.17.0 and Python 3.13.7,
without elevation and with a temporary root containing spaces and a newline. The report binds
its results to the runner, probe, native
fixture and shared cleanup source by SHA-256; it is not evidence for later source
revisions. The host reported Yama ptrace scope 1, AppArmor enabled, and seccomp
mode 0 for the runner. These values do not describe every process's confinement.
The prerequisite check confirmed readable procfs task-child enumeration. This
run does not establish support for kernels or procfs mounts without that facility.

Only the healthy control accepted the simulated handoff. All ten other lifecycle,
sender and handoff controls rejected it; the separate memory-modification control
also rejected it after independently observing the write. All fixture descendants
were reaped. The memory result demonstrates a limit of attaching to an
already-running bootstrap with a previously opened memory handle; it does not
establish that a handle opened before exec can modify a replacement image.

## Boundaries

The supervising harness, launcher, native fixture, and simulated executor are
ordinary user-owned test programs. Controlled ordering in this topology is not a
root-controlled installation or proof that an arbitrary caller was launched
without prior manipulation. Executable observations and retained process handles
do not authenticate the human, parent shell, or all running code.

The main lifecycle fixtures establish supervision before their first selected
native fixture exec and retain the process instance throughout the experiment.
Subsequent exec, new tasks, a different message sender, and caller or monitor loss
must invalidate the pending fixture request. The handoff uses fresh correlation
data and an acknowledged stop. Its result is a simulated acceptance at an observed
instant, not execution, durable consumption, or an atomic guarantee against a
failure occurring after that instant.

A separate memory-modification control deliberately uses an already-running
bootstrap that retains a writable memory descriptor before tracing. That case is
not admitted through the main controlled-exec path. A separate same-account
writer, which is not the tracer, uses that earlier handle; the monitor checks the
changed executable mapping and unchanged executable file. It identifies the
mapping by address range, execute permission, device and inode from the fixed
procfs columns, compared with the fixture file's stat identity; it does not use
the printed pathname. This remains a backing-file observation, not protected-code
authentication. A descriptor opened
before an exec refers to the old address space; it cannot be used as evidence of access to
the replacement image. The report must preserve this distinction.

All successful reports retain `trustedCode: false` and
`productionAdmission: false`. A passing negative control means the expected
refusal or limitation was observed; it does not remove the limitation.

## Scope left for later work

Protected frontend and loader installation, syscall/code-loading restrictions,
host namespace and credential-transition enforcement, authenticated service IPC,
current grants, hardware authority, journal consumption, and real dispatch remain
separate gates. This experiment does not change schema 4 or advertise a Linux
host capability. It does not relax Yama, AppArmor, seccomp, or another system
policy to obtain a result.

Ordinary owned-process fixtures require no interactive operator. Root-owned
installation, service access configuration, TPM provisioning and physical phone
pairing remain operator milestones.

## Kernel references

The [ptrace manual](https://www.man7.org/linux/man-pages/man2/ptrace.2.html)
defines the separate exec, clone, fork, vfork and exit events and the tracer-exit
kill option. All task-creation event classes matter; watching clone alone does not
cover every way a task can be created. The [Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
describes additional access restrictions. The experiment measures operations on
the selected host rather than treating documented API availability as a pass.
The [task-children manual](https://www.man7.org/linux/man-pages/man5/proc_tid_children.5.html)
documents the optional `CONFIG_PROC_CHILDREN` facility required by this
experiment's cleanup path. The preflight checks access to the entry itself rather
than inferring availability from a kernel version or configuration file.
