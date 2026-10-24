# Linux OS observation and retained-object experiment

This isolated experiment fills the observation gap in the disposable
[approval-command fixture](linux-approval-command.md). It reads real current-task
credentials, executable objects, directory identity and stream properties, builds
the existing `LinuxCommandCapture` schema 4, and rechecks retained objects before
a synchronous fixture callback. It executes **no commands** and issues no request.

The measured requester is the experiment process itself. Protected process and
monitor bindings, exec epoch, submission/stream bindings and code-policy digest
are injected synthetic fixture data. They are never derived from OS observations
or presented as protected admission. Reports retain `trustedCode=false`,
`productionAuthority=false`, `productionAdmission=false`, `selfObservationOnly=true`
and the synthetic-binding/policy flags. The codec's required profile string does
not establish that this process meets that profile. Do not send these captures
through a production approval path.

## Reproduce

Use Linux x86_64, Python 3.11 or later and Swift 6.2 or later, without elevation or
different real/effective credentials. The fixture copies the installed
`/usr/bin/true` into private temporary directories as an executable specimen; it
does not run that specimen. Procfs access to the current task and its executable
is required. No service, grant, namespace, privilege, policy or hardware change is
performed.

```sh
python3 scripts/run-linux-os-capture-experiment.py
python3 -m unittest discover -s tests -p test_linux_os_capture_experiment.py
```

The runner uses the committed dependency lock, four build jobs and distinct Swift
cache, scratch, module, configuration and security paths under
`.build/linux-swift/os-capture`. `--work-dir` selects another absolute build root;
`--output` accepts an absolute sanitized report path. Build time is limited to
600 seconds by default (maximum 900); native execution to 30 seconds (maximum 60).
The existing owned-process cleanup helper retires and reaps the process group
before temporary-directory removal. Its subreaper context encloses the Swift
version check, build and native worker, and restores the prior process state on
success, failure and cancellation. Lifecycle tests prove actual orphan adoption
and reaping and verify restoration after each worker phase fails. Compiler output is capped at 1 MiB and native
output at 32 KiB; stderr and raw failure output are excluded from evidence.
This inherits that helper's owned-topology limits, including no protection from
an external kill of the runner or children deliberately escaping the group.

The report binds every component and protocol source, manifests, dependency locks,
runner and cleanup helpers by SHA-256 before and after the run. It contains fixed
check names, scope flags, measurement time and numeric platform versions; no
observed UID/GID, PID, personal path, command bytes or environment is published.
No evidence is committed automatically. This experiment runs automatically in
`scripts/check-linux-host.sh`, in both the local Linux gate and Linux Swift CI job.
Unavailable prerequisites or failed controls fail that gate without a skip.

## What the component observes

- `/proc/thread-self/status` supplies each real/effective/saved/filesystem UID and
  GID. Current real/effective IDs and the complete supplementary-group list are
  cross-checked with libc. The kernel may return duplicate group memberships:
  the raw list remains retained, while wire/target groups use its sorted unique
  set. Unequal credential roles, root, missing/malformed fields and more than 256
  observed group entries are unavailable. The target is the current effective
  account and observed groups; its name is explicitly unavailable. This is not a
  policy-authorized target lookup or a grant.
- Requested executable and directory paths stay raw bytes, including non-UTF-8
  and newline bytes. Retained descriptors supply identity; executable SHA-256
  comes from the same descriptor with bounded `pread`, without moving its offset.
  Type, ownership, mode, size and nanosecond modification/change metadata are
  checked around hashing. The actual requester executable is opened through
  `/proc/thread-self/exe` and must match the raw pathname from `readlink`.
- Rechecks compare retained executable content and metadata with the current
  named object, then check the name again after hashing. Directory identity and
  access metadata are checked through both the retained descriptor and path;
  ordinary changes to directory contents are allowed.
- Each supplied stream is independently duplicated with close-on-exec ownership.
  `fstat` and `F_GETFL` supply its actual kind, access and semantic flags. This
  experiment admits regular files and pipes/FIFOs; sockets, directories, devices,
  TTY/PTY and unknown kinds are explicitly unavailable. Unknown status flags,
  including `O_PATH`/`O_DIRECT`, fail. Linux's x86_64 `O_LARGEFILE` ABI bit has no
  separate stream semantic. Descriptor close-on-exec is checked separately from
  the wire flags. Capture/recheck neither reads stream contents nor changes its
  shared status flags or offset.

Schema 4 remains pipes routing, terminate-only, no terminal, zero PTY mask and
unavailable ancestry. The real kernel observations do not populate Apple identity
fields. Exact capture mismatch or any failed recheck retires that capture; a later
restoration of changed flags cannot revive it. Calls are synchronous and serial;
this experimental object does not implement a concurrent authority lock.

## Controls and limits

Native controls require exact credential/target correspondence, byte-preserving
schema round-trip and unchanged callback admission. Negative controls replace an
executable with identical bytes at another inode, modify its existing inode,
replace the path at an injected post-hash boundary, mismatch the proc executable
object and pathname, replace a directory, mutate pipe nonblocking/file append
flags through aliases, and supply invalid descriptor shapes, wrong access, final
symlinks, unsupported objects and `O_PATH`. Independent whole-buffer SHA-256
checks cover empty and multiple chunk boundaries and confirm offset preservation.
Reusing the original descriptor number cannot redirect its retained duplicate.

Credential parser controls preserve differing saved/filesystem roles before
rejecting that unsupported profile. They test missing/duplicate fields, missing
roles, malformed/out-of-range numbers and normalization of duplicate groups.
These are synthetic parser inputs: no actual credential transition is performed.
The report explicitly records `actualCredentialTransitionTested=false`.

Executable hashing is capped at 64 MiB, final path symlinks are refused, and input
paths are limited to 4096 bytes. Parent path components and procfs provenance are
not protected by this experiment. Comparing samples cannot detect a mutation that
occurs and is restored between observations. After the final check a pathname or
shared open-file-description flag can still change. Retention does not freeze
script/interpreter dependencies, file contents, offsets, flags or other holders.
There is no ptrace-owned stop or acknowledged executor handoff, trusted code
policy, protected installation, physical phone, TPM or production authority.

## Integration seam

`RetainedExecutable`, `RetainedDirectory` and `RetainedStream` are the reusable
experimental primitives: a monitor-owned layer could supply a retained executable
descriptor and retained received streams, plus independently observed raw paths.
They still require owner serialization and an appropriate lifetime boundary.
`hashFile` and credential `parse` are bounded data helpers; parsing caller-supplied
status text never makes its contents trusted.

`CredentialObservation.current`, `/proc/thread-self/exe`, `getsid(0)` and
`RetainedOSCapture` are deliberately **self-only**. A later composed fixture must
replace them with observations taken by the monitor from its retained, stopped
sender and kernel message pidfd, keep that stop through the acknowledged handoff,
and obtain bindings/exec epoch/policy from the independently validated owner.
Self-reported credentials, injected bindings and this callback cannot serve as
authority inputs. The existing caller-monitor experiment remains a separate
evidence boundary; this patch does not modify its code or results.
