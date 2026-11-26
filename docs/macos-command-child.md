# Private command child

The app embeds a small C executable for credential preparation in a fresh child process.
Root will use public `posix_spawn` instead of forking its multithreaded Swift runtime.
This executable grants no authority to an ordinary caller and has no request listener.
The product authority does not launch it yet.

```mermaid
sequenceDiagram
    participant R as Root request owner
    participant C as Fresh command child
    participant P as Approved program
    R->>C: Spawn with private pipes and retained descriptors
    R->>C: Exact capture and finite preparation budget
    C->>C: Validate frame; set and verify target credentials
    C->>C: Enter retained directory; prepare selected I/O
    C-->>R: Prepared status on private pipe
    Note over R: Native supervision is available; authority dispatch integration remains pending
    R->>R: Consume durable permit; enforce current policy; final recheck
    R->>C: One private release byte
    C->>P: execve captured pathname, raw argv and environment
    Note over R,P: Status pipe closure alone does not prove exec or command exit
```

## Descriptor contract

The parent must authenticate the installed executable and supply only these descriptors.
It must create a separate process group, reset inherited signals and use a clean launcher environment.
Legacy `--execute` PTY mode requires a new session and a private terminal slave.
The monitor selects `--execute-in-session` to preserve its session and give the target a separate process group.
That mode verifies the parent session and, for PTY mode, the existing controlling terminal and target foreground group.

| Descriptor | Use |
| --- | --- |
| 0 | Original stdin, or the selected PTY slave |
| 1 | Original stdout, or the selected PTY slave |
| 2 | Original stderr, or the selected PTY slave |
| 3 | Private configuration pipe, read end |
| 4 | Retained working directory |
| 5 | Private status pipe, write end |
| 6 | Private release pipe, read end |

The child requires real and effective UID zero before touching these descriptors.
It validates private pipe direction, closes other descriptors, and marks control descriptors close-on-exec.
It changes nonblocking flags only on private pipes. It does not read stdin or write stdout/stderr during preparation.
The directory is entered after dropping credentials, so possession of its descriptor does not bypass target access checks.
The parent must normalize borrowed sources before mapping descriptors to avoid source/destination collisions.
The [native process owner](macos-command-process.md) implements these descriptor mechanics.
Protected installation and an installed dispatch service remain pending.

## Private frame

Format 1 uses a 40-byte header of ten big-endian UInt32 words.
The complete frame is bounded at 8 MiB. Argument and environment counts are each bounded at 262,144 entries.

| Header word | Value |
| --- | --- |
| 0 | `0x524d4331` (`RMC1`) |
| 1 | Exact body byte count |
| 2–3 | Target UID and primary GID |
| 4 | Supplementary group count |
| 5–6 | Argument and environment counts |
| 7 | Preparation budget in milliseconds, 100–60,000 |
| 8 | Explicit policy-supplied umask, 0000–0777 |
| 9 | I/O mode: 0 for pipes, 1 for PTY |

The body contains raw supplementary group IDs, then the absolute executable pathname, arguments and sorted `NAME=value` entries.
Each string has a UInt32 byte length. Empty arguments and values, custom argv[0], and non-UTF-8 bytes remain exact.
NULs, duplicate or unsorted environment names, relative executable paths, unknown formats and trailing bytes fail.
The private frame conveys captured data. It is not a permit or public command protocol.

The child requires EOF after the complete frame. Partial frames and stalled writers have finite deadlines.
The same sleep-inclusive preparation deadline covers credential setup, status and waiting for release.
This deadline does not limit a successfully executed command's runtime.
Temporary decoded string storage is wiped on explicit cleanup. This does not promise erasure of allocator or kernel copies.

## Darwin group handling

Darwin stores the effective primary GID in the first group slot.
Its empty `setgroups` path substitutes group zero. An empty supplementary list must therefore not become `setgroups(0, ...)`.
The child normalizes the approved primary GID first, then adds only unique approved supplementary GIDs.
It rejects unions above Darwin's 16-entry limit.
It sets groups, GID and UID, then verifies real/effective IDs and the complete actual group list.

This follows Apple's [XNU credential implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_credential.c)
and [credential syscalls](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c).
Upstream source inspection and pure decoder tests do not prove privileged behavior on the installed or minimum supported OS.

## Release and outcomes

The private status record has three big-endian UInt32 words: magic `0x524d5231`, tag and errno.
Tag 1 means prepared with errno zero. Tag 2 means preparation or exec failed with the reported errno.
The child writes no command output for these records.
Only release byte 1 permits `execve`. EOF, another value or deadline exhaustion prevents dispatch.
There is no extra shell, interpreter substitution, inherited service environment or automatic retry.

The status descriptor closes on successful exec. EOF alone cannot distinguish exec from a process death.
The native supervisor establishes kernel exec/exit evidence and the owned child result.
The authority must bind those observations to the retained request before reporting a command exit status or signal.
It must retain the original request, handle caller lifetime, forward signals, cancel the process group and support terminal resize.
Those integrations remain required, along with durable permit ownership and current elevation policy.
The production launcher accepts private format 4. It adds the launch mode and the verified file metadata to the account-bound format 3.
Root checks the resolved path with the protected-path validator. The file and its ancestors must have protected ownership, permissions, ACLs and mounts.
Protected mode requires the boot system or Data volume. The classification covers the named executable. Interpreters and libraries have their own lookup.
Previously opened writable descriptors and writable mappings remain a risk.
Both modes use the resolved path and preserve arguments, working directory and environment.
After release, the child opens the executable with target credentials and checks its metadata before exec.
A failed check prevents exec. Path-bound mode retains the window between the check and the kernel's pathname lookup.
The Root local diagnostic log records the launch mode and the request ID. A confirmed pre-exec ESTALE records the executable change or stale handle.

## Path-bound timing

A normal-user fixture on arm64 macOS 27.2.1 sampled 120 launches of `/usr/bin/true` per condition.
The interval starts at the check's descriptor close and ends at the userspace `execve` call site.

| Condition | Median (µs) | 95th percentile (µs) | Maximum observed (µs) |
| --- | ---: | ---: | ---: |
| Idle | 3.583 | 5.791 | 16.291 |
| Two CPU workers | 3.167 | 5.000 | 28.292 |

Scheduling can widen this interval. The kernel pathname lookup follows it.

## Validation limits

Ten focused tests cover raw-byte preservation, malformed frames, cleanup and Darwin group normalization.
Debug and Release packaging checks verify the embedded signature, runtime, architecture and macOS 26 deployment target.
The refusal checks cover both private modes. A non-root caller cannot consume stdin or write command output.
No privileged command, Root listener, service registration, PTY session or physical device was activated.
Protected installation, Developer ID distribution and interactive credential/terminal checks remain open.
