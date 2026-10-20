# Disposable Linux storage ownership mechanics

This native C component retains existing directory/file objects and a cooperative
writer lock for one ordinary process. Its explicit fixture anchor and owner are
not a protected installation, trusted service identity, authority journal, or
permission to issue or dispatch an approval. It does not select a Linux journal
catalog, production service UID, filesystem durability policy, or installer.

Run with Linux, Python 3.11 or later, `cc` and readable procfs child/descriptor
enumeration, without elevation or differing real/effective IDs:

```sh
python3 scripts/run-linux-storage-lease-experiment.py
python3 -m unittest discover -s tests -p test_linux_storage_lease_experiment.py
REMOZIO_LINUX_STORAGE_LEASE_LIVE=1 python3 -m unittest discover -s tests -p test_linux_storage_lease_experiment.py
```

The runner also runs automatically in `scripts/check-linux-host.sh`, locally and
in the Linux Swift CI job. Unsupported prerequisites fail the experiment; they
are not skipped or treated as successful validation. Python below 3.11 refuses
before checking procfs, building or launching any process.

The runner creates only private disposable files. Existing objects are never
accepted as test targets. Each worker has a 15-second deadline (configurable up
to 60), a 16-KiB stdout bound, discarded stderr and owned-process-group cleanup.
The compiler has a fixed 30-second bound. Only the owned compiler/worker processes
receive a private 0077 umask; the calling session's mask is unchanged. Runtime paths, UIDs, process IDs,
inode/device values, raw compiler output and ACL contents are not published.
Source inventories are hashed before building and after all controls. Any change
refuses a successful report. `--output` saves the same sanitized JSON.

The component acquires, rather than creates, the fixture's existing
`ANCHOR/RELATIVE/{writer.lock,fixture.data}`. It walks absolute anchor components
from `/` and then relative directory components with `openat`, `O_NOFOLLOW`,
`O_DIRECTORY` and `O_CLOEXEC`; empty, dot, dot-dot, trailing separators, oversized
paths/components and more than 64 retained nodes refuse. All traversed directory
identities are rechecked through their retained parent. Ancestors before the
explicit private anchor have no production ownership/ACL policy: `/tmp` is a
normal fixture parent. The anchor and every object below it require the explicit
ordinary UID, exact 0700/0600 modes, no special bits, regular single-link files,
and no stored POSIX access ACL; directories also reject default ACLs. Even masked
ACL entries with zero effective access refuse. Only ENODATA means absent; denied,
unsupported or other ACL-read errors refuse.

The fixture admits tmpfs, ext-family (the shared ext2/3/4 magic), XFS and Btrfs filesystem magic values and requires
the private subtree to remain on the anchor's device/filesystem type. This is a
bounded fixture policy, not a production filesystem certification. Unknown kinds
and failed filesystem reads refuse. Unsupported ACL semantics cannot pass a live
control. Each result names the observed fixture filesystem class. The controls create real extended/default ACLs without changing system
policy. Error controls for unavailable/denied ACL reads, unavailable/unknown
filesystems and a stored object's wrong observed UID use linker-wrapped calls
and are explicitly labelled injected evidence.

The lease owns all descriptors. No descriptor-returning API exists. Files are
opened nonblocking before type validation; no FIFO can hang acquisition. The
lock uses `flock(LOCK_EX|LOCK_NB)`. Validation failures permanently retire an
instance and retain its descriptors/lock until explicit close; restoring the old
object does not revive it. Close is idempotent, removes no files, and closes rather
than explicitly unlocking: closing an inherited child copy must not unlock the
parent's shared open-file description. A fork copy refuses validation and a fresh
process may acquire only after the owner's descriptors close. `O_CLOEXEC` is
checked by executing a fresh control process and counting its descriptors.

The 34 controls comprise 29 live ordinary-user filesystem controls and five
explicitly injected error controls; the report's `controlCounts` records both
categories. `owner-mismatch` exercises only the requested
owner/caller-identity guard. The separate injected `stored-owner-mismatch` first
acquires the healthy fixture, then changes only `fstat`'s observed UID for the
retained data object's device/inode. It requires `RSL_METADATA`, confirms that the
wrapper was exercised, verifies the real file's owner remains unchanged, and
reacquires without injection. No actual foreign-owned file or privilege transition
is tested. An opt-in native mutation test removes only the stored-UID comparison:
the healthy control must still pass and `stored-owner-mismatch` must fail.

Controls also cover ordinary reopen, invalid paths, missing objects, symlinks at
file/directory/anchor/ancestor levels, FIFO and directory substitutions, hardlinks,
unsafe modes and special bits, access/default ACLs, a competing process, forked
ownership, close-on-exec, file/lock/directory/anchor replacement, post-acquisition
mode/ACL mutation, permanent retirement, and failed-acquisition descriptor/lock
cleanup. Each control also checks its descriptor count returns to its baseline.
Portable Python tests verify exact reports, prerequisite refusal, fixed build and
source inventory, cleanup, output bounds and timeout behavior. Below-floor Python
refusal is tested with injected version tuples, without launching subprocesses;
it is not a live run of an older interpreter. Live controls are
explicitly enabled; portable validation on macOS is not Linux filesystem evidence.

Advisory locking does not stop a malicious same-account process from ignoring the
lock or modifying its own files. Metadata/ACL checks are point-in-time observations
and do not make multi-syscall operations atomic. Data contents and inode generations
are not authenticated. This component does not exclude a hostile mount namespace,
root/kernel compromise, whole-state replacement or storage rollback. It performs
no SQLite operation, fsync, migration, crash recovery, privilege transition,
service installation, TPM operation, network exchange or phone interaction.
Protected production ownership and platform policy require separate reviewed
decisions and operator validation.

Primary API references retained for review:

- [Linux open/openat semantics](https://man7.org/linux/man-pages/man2/open.2.html)
- [Linux flock open-file-description and fork semantics](https://man7.org/linux/man-pages/man2/flock.2.html)
- [Linux POSIX access/default ACLs](https://man7.org/linux/man-pages/man5/acl.5.html)
- [Linux fgetxattr absence and error semantics](https://man7.org/linux/man-pages/man2/getxattr.2.html)
