# Disposable Linux placement and ownership validator

This native C component checks that existing objects below one explicit anchor match
expectations supplied by its caller. It is component evidence for the validator named in the
[activation proposal](../../docs/linux-activation-proposal.md). It is not activation: it creates
no service or account, changes no system permission, uses no elevation or TPM provisioning, and
touches no physical device. It selects no production name, UID, filesystem policy or protocol
tag, and it does not decide the line 67 handoff or any other open proposal decision. It has no
Mac implementation.

Run with Linux 5.8 or later, Python 3.11 or later, `cc` and readable procfs child/descriptor
enumeration, without elevation or differing real/effective IDs:

```sh
python3 scripts/run-linux-placement-validator-experiment.py
python3 -m unittest discover -s tests -p test_linux_placement_validator_experiment.py
REMOZIO_LINUX_PLACEMENT_VALIDATOR_LIVE=1 python3 -m unittest discover -s tests -p test_linux_placement_validator_experiment.py
```

The runner also runs automatically in `scripts/check-linux-host.sh`, locally and in the Linux
Swift CI job. Unsupported prerequisites fail the experiment; they are not skipped. It shares the
storage lease's owned-process runner and its 15-second worker, 30-second compiler and 16-KiB
output bounds. Runtime paths, UIDs, process IDs, inode/device values and ACL contents are not
published. Source inventories are hashed before building and after all controls.

## What it checks

`rpv_acquire` reads and retains the anchor and every expected object, then rechecks all of them.
`rpv_validate` repeats that recheck later. The walk is the storage lease's
[`descriptor-walk`](../linux-storage-lease/descriptor-walk.h), now shared by both components:
`openat` with `O_NOFOLLOW`, retained descriptors and a recheck of each held and named identity
through its retained parent.

Each expectation states the kind, owner, group, exact mode and ACL policy. Each entry's parent
must be the anchor or an earlier directory entry, so no component is walked without an
expectation. These rules hold whatever the caller supplies:

- **Write permissions and special bits.** An expectation with group write, other write, set-ID or
  sticky bits refuses as an argument, so a caller cannot permit them by expecting them.
- **Extra links.** Every file must have exactly one link. Two expected names for one file refuse
  at the first name, by link count.
- **Aliases.** A symlink at or above the anchor, or at any entry, refuses. Two nodes with one
  device and inode refuse. An ordinary user cannot make that for a directory without a bind
  mount, so the directory case is an injected control.
- **Inode replacement.** A replaced anchor, directory or file refuses. A failed validation
  permanently retires the instance, and restoring the old object does not revive it.
- **Ownership.** Owner and group must equal the expectation, on every object from the anchor down.
- **ACL grants.** `RPV_ACL_NONE` refuses any stored access or default ACL, even a masked one.
  `RPV_ACL_NO_WRITE_GRANTS` admits read and execute grants and refuses a stored write grant to
  anyone but the owning user. It ignores the mask, because the owner can widen it later. Only
  ENODATA means absent; denied, unsupported, oversized or malformed ACLs refuse.
- **Same mount.** Every object must keep the anchor's device and `statx` mount ID. A bind mount
  inside the tree would refuse. No filesystem type is admitted or refused here.

Validation never repairs. A refused object keeps its mode, owner and change time.

## Evidence

The 46 controls comprise 39 live ordinary-user filesystem controls and seven explicitly injected
error controls; the report's `controlCounts` records both. Live controls include real symlinks,
hard links, FIFOs, mode changes, renames, access and default ACLs, a fork copy, close-on-exec,
failed-acquisition descriptor cleanup and a real replacement at the point between the walk and its
recheck. Owner and group mismatches are live comparisons against a differing expectation on the
same fixture.

The injected controls are `acl-unavailable`, `acl-denied`, `acl-malformed`, `mount-crossing`,
`mount-unavailable`, `device-crossing` and `directory-alias`. They use linker-wrapped calls and must
report that the injection ran. An opt-in native mutation test removes each of eleven comparisons in
turn: the healthy control must still pass and the matching control must fail.

## What this does not prove

- No root-owned or foreign-owned object was observed, and no real mount or bind mount was crossed.
  Owner comparison runs against a differing expected value, not against another account's file.
- The walk stops being checked above the explicit anchor, and `/` is not an accepted anchor. A
  walk from `/` with root-owned ancestors, as the proposal requires, remains unproved.
- Opening needs read access, so an ordinary user cannot inspect another account's 0600 file or 0700
  directory. That open fails and refuses. Which account runs the production validator is undecided.
- The file is opened before its type is checked, as in the lease. `O_NONBLOCK` stops a FIFO
  hanging the walk, but opening a device node could still have a device-specific effect.
- It does not check `security.capability`, executable contents, extra names inside a directory,
  or `/proc/self/exe`, so those proposal checks remain open.
- Checks are point-in-time observations. A hostile writer with the same account or root is not
  excluded, and multi-syscall operations are not atomic.
