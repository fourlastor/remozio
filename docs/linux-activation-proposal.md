# Linux protected services: activation proposal

Status: **unapproved proposal**, 29 October 2026. On 13 November 2026 the Linux
host owner chose decisions 5, 7 and 8 and put decisions 4 and 6 behind written
gates (see [Decisions](#decisions)). Decisions 1, 2, 3, 4 and 6 stay open. Nothing
else here is accepted policy.
It proposes concrete service identities, paths, ownership and modes, IPC peers,
startup refusals, recovery behavior and operator gates for the
[contributor guide's](https://gist.github.com/rock3r/ef069bbc6f931b83febf2e1c159cdbfa)
Phase 3. It does not approve production activation, change any contract, claim
hardware key custody, or choose the open
[line 67 handoff](linux-host-contract.md#candidate-strict-admission-profile).
Account, unit and path names are chosen (decision 8), except the execution
identity, which stays with decision 2. Every mode and limit below is still a
reviewable proposal. Nothing has been
installed, started or provisioned, and no service code exists yet.

The inputs are the [Phase 0 contract](linux-host-contract.md), whose platform table
(Ubuntu 25.10, x86_64, kernel 6.17, systemd, `SOCK_SEQPACKET`, TPM 2.0 P-256,
own-account first target) is itself still marked proposed; the
[validation guide](linux-validation.md); the merged Linux experiments; and the
macOS service design that the Linux host must stay consistent with. Where this
document repeats a contract requirement, the contract is authoritative.

## Roles and identities

The contract requires systemd system services with distinct protected authority,
transport and execution identities and a separate unprivileged session component
([contract](linux-host-contract.md#initial-platform-and-scope), line 17), each with
the least required access (line 155).

| Role | Proposed unit and identity | Owns | Must not |
| --- | --- | --- | --- |
| Authority | `remozio-authority.service`, system user `remozio-authority`, no login shell, no capabilities | Journal, continuity store, checkpoints and recovery marker; decision verification and atomic consumption; grants reading; authority TPM key; dispatch permits | Execute commands; open network sockets; read the transport key |
| Transport | `remozio-transport.service`, system user `remozio-transport`, no capabilities | Network listener, pinned TLS with its own TPM key, framing to and from the authority | Sign arbitrary bytes with the authority key, consume decisions, reach authority state, execute, reach pairing administration |
| Execution | `remozio-exec.service`; identity and privilege are an open decision (below) | Receiving one-use dispatch permits from the authority and starting the target command with the retained streams | Accept anything but an authority-issued permit; decide; retry an uncertain dispatch |
| Caller monitor | Placement is an open decision (below); candidate: a dedicated system user that keeps only `CAP_SYS_PTRACE` (decisions 2 and 5) | Trace ownership of the frontend from protected launch, the kernel-checked submission carrier | Release a stop across the dispatch handoff without the acknowledged protocol |
| Frontend | `/usr/libexec/remozio/remozio` invoked by the user; launch path is the contract's largest open gate; candidate: static, set-group-ID to `remozio-frontend` (decision 5) | Submitting one bounded request with its streams | Execute the target itself |
| Session | `remozio-session.service` as a systemd user unit, the interactive user's identity | Presence observations and read-only status | Modify authority state (contract line 156) |

Mac comparison: the Mac authority and its command helpers run as Root inside one
signed bundle, and the transport and gateway run as dedicated per-account users
(`_rmz_t_…`, `_rmz_g_…`) that must not be Root or the interactive owner
(`docs/macos-installation-inventory.md`, `docs/macos-service-account-startup.md`).
Linux deliberately separates execution from authority because the contract asks
for it; the authority itself needs no Root privilege.

The proposal starts with one machine-wide instance of each system service. The Mac
host runs per-account jobs (`dev.remozio.account.<hex>.authority`); a per-account
template (`remozio-authority@<hex>.service`) is the natural Linux extension once a
second local account is in scope (decision 7). User names follow Ubuntu's plain
`<package>-<role>` style (decision 8); the execution identity stays open
(decision 2). Stable, preallocated
system UIDs are required because state ownership is checked against them, so
`DynamicUser=` is not used.

## Paths, ownership and modes

| Path | Owner:group | Mode | Contents |
| --- | --- | --- | --- |
| `/usr/libexec/remozio/` | `root:root` | 0755 | Service and helper binaries |
| `/usr/libexec/remozio/*` | `root:root` | 0755 | Regular files, one link, no set-ID bits except the frontend below, no `security.capability` |
| `/usr/libexec/remozio/remozio` | `root:remozio-frontend` | 2755 | Frontend, candidate (decision 5): static, no program interpreter, the one set-group-ID exception; the `remozio-frontend` group has no members |
| `/usr/lib/systemd/system/remozio-*.{service,socket}` | `root:root` | 0644 | Units |
| `/usr/share/remozio/install/{sysusers.conf,state-tmpfiles.conf}` | `root:root` | 0644 | Installer-only account and persistent-state declarations, outside the `sysusers.d` and `tmpfiles.d` discovery directories |
| `/usr/lib/tmpfiles.d/remozio-runtime.conf` | `root:root` | 0644 | Boot declaration for `/run/remozio` and its socket parents only, with no persistent path |
| `/etc/remozio/` | `root:root` | 0755 | Administrator policy |
| `/etc/remozio/grants.cbor` | `root:root` | 0644 | Explicit caller-to-target grants in the shared grant format |
| `/var/lib/remozio/` | `root:root` | 0755 | State parent |
| `/var/lib/remozio/authority/` | `remozio-authority:remozio-authority` | 0700 | `journal.sqlite` and its `writer.lock`, checkpoints, recovery marker, authority key record |
| `/var/lib/remozio/authority-continuity/` | `remozio-authority:remozio-authority` | 0700 | Continuity store and its `writer.lock`, outside the journal directory as on the Mac |
| `/var/lib/remozio/transport/` | `remozio-transport:remozio-transport` | 0700 | Transport key record and certificate |
| `/run/remozio/` | `root:root` | 0755 | Socket parent |

State files are 0600 and owned by their directory's owner, matching the merged
[storage lease](../experiments/linux-storage-lease/README.md) layout
(`ANCHOR/RELATIVE/{writer.lock,…}`, 0700/0600, no POSIX ACLs, `flock`). The lease's
admitted filesystem kinds (ext family, XFS, Btrfs, tmpfs) are a fixture policy; the
production filesystem policy for `/var/lib/remozio` is still to be decided.

Every component of a binary or state path, from `/` down, must be root-owned
(state leaves: role-owned), on local storage mounted by Root, without group or
other write, special bits or ACL mutation grants, and reached without following
symlinks. This is the Mac
[protected executable placement](../macos/core/protected-executable-path.md) rule
applied to Linux; the storage lease already implements the same walk
(`openat`, `O_NOFOLLOW`, `O_DIRECTORY`, retained descriptors, recheck through
the retained parent) for an ordinary-user anchor.

Services never create, migrate, `chmod`, `chown` or replace state at startup, as
on the Mac (`macos/app/README.md`, `docs/macos-protected-setup-directories.md`).
For that reason the units do not use `StateDirectory=` or `RuntimeDirectory=`,
which create missing directories and adjust their ownership whenever the service
starts.

`systemd-tmpfiles` `d` lines also adjust the mode and ownership of an existing
directory, and `systemd-tmpfiles-setup.service` applies every discovered declaration
at boot. A persistent-state declaration in a discovery directory could therefore
repair a path before the startup refusals inspect it. The account and
persistent-state declarations stay outside discovery for that reason. The attended
installer validates every existing path first, refuses unexpected ownership or modes
rather than correcting them, and only then applies each declaration once by explicit
path (`systemd-sysusers` and `systemd-tmpfiles --create` with the absolute file name).

Only `/run/remozio` and its socket parents use an automatically discovered
declaration. `/run` is empty at boot, so that declaration creates them rather than
repairing persistent state. Service starts and restarts validate those paths and
refuse a mismatch; they do not repair them. Nothing in the package may run
`systemd-tmpfiles --create` on this declaration during an update, because that would
repair a live path. Whether updates can guarantee this belongs to open decision 6.

## IPC endpoints and peers

All endpoints are filesystem `AF_UNIX` `SOCK_SEQPACKET` sockets with bounded
messages (contract line 18). The proposal uses systemd socket units, so PID 1 (Root)
creates each socket with an explicit `SocketUser=`, `SocketGroup=` and
`SocketMode=` and passes the listening descriptor to the service. Endpoint
ownership is then established by Root, not by the service that serves it.

| Endpoint | Socket owner:group, mode | Parent directory | Connects | Served by | Peer check |
| --- | --- | --- | --- | --- | --- |
| `/run/remozio/commands/socket` | `root:remozio-frontend` 0660, candidate (decision 5) | `root:root` 0755 | The frontend only, through its set-group-ID launch | Caller monitor / authority admission | `SO_PEERPIDFD` required; effective GID `remozio-frontend`, real GID not, group absent from the supplementary list; per-message `SCM_CREDENTIALS` and kernel pidfd matching the retained admitted process (contract line 68); no other control messages; exact stream descriptor count |
| `/run/remozio/transport/socket` | `root:remozio-transport` 0660 | `root:remozio-transport` 0750 | Transport | Authority | `SO_PEERCRED` UID equals `remozio-transport`, rechecked per message; bounded request frames only |
| `/run/remozio/exec/socket` | `root:remozio-authority` 0660 | `root:remozio-authority` 0750 | Authority | Execution | `SO_PEERCRED` UID equals `remozio-authority`; one-use permits only |
| `/run/remozio/status/socket` | `root:root` 0666 | `root:root` 0755 | Session component, any local user | Authority | Requesting UID scopes the read-only answer; no state change |

Starting bounds reuse the Mac values: decisions at most 4096 bytes with a queue of
8 frames, status queries at most 64 bytes, and a per-peer work budget of 8
(maximum 64) (`docs/macos-approval-channel.md`, `macos/core/authority-xpc-endpoint.md`).
Linux measurements may change them.

UID checks authenticate the service account, not trusted code. A process that has
gained a role's UID is that role. Code identity for services comes from protected
placement, root-owned units and the startup checks below, never from the peer
connection alone. There is no setup daemon in the first slice: setup is an attended
Root command-line step.

## Startup refusals

Each service checks the following before serving and refuses to start, or starts in
a non-permissive status-only mode, when any check fails:

1. **Identity.** Real, effective, saved and filesystem UID and GID equal the role's
   account; the supplementary group set is exactly the expected one; no permitted,
   effective or ambient capabilities except the role's declared set;
   `no_new_privs` is set. A mismatch or failed lookup is permanent (`wrongAccount`
   on the Mac).
2. **Executable placement.** The installed binary path passes the placement walk,
   and `/proc/self/exe` refers to the same device and inode as the walked file.
   A replaced binary, symlink or path substitution, extra link or unexpected
   ownership refuses (contract lines 157–159). The release manifest and committed
   version floor are checked too, once the package trust policy exists.
3. **Endpoints.** Each received descriptor is `AF_UNIX`, `SOCK_SEQPACKET`, listening,
   bound to the expected path, and the path's socket file and parent have the owner,
   group and mode in the table.
4. **State.** The role's state directories and files pass the ownership walk; known
   schema; no unexplained partial replacement. Corruption, an unknown schema,
   conflicting inventory or a sticky recovery marker blocks permissive operation; it
   never clears trust or history (contract lines 163–166).
5. **Keys.** The role's TPM key record exists and opens to the expected public key.
   Missing, damaged or inaccessible hardware keys block. There is no file-key
   fallback and no automatic regeneration (contract lines 146–147).
6. **Clock.** A fresh `LinuxAuthorityClock` epoch per start, sampled from
   `CLOCK_BOOTTIME` ([shared core](../host/shared-core/README.md)).

Busy and transient I/O errors retry with backoff from 1 s up to 30 s. Identity,
schema and corruption errors are permanent and need an operator, as on the Mac
(`docs/macos-machine-store-ownership.md`, `macos/core/continuity-storage.md`).

## Recovery

- **Consumption.** One atomic transaction verifies the decision and consumes it
  (contract lines 163–166), as the composed fixture already does with SQLite.
  Outcomes follow the Mac state machine: Authorized, Executing, then Succeeded,
  Failed or Unknown. Unknown is terminal and never retried
  (`macos/core/consumption-outcomes.md`).
- **Restart.** A consumption interrupted by a restart becomes Unknown
  (`authorityRestarted`). A dispatch whose result commit failed records exactly one
  Unknown.
- **Reboot.** The authority would record the boot identifier
  (`/proc/sys/kernel/random/boot_id`) with each pending record. After a reboot,
  pending requests from the earlier boot expire and are reconciled; they are never
  revived by monotonic time from another boot. The shared clock adapter has no
  boot-ID persistence yet; this proposes it.
- **Checkpoints.** Prepare/finalize with a sticky recovery marker that no API clears,
  as in `macos/core/continuity-storage.md`. The Linux persistent catalog and its
  format remain a separate security review; this document selects none.
- **Whole backups.** The accepted whole-backup limit applies (contract lines 193–200).
  Lost hardware identity needs explicit recovery and re-enrollment.

## Proposed unit hardening

Proposed per-role systemd settings, to be verified with `systemd-analyze security`
on the target machine:

| Setting | Authority | Transport | Execution |
| --- | --- | --- | --- |
| `NoNewPrivileges=yes`, `UMask=0077`, `LockPersonality=yes` | yes | yes | see open decision 3 |
| `ProtectSystem=strict`, `ReadWritePaths=` own state only | yes | yes | see open decision 3 |
| `ProtectHome=yes` | yes | yes | no; commands run in the user's directories |
| `RestrictAddressFamilies=` | `AF_UNIX` | `AF_UNIX AF_INET AF_INET6` | `AF_UNIX` |
| `IPAddressDeny=any` | yes | no | yes |
| Device namespace and TPM exposure | unresolved, open decision 4 | unresolved, open decision 4 | `PrivateDevices=yes`, no TPM |
| `CapabilityBoundingSet=` | empty | empty | open decision 2 |
| `SystemCallFilter=@system-service` | yes | yes | open decision 3 |

## Decisions

On 13 November 2026 the Linux host owner chose decisions 5, 7 and 8 and put
decisions 4 and 6 behind written gates. Decisions 1, 2, 3, 4 and 6 stay open, and
this proposal still chooses none of them.

1. **Line 67 handoff.** [Contract line 67](linux-host-contract.md#candidate-strict-admission-profile)
   requires the monitor to own and confirm the caller's stop while committing the
   dispatch handoff. The [composed fixture](experiments/linux-composed-caller-command.md#contract-line-67-and-the-dispatch-race)
   detects and records a loss in that interval but does not prevent it. The
   candidate readings (A: detect and record, as in the fixture; B: a single owner
   holds the stop and spawns; C: pause until a production design exists) remain
   open, and nothing here selects one.
   **Open.** It depends on the protected-launch design (decision 5); review it
   again when that design has a candidate. Decision 5 now has a candidate with a
   recorded result, so this review is due.
2. **Monitor and execution privilege.** Ptrace access is checked in layers. Ubuntu's
   default Yama mode adds an ancestry rule: without `CAP_SYS_PTRACE`, a tracer may
   attach only to its descendants. Being the frontend's parent satisfies only that
   rule. The ordinary ptrace access checks still apply: matching credentials or
   `CAP_SYS_PTRACE`, the target's dumpability, and any other active LSM policy.
   A monitor under a separate service UID therefore needs `CAP_SYS_PTRACE` or
   another reviewed mechanism whether or not it launched the frontend, and a monitor
   running as the user is not protected from that user. The protected launcher
   design stays open. Starting a command as the target user needs
   `CAP_SETUID` and `CAP_SETGID`, or Root. The contract already flags that a
   narrowly privileged monitor needs its own review (lines 110–114).
   **Open.** It depends on the protected-launch design (decision 5) and on where
   the monitor runs. Candidate for the monitor, from the decision 5 design: a
   dedicated system service user that keeps only `CAP_SYS_PTRACE`. The protected
   launch experiment measured that this capability set is enough for every check
   except an outside reading of the frontend's personality, which the frontend
   reports itself. That capability can trace Root processes, so production also
   needs confinement to the frontend peer, a separate experiment. The execution
   identity stays open.
3. **Execution sandbox inheritance.** A command started directly by
   `remozio-exec.service` inherits the unit's sandbox: `NoNewPrivileges=` would
   break `sudo` inside the command, and `ProtectSystem=` would make system paths
   read-only for it. Either the execution unit stays unsandboxed apart from its
   capability set, or commands start as transient units through PID 1 with the
   retained descriptors passed as standard streams. The second changes how stream
   retention and the line 67 handoff are proved.
   **Open.** It depends on the protected-launch design (decision 5) and on the
   reading chosen for decision 1.
4. **TPM role isolation.** On Ubuntu `/dev/tpmrm0` is shared by group. Any account
   allowed to open it can use any object whose authorization it holds, so role
   separation would rest on per-role key authorization stored in each role's 0600
   state, a proposed requirement whose hardware verification is pending. Protected
   service access to the TPM is unmeasured
   ([validation guide](linux-validation.md#human-testing-boundary)). Device exposure
   is unresolved too: `PrivateDevices=yes` gives a unit a private `/dev` without
   physical device nodes, and `DeviceAllow=` grants access without adding the node,
   so a TPM-using role needs an explicitly reviewed exposure and device policy.
   **Open behind a gate.** No service uses the TPM until per-role key authorization
   and the device exposure policy are measured on the target hardware in an
   attended session, under the
   [hardware gate rules](linux-validation.md#human-testing-boundary).
5. **Protected frontend launch and code policy.** The contract's largest open gate
   (lines 95–108). The frontend path above is placement only.
   **Direction chosen: strict first.** The Linux host keeps the Mac guarantee. The
   next work is a protected-launch design and an experiment on Ubuntu. Production
   execution stays off until that experiment passes. If it shows that Ubuntu
   cannot meet the claim, the capability is reported as unsupported, and a
   narrower guarantee needs the separately reviewed contract decision that the
   contract already requires.
   **Candidate, measured on one host.** A static frontend installed set-group-ID to
   `remozio-frontend`, a group with no members; a command socket that only that
   group can open; a code policy that the frontend applies before it reads its
   arguments; and a monitor that keeps only `CAP_SYS_PTRACE` and seizes and checks
   the frontend from outside. The
   [protected launch experiment](experiments/linux-protected-launch.md) passed all
   14 cases in one supervised Root run on Ubuntu 25.10 (kernel `6.17.0-41`) on
   2026-11-13. Adopting the candidate is the Linux host owner's decision. Production
   execution stays off: monitor confinement, the production frontend, the stopped
   handoff (decision 1) and the installed services are not measured.
6. **Package and update trust.** Release manifests, version floors and update
   serialization have no Linux design yet. Updates must also avoid a
   `systemd-tmpfiles --create` run that would repair live `/run/remozio` paths.
   **Open behind a gate.** Installation stays a manual, attended operator step
   (see [Operator gates](#operator-gates)) until a design for release manifests,
   version floors and update serialization exists.
7. **Instances.** Machine-wide services first, or per-account templates from the start.
   **Chosen:** one machine-wide instance of each system service first, and a
   per-account template (`remozio-authority@<hex>.service`) once a second local
   account is in scope.
8. **Names.** Account, unit and path names.
   **Chosen:** the account, unit and path names in the tables above. The execution
   identity itself stays with decision 2.

## Operator gates

Every step below needs an attended operator with Root, and none has been run. They
are written out so review can check them before any activation work. Commands that
change the system are listed for review only.

**Before installation (read-only):**

```sh
cat /proc/sys/kernel/yama/ptrace_scope
sudo aa-status --enabled && sudo aa-status | head -n 20
ls -l /dev/tpm0 /dev/tpmrm0
getent passwd remozio-authority remozio-transport
namei -l /usr/libexec/remozio /var/lib/remozio /run/remozio /etc/remozio
```

Any existing `remozio-*` account or path blocks installation until explained.

**Installation (attended, changes the system):** apply the package's
installer-only declarations by explicit path after validating every existing path,
install the units and the runtime declaration, and do not enable the units.
TPM key creation for the authority and transport roles follows the existing
[hardware gate rules](linux-validation.md#human-testing-boundary): known-empty owner
authorization only, disposable objects first, no TPM clear, ownership reset or
eviction of unrelated handles, and before/after persistent-handle listings.

**After installation (read-only):**

```sh
systemd-analyze security remozio-authority.service remozio-transport.service remozio-exec.service
systemctl show -p User -p Group -p NoNewPrivileges -p CapabilityBoundingSet remozio-authority.service
sudo stat -c '%U:%G %a %h %n' /usr/libexec/remozio/* /var/lib/remozio /var/lib/remozio/*
sudo getfacl -p /usr/libexec/remozio /var/lib/remozio/authority /var/lib/remozio/transport
```

**Negative controls (attended, each expected to refuse):** start with a replaced
binary, an extra hard link, a symlinked parent, a group-writable state directory,
a wrong state owner, a missing TPM key record and a socket with the wrong mode;
interrupt the authority during consumption and confirm an Unknown outcome that is
not retried. Each must leave trust and history intact.

**Still not covered by these gates:** physical Pixel pairing and biometrics,
reboot and suspend reconciliation, and Mac GUI checks remain separate attended
milestones ([validation guide](linux-validation.md#human-testing-boundary)).

## What this proposal does not establish

It installs, starts or provisions nothing and contains no service code. It does not
prove protected launch, trusted frontend code, TPM role isolation, crash consistency,
reboot reconciliation or any phone interaction. The separate
[placement validator](../experiments/linux-placement-validator/README.md) checks
placement and ownership against caller-supplied expectations on ordinary-user fixtures.
It is component evidence only and decides nothing listed here.
