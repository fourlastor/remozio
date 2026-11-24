# Accepted implementation limits

The user approved these changes on 2026-10-03.
They replace the earlier requirements for an independent whole-backup witness and a pending command-execution decision.
Production integration and platform tests remain incomplete.

## Whole-Mac backup rollback

Restoring an entire Mac to an older backup is outside the security guarantee. Such a restore can restore revoked enrollment, old policy or floors, and consumed control state. Remozio does not promise to detect that complete, internally consistent restoration.

An independent hardware or online witness is no longer a prerequisite for this threat. Keep normal offline and LAN operation. Do not add recurring authorization, forced re-pairing or a mandatory network startup check.

The following protections remain required:

- Root-controlled installation and state paths, with protection against an unprivileged process replacing files or trusted code.
- Signature verification, current enrollment checks, fresh challenges and durable replay prevention during ordinary operation and restart.
- Committed security floors and authenticated policy revisions outside replaceable application binaries. Reject older binaries against the retained current state.
- Atomic consumption, crash-consistent state transitions, a protected local checkpoint, and recovery markers. Reconcile interrupted commits before enabling permissive authority.
- Automatic retry for transient storage faults. Retain consumed actions and Unknown outcomes; never retry an uncertain external action.
- Detection and safe handling of partial replacement, inconsistent state and conflicting retained evidence. Never silently reset trust or clear history to make startup succeed.
- Device-bound, non-exportable authority keys, cross-device clone protection, and explicit re-enrollment for hardware replacement or lost identities.

The [journal experiment](experiments/macos-authority-journal.md) still demonstrates a real limitation: a matching old database and checkpoint are indistinguishable locally. The accepted boundary does not turn that observation into successful rollback detection. It also does not authorize an unprivileged caller to restore arbitrary files.

## Abandoned gateway grants

A stale candidate or activation can leave an unrecorded revision. A later grant can advance the gateway beyond that revision. Recovery requires complete signed history, so the missing record prevents reconciliation.

The Root records that a candidate or activation is no longer deliverable before signing a tombstone. This applies to a revoked or replaced enrollment epoch or an expired grant. The Root delivers an earlier revocation first. Submission controls and missing or ambiguous records cannot be abandoned.

A tombstone binds the registration, original revision, kind, operation ID and digest of the original payload and signature. The gateway requires a fresh authenticated Root lease and checks that the stored head is exactly one revision earlier. It records the tombstone and advances the head in one transaction. An identical retry returns the original receipt. No mapping, token, enrollment or delivery changes. Signed recovery history contains the tombstone at the exact revision, so the collector still requires contiguous records. The Root can compare this evidence with its retained grant. A tombstone by itself cannot reconstruct a lost grant.

Local phone revocation takes effect independently of gateway delivery. Root retains the delivery intent and reports its status separately. The Mac publisher uses tombstones to close abandoned grant revisions before delivering a later revocation or grant.

The first durable Root retirement upgrades the journal to schema 18 and commits its continuity checkpoint before signing. A Root binary that supports through schema 17 cannot open that journal. A verified tombstone advances the known gateway head and marks the original grant as abandoned. If the original signed grant reached the gateway first, its verified receipt supersedes the pending retirement. The receipt preserves the original grant result and does not restore a revoked enrollment.

The main Setup window and paired-phone controls read the same protected intent and publisher observations. A gateway without tombstone support reports that it needs an update when an abandoned grant blocks the next revision. Root retains the start time before the first delivery attempt, so a missing reply leaves an inconclusive status and elapsed time across restart. A later authenticated tombstone receipt confirms delivery. The current gateway protocol does not provide an explicit negative reply. See #889.

## Gateway control capacity

The gateway keeps its configured ordinary control limit for candidates, activations, submission controls and repeated revocations for the same phone and enrollment epoch. Each fixed registration lifecycle has room for up to 1,024 first phone revocations. Tombstones have a separate reserve equal to the configured ordinary limit. If either reserve is full, extra controls of that kind need ordinary capacity. A retry of an accepted operation uses its retained receipt and takes no additional space.

At the default limit of 4,096 ordinary controls, the receiver retains at most 9,216 control rows. At the maximum setting of 1,000,000, it retains at most 2,001,024. The reserved tombstones add at most 4 MiB at the default and about 977 MiB at the maximum, using a conservative 1 KiB per tombstone. The signed payload and the other row fields total at most 312 bytes before SQLite overhead. The reserve does not change the storage schema.

An older gateway cannot open a store whose control count exceeds its configured limit. This also affects its read-only update health check. Restore a compatible backup before downgrading. A newly provisioned registration starts a new lifecycle. A whole-Mac backup rollback is outside the guarantees for the per-lifecycle revocation reserve.

## Delayed gateway phone revocation

A signed phone revocation can only remove privileges for the enrollment epoch in the control. The gateway can recover that original control after its delivery deadline. It checks the same registration, the unchanged Root signature and a fresh lease on the authenticated Root connection. The gateway uses the latest complete snapshot accepted from any authenticated Root connection. The requesting connection must still hold a fresh lease. Recovery refuses an epoch that the snapshot lists as active. The snapshot can omit a revoked phone or list a replacement epoch. Recovery requires a current snapshot in both cases. A gateway with an inactive registration also rejects the capability query.

The receiver applies the next revision in one transaction. An exact retry returns its retained receipt. Candidate, activation and submission controls keep their existing expiry rules. Recovering a revocation does not renew a token or affect a replacement enrollment.

## Command execution by pathname

Execute the captured command by pathname after a final executable identity/content and working-directory recheck. Preserve the captured argv, deterministic environment, caller lifetime and input-source contract. Do not add an implicit shell.

On macOS, the Authority opens the symlink target from retained directories. The private child frame uses the resolved path and preserves the captured argv, including its first entry. The approval payload keeps the requested path.

The Authority hashes up to 512 MiB per executable. Each filesystem phase has a five-second monotonic deadline and uses a bounded worker pool outside the journal lock. A timed-out operation holds its slot until the filesystem call returns.

A process can still replace or modify the executable after the recheck and before the OS executes it. Scripts and dependencies can also change. Approval binds the invocation; it does not guarantee immutable approved program bytes or transitive behavior.

Do not silently relocate executable files, force another interpreter, or restrict commands to an immutable allowlist. The user accepted the documented race to preserve ordinary executable-location and argv behavior.

The [macOS 26 and 27 experiment](experiments/macos-execution-binding.md) provides the measured evidence. Production execution still needs protected service integration, authorization policy, durable consumption, process I/O and recovery. Acceptance of this contract does not enable an unimplemented executor. The [filesystem capture component](macos-command-filesystem-capture.md) now implements capture and recheck without command dispatch.

## Independent command elevation policy

The user selected a separate Remozio policy on 11 October 2026.
Setup must disclose this authority and configure explicit caller-account and target-user grants.
Remozio does not inherit sudoers restrictions or execution settings.
Administrator membership grants no automatic Remozio access.
Each command still requires exact phone approval and all execution checks.

Read current protected grants at admission and immediately before dispatch.
Missing, unreadable or revoked grants prevent execution without a cached-policy or sudo fallback.
Resolve target credentials through the OS and reject a changed captured identity.
Shared setup imports do not transfer machine-specific elevation grants.

The [policy component](macos-command-elevation-policy.md) implements canonical configuration, grant checks and native target resolution.
Setup, protected installation and command-dispatch composition remain pending.
The 1Password and Little Snitch adapter contracts remain unchanged.

## Test order and signing

The user made an Android 17 Pixel available through LAN ADB. Prepare and run its app tests first, with the user performing biometric interactions. Do not change biometric enrollment or debugging configuration automatically.

Reuse the user's existing Developer ID Application identity where suitable. Keep credentials outside the repository and select the intended identity explicitly. A certificate inspection alone does not establish private-key access, notarization or protected service behavior.

Mac service installation, lock/logout/restart, and CRD/Screen Sharing tests come last. The [interactive handoff](experiments/interactive-handoff.md) remains the test procedure, with this ordering amendment.

## Local macOS distribution and installation

The user confirmed local distribution on 14 October 2026. Apple App Store publication is outside the current scope.
A `.pkg` installer is an approved bootstrap route. Keep the services inside the single Remozio `.app`.
Do not make Apple approval for the privileged-file-operations entitlement the only installation route.
The installer must preserve the protected paths, security floors, key custody, recovery state, and explicit elevation grants.
Actual privileged installation tests remain pending in [issue #363](https://github.com/rock3r/remozio/issues/363).

Keep Sparkle update detection and installation in the implementation plan.
Updates must use the existing signed-release and protected-activation contracts.
Prioritize the first complete Mac–Pixel approval flow before the updater UI.
