# Accepted implementation limits

The user approved these amendments on 2026-10-03. They supersede the earlier requirements for an independent whole-backup witness and a pending command-execution decision. They do not claim that production integration or platform tests are complete.

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

## Command execution by pathname

Execute the captured command by pathname after a final executable identity/content and working-directory recheck. Preserve the captured argv, deterministic environment, caller lifetime and input-source contract. Do not add an implicit shell.

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
