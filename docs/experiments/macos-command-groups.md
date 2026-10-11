# Native target-group experiment

The command child currently accepts 16 groups. The full OS target lookup can return more groups, including for root.
This experiment inspects that mismatch and prepares isolated credential controls. It does not change the production credential contract.

## Measured ordinary-account evidence

On macOS 27.0.1, the system reports a group limit of 16. Directory lookup reports 24 groups for root and 17 for the current ordinary account.
The strict C probe reports 16 current process groups. A build with the SDK’s `_DARWIN_UNLIMITED_GETGROUPS` selector reports 17.
The selected SDK header maps these variants to different exported `getgroups` symbols.
These values alone do not establish the effective directory-membership behavior of a privileged child.
The ordinary account cannot invoke the privileged controls. Invalid target UIDs are refused.
The probe compiles for Apple Silicon and macOS 26 with warnings treated as errors.

## Privileged controls: unrun

Each control runs in a separate child. The parent retains its credentials and removes its disposable Root-owned fixture.
The controls compare the full root group list, full ordinary-account group list, a bounded static subset, and native `initgroups`.
For the ordinary target, a Root-owned file tests access through a group outside the bounded subset.
The result records credential API errors, observed group count, and file-access success or failure. It does not assume the membership result.
Child waits are bounded. The parent checks its unchanged UID and group list after reaping the children.
These controls require the approved interactive privileged test stage. They remain unrun in CI and this evidence.

## Why counts are insufficient

[Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_prot.c#L1433) distinguishes static `setgroups` credentials from directory-service membership.
[Apple Libinfo](https://github.com/apple-oss-distributions/Libinfo/blob/main/lookup.subproj/libinfo.c#L896) implements `initgroups` with a bounded static list and a separate membership UID.
This source evidence guides the experiment. It does not prove the behavior of the installed macOS runtime.

Do not truncate the signed target groups or reject root as a workaround. Increasing the child array alone does not prove correct credentials.
Resolve [issue #298](https://github.com/rock3r/remozio/issues/298) before activating protected dispatch. Any workflow restriction needs the user's decision.

## Run the ordinary controls

Run `python3 scripts/run-command-groups-experiment.py` as the ordinary Mac account.
The runner compiles POSIX and Darwin extended variants in a disposable directory. It never executes a privileged control.
It verifies that the ordinary account receives a refusal for privileged mode and invalid UIDs.
The JSON evidence records the source hash, host version and measured group counts.

## Prepare the interactive controls

These commands only compile the probes. They do not request elevation:

```sh
xcrun clang -target arm64-apple-macos26.0 -std=c11 -Wall -Wextra -Werror experiments/command-groups/probe.c -o /tmp/remozio-groups-posix
xcrun clang -target arm64-apple-macos26.0 -std=c11 -D_DARWIN_UNLIMITED_GETGROUPS -Wall -Wextra -Werror experiments/command-groups/probe.c -o /tmp/remozio-groups-darwin
```

The interactive stage must inspect and build the selected source in a protected temporary location before invoking it with elevation.
Both probes accept `--privileged-controls <ordinary-account-uid>`. The target UID must identify the intended ordinary account and have more directory groups than the reported limit.
They refuse Root as the ordinary target. The separate full-root-list control still uses UID 0 inside its own child.
Do not install a service, change account membership, or run arbitrary target commands for this experiment.
