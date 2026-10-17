# Remozio

Remozio is a prototype that lets one Android app approve requests from several Macs. Production approval is not implemented yet.

The proposed app supports privileged commands, 1Password, and Little Snitch. It shows request details and requires biometrics where needed.

The [accepted implementation limits](docs/design-decisions.md) record the threat-model changes that the user approved on 2026-10-03.

The [Remozio specification](https://remozio-plan.seebrock3r.chatgpt.site/) describes the proposed architecture, app experience, and open questions.

## Repository contents

The repository contains experiments, protocol code, and partial native apps.

- The [experiment sequence](docs/experiments/README.md) and [Mac XPC experiment](docs/experiments/macos-xpc.md) record measured results and reproducible checks.
- The [protocol modules](protocol/README.md) use shared encoding fixtures in Swift and Kotlin.
- The [Linux host proposal](docs/linux-host-contract.md) and [Linux validation guide](docs/linux-validation.md) track Ubuntu experiments and the remaining hardware and integration gates.
- The [Android app](android/README.md) shows saved Mac records and cached audit history. It does not claim a live connection.
- The [native Mac app](macos/app/README.md) has a main window, a menu bar entry, and Settings.

## Local and pull request checks

Run the automated checks for your host:

```sh
./scripts/check-local.sh
```

Linux runs Python, Swift protocol, portable Kotlin/phone tests, and Android unit
tests, debug assembly and lint. macOS also runs the native builds, tests and
experiments, then the Swift/Kotlin interoperability suite using its freshly built
Mac peers. Mac interoperability runs in CI for Linux contributions.

Both hosts require Python 3.11 or later, JDK 21 and the Android SDK described in the
[Android build guide](android/README.md). Linux additionally needs Swift 6.2 or later
on `PATH`; see the [Linux Swift setup](docs/experiments/linux-swift-protocol.md).
macOS needs the supported Xcode toolchain. This command is a manual local gate;
no Git hook is installed.

Pull requests use the repository's [babysit skill](.agents/skills/babysit-pr/SKILL.md).
Required checks cover Python, Linux Swift protocol, Mac builds, Mac interoperability,
Kotlin protocol tests, Android builds and lint, and Codex review. The
[CI coverage table](docs/linux-validation.md#local-gate-and-ci-coverage) maps each
local check to its CI job. Device-dependent and Mac GUI checks still require the
interactive sessions named in their experiment procedures.
