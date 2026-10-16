# Remozio

Remozio is a prototype that lets one Android app approve requests from several Macs. Production approval is not implemented yet.

The proposed app supports privileged commands, 1Password, and Little Snitch. It shows request details and requires biometrics where needed.

The [accepted implementation limits](docs/design-decisions.md) record the threat-model changes that the user approved on 2026-10-03.

The [Remozio specification](https://remozio-plan.seebrock3r.chatgpt.site/) describes the proposed architecture, app experience, and open questions.

## Repository contents

The repository contains experiments, protocol code, and partial native apps.

- The [experiment sequence](docs/experiments/README.md) and [Mac XPC experiment](docs/experiments/macos-xpc.md) record measured results and reproducible checks.
- The [protocol modules](protocol/README.md) use shared encoding fixtures in Swift and Kotlin.
- The [Android app](android/README.md) shows saved Mac records and cached audit history. It does not claim a live connection.
- The [native Mac app](macos/app/README.md) has a main window, a menu bar entry, and Settings.

## Local and pull request checks

Run both local checks:

`./scripts/check.sh`

`./gradlew :protocol-kotlin:test :phone-core:test :phone-core:approvalFlowTest :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug`

These checks require Xcode, JDK 21, and the Android SDK described in the [Android build guide](android/README.md).

Pull requests use the repository's [babysit skill](.agents/skills/babysit-pr/SKILL.md). Required checks cover Python, Mac builds, Mac interoperability, Kotlin protocol tests, Android builds and lint, and Codex review.
