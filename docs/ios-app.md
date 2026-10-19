# iOS app

Status: first build, issue #436 PR A. The app imports a pairing invitation and shows its claims. It does not
connect to a computer, store an invitation, create keys, or approve anything.

## What the app does

- **Computers** shows an empty list.
- **Add computer** reads an invitation from the camera (QR) or the clipboard, or from text typed in the field. It
  runs the strict `PairingInvitation.importText` parser from `:protocol-kotlin`. Only surrounding whitespace is
  trimmed.
- A valid invitation shows the label, Mac ID, account ID and the full fingerprint. The screen states that these are
  unverified claims. The invitation has no signature or checksum, so a changed but well-formed invitation is
  accepted with a different fingerprint. Trust starts only with the verified pairing exchange, which is not built
  yet.

## Modules

| Path | Contents |
| --- | --- |
| `protocol/kotlin` | Kotlin Multiplatform: `jvm`, `iosArm64`, `iosSimulatorArm64`. The invitation path is in `commonMain`; everything else stays in `jvmMain`. |
| `phone/ui` (`:phone-ui`) | Compose Multiplatform 1.12.2 screens (Foundation and UI only) and the `PhoneServices` interface. A JVM target runs the shared tests on Linux; Android does not use this module yet. |
| `ios` | XcodeGen spec `project.yml`, the generated `Remozio.xcodeproj`, and a SwiftUI shell that hosts the Compose view and implements the camera scanner and clipboard. |
| `tools/dev-invitation` | Development invitation for import tests on any host. |

Minimum iOS is 18.5. The bundle ID is `dev.remozio.ios`.

## Build

Requirements: macOS with Xcode 26.3 or later, and JDK 21 in `JAVA_HOME` (the Xcode build phase runs Gradle).

```sh
./gradlew :protocol-kotlin:iosSimulatorArm64Test :phone-ui:iosSimulatorArm64Test
cd ios
xcodebuild -project Remozio.xcodeproj -scheme Remozio -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

For a device or TestFlight build, pass the team at build time with `DEVELOPMENT_TEAM=<team>`. The project does not
contain a team ID.

After a change to `ios/project.yml`, run `xcodegen` in `ios/` and commit the regenerated project.

## Test invitation

No host completes pairing yet, so the device check uses a development invitation:

```sh
./gradlew :dev-invitation:run --args="--png /tmp/dev-invitation.png"
```

The tool prints the Mac ID, account ID, label, fingerprint and text, and writes the QR code as a PNG. It discards
the private keys, so its invitations can never complete a pairing. Relative `--png` paths resolve from the
repository root.

## End-to-end flow

`.maestro/ios-add-computer.yaml` pastes the `ascii` vector from `protocol/vectors/pairing-invitation-v1.json`, checks
the displayed claims, then checks that an invalid text is rejected. Run it against a simulator with the app
installed:

```sh
maestro --device <simulator UDID> test .maestro/ios-add-computer.yaml
```

CI builds the app and runs the Kotlin iOS tests; it does not run Maestro.

## Not covered yet

Pairing over the network, Secure Enclave keys, Bonjour discovery, approvals, push, and Android use of `:phone-ui`.
See #436 for the remaining steps.
