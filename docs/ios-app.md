# iOS app

Status: TestFlight builds, issue #436. The app imports a pairing invitation, shows its claims, and can test the
connection to the computer that made the invitation. It does not pair, save a computer, or approve anything.

## What the app does

- **Computers** shows an empty list.
- **Add computer** reads an invitation from the camera (QR) or the clipboard, or from text typed in the field. It
  runs the strict `PairingInvitation.importText` parser from `:protocol-kotlin`. Only surrounding whitespace is
  trimmed.
- A valid invitation shows the label, Mac ID, account ID and the full fingerprint. The screen states that these are
  unverified claims. The invitation has no signature or checksum, so a changed but well-formed invitation is
  accepted with a different fingerprint.
- **Test connection** runs the setup exchange up to the transcript, shows the comparison code, and closes the
  channel. It sends no proof, so the computer enrolls nothing, and the app saves nothing. A test that does not reach
  the transcript within 60 seconds fails.

## Connection test

- **Route.** With the address field empty, the app looks for the computer with Bonjour: service type
  `_remozio-pairing._tcp`, instance name `R-<Mac ID>-<account ID>` with both IDs in unpadded base64url. With an
  address (`host:port`, `[IPv6]:port` or `IPv4:port`), the app connects to it and never falls back to Bonjour. Text
  that is not an address disables Test connection. The address stays in the screen state only. Debug builds also
  read `REMOZIO_PAIRING_ENDPOINT` from the environment for a test harness; a typed address wins over it.
- **Channel.** Network.framework with TLS 1.3 only, the pairing ALPN, and no session tickets or resumption. The
  computer must present exactly one certificate, valid at that moment, whose key equals the P-256 key that the
  invitation pins. An address is only a route: a wrong one can only fail.
- **Keys.** Each test makes three new P-256 keys in memory: transport, decision and biometric. On a device, the
  transport key is a temporary Secure Enclave key. It must carry the Secure Enclave token attribute and refuse
  export, or the test stops before discovery or any connection. The simulator has no Secure Enclave and uses a
  software key. The transport key signs a self-signed client certificate (swift-certificates 1.21.0, valid for one
  hour), and the handshake presents it, so the proposal and the TLS client key are the same key. The decision and
  biometric keys are CryptoKit software keys; the test signs nothing with them. Nothing goes into the keychain or
  onto disk. The [device result](experiments/ios-enclave-tls.md) records the first run on an iPhone.
- **Logs.** On a failure, the screen shows only "Could not reach the computer." The unified log (subsystem
  `dev.remozio.pairing`, category `transport`) names the failed stage and the error code, with no key data. Network
  failures also log the system's error text. Nobody has checked yet whether that text can contain an address.

## Modules

| Path | Contents |
| --- | --- |
| `protocol/kotlin` | Kotlin Multiplatform: `jvm`, `iosArm64`, `iosSimulatorArm64`. The invitation and the pairing setup messages (proposal, setup frames, transcript, receipt frame) are in `commonMain`; everything else stays in `jvmMain`. |
| `phone/pairing` (`:phone-pairing`) | The setup channel, the `PairingTransport` contract and `PlatformPairingKeys`. The iOS framework exports this module, so Swift can implement the transport. |
| `phone/ui` (`:phone-ui`) | Compose Multiplatform 1.12.2 screens (Foundation and UI only), the connection test, the address parser and the `PhoneServices` interface. A JVM target runs the shared tests on Linux; Android does not use this module yet. |
| `phone/enrollment` (`:phone-enrollment`) | The [enrollment store](../phone/enrollment/ENROLLMENTS.md). The iOS app does not use it yet. |
| `ios` | XcodeGen spec `project.yml`, the generated `Remozio.xcodeproj`, and a SwiftUI shell that hosts the Compose view. It implements the camera scanner, the clipboard, the Network.framework transport and the transport key (`PairingNetwork.swift`). `RemozioTests` holds the native tests. |
| `tools/dev-invitation` | Development invitation for import tests on any host. |

Minimum iOS is 18.5. The bundle ID is `dev.sebastiano.remozio.ios`.

## Build

Requirements: macOS with Xcode 26.3 or later, and JDK 21 in `JAVA_HOME` (the Xcode build phase runs Gradle).

```sh
./gradlew :protocol-kotlin:iosSimulatorArm64Test :phone-pairing:iosSimulatorArm64Test \
    :phone-enrollment:iosSimulatorArm64Test :phone-ui:iosSimulatorArm64Test
./scripts/build-ios-app.sh
./scripts/test-ios-app.sh
```

CI and `./scripts/check-local.sh` on macOS run the same three steps. `test-ios-app.sh` runs `RemozioTests` on the
first available iPhone simulator, so the Secure Enclave path runs only on a device.

For a device or TestFlight build, pass the team at build time with `DEVELOPMENT_TEAM=<team>`. The project does not
contain a team ID.

After a change to `ios/project.yml`, run `xcodegen` in `ios/` and commit the regenerated project.

## Test invitation

The import check uses a development invitation:

```sh
./gradlew :dev-invitation:run --args="--png /tmp/dev-invitation.png"
```

The tool prints the Mac ID, account ID, label, fingerprint and text, and writes the QR code as a PNG. It discards
the private keys, so its invitations can never pass a connection test or complete a pairing. Relative `--png` paths
resolve from the repository root.

A connection test needs a computer that holds the invitation's keys and waits for a phone, for example
`remozio-linux-pair` from `experiments/linux-pairing-peer`. The [repeat steps](experiments/ios-enclave-tls.md#repeat)
of the enclave experiment show how to run it.

## End-to-end flow

`.maestro/ios-add-computer.yaml` pastes the `ascii` vector from `protocol/vectors/pairing-invitation-v1.json` and
checks the displayed claims. It checks that an address without a port disables Test connection and that `host:port`
enables it. Then it checks that an invalid text is rejected. It does not run a connection test. Run it against a
simulator with the app installed:

```sh
maestro --device <simulator UDID> test .maestro/ios-add-computer.yaml
```

CI builds the app and runs the Kotlin and native iOS tests; it does not run Maestro.

## Not covered yet

Pairing (the proof, the Face ID signature, saving the computer), permanent enclave keys and the iOS enrollment
archive, Bonjour discovery on a device, a Mac as the peer, approvals, push, and Android use of `:phone-ui`. The key
custody decisions on #436 come before permanent keys and the archive.
