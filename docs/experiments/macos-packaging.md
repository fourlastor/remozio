# One-app packaging experiment

The Xcode project builds one arm64 app with two separate Swift tool targets. The session probe and authority probe occupy different processes. Neither has an XPC listener, credentials, approval logic, or a command execution interface.

```text
RemozioPackaging.app/
  Contents/
    MacOS/RemozioPackaging
    Helpers/
      RemozioSessionProbe
      RemozioAuthorityProbe
    Library/
      LaunchAgents/dev.sebastiano.remozio.macos.experiments.session.plist
      LaunchDaemons/dev.sebastiano.remozio.macos.experiments.authority.plist
```

The SwiftUI window reports SMAppService registration status. It never registers or unregisters a service. The probes print their role only with `--describe`; other invocations exit with `EX_UNAVAILABLE`. There is no startup loop or persistent background job.

## Run the build checks

On an Apple Silicon Mac with Xcode and the macOS 26 SDK or newer:

```sh
python3 scripts/check-macos-packaging.py
# Optional evidence file; an existing file will not be overwritten:
python3 scripts/check-macos-packaging.py --output experiment-results/packaging.json
```

Create the output directory first. The script builds the shared Xcode scheme and saves the build log to `.build/packaging/xcodebuild.log`. It verifies the bundle layout, launch manifests, arm64 slices, macOS 26 deployment target, role identifiers, hardened runtime, and absence of privilege or debugging entitlements. It invokes the harmless probes directly as the current user. It checks that modifying nested code or a launch manifest breaks signature validation. It does not open the app or register services.

`./scripts/check.sh` runs these checks on macOS. Linux runs the existing Python checks. CI evidence covers packaging; it does not cover service installation.

## What this establishes

The [recorded check](evidence/2026-10-01-packaging.json) exercises ad-hoc signed packaging on the recorded host. Ad-hoc identifiers are reproducible labels, not trusted publisher identities. Another local binary can claim them. Production XPC requirements must include the approved signing chain, Team ID, and role, plus the runtime checks in the design.

The project uses Xcode application and tool targets. Xcode signs the tools, copies them into the app, and seals the complete bundle. The launch manifests use the bundle-relative `BundleProgram` layout documented in the installed SDK's `SMAppService.h`.

## Evidence still required

- Developer ID signing, notarization, and restricted release entitlements.
- Protected installation and staging paths, including all parent directories.
- Actual SMAppService registration, approval, removal, and per-user behavior.
- Login, lock, logout, restart, and service replacement during updates.
- Transport under a dedicated service account before GUI login.
- Same-user modification, old signed binary replacement, and rollback rejection.

No valid code-signing identity was available on the experiment host. The generated app is an experiment, not an installer or a release. The service manifests must not be used as production registrations. The authority probe does not exercise root execution.

The SDK states that changed executables or manifests require service re-registration. It recommends unregistering before re-registering an executable. The release updater therefore needs the separate activation experiment from the design. A successful bundle check does not establish update continuity.
