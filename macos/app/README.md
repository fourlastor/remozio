# Native Mac application

The Xcode target builds `Remozio.app` for macOS 26 and Apple Silicon.
The product app is separate from the disposable packaging experiment.

The SwiftUI app has a main window, a menu bar entry, and a native Settings window. The menu can reopen the main window and quit the app. Settings can hide the menu entry; the Dock and Applications remain available. That preference uses the current user's defaults. It carries no enrollment or approval authority.

Settings also define defaults for the command caller: I/O mode, disconnect behavior, readiness wait, connection backoff, control timeout, and retry intervals.
The form reports invalid durations and contradictory backoff values.
These preferences apply to new CLI invocations and carry no authority pins or installation identity.
CLI integration is still in progress. These settings do not activate a command service or change approval expiry.

The app shows an unconfigured state until protected metadata is available.
With protected service metadata, the Pair a phone sheet connects the local pairing channels.
The sheet does not provision services or complete approval UI integration.

Startup does not register privileged services or load experiment manifests.
Explicit setup actions use native administrator approval and protected installation checks.
Login registration applies only to the main app; prepared services have separate registration and identity checks.

## Build checks

Run on an Apple Silicon Mac with Xcode and a macOS 26 or later SDK:

```sh
python3 scripts/check-macos-app.py
```

The script builds Debug and Release, verifies their signatures and hardened runtime, and checks arm64 architecture, deployment targets, localization resources, and bundle contents. It does not launch either app. The repository gate runs this check on macOS.

Build outputs are under `.build/macos-app/DerivedData/Build/Products/`.
Debug uses `dev.remozio.mac.debug`; Release uses `dev.remozio.mac`.
Both use ad-hoc signing for local build validation.
The project enables the runtime signing option and disables the debug injection library.

Distribution still requires Developer ID signing, notarization, updater integration, and trusted service identities.

Logs are `.build/macos-app/xcodebuild-debug.log` and `.build/macos-app/xcodebuild-release.log`. The shared Xcode scheme is available at `macos/app/Remozio.xcodeproj`.

## Signed release declaration

The app's signed plist contains a [component release manifest](../../docs/macos-release-manifest.md).
The build records the actual signed helper hashes before signing the enclosing app.
The Core reader checks exact version sets and distinguishes absent roles from bundled code.
Strict inspection requires a trusted Developer ID identity and reads secured signing metadata.
This declaration does not install services or enable automatic updates.

## Validation limits

Compilation and bundle checks do not prove window behavior, menu accessibility, localization, VoiceOver, or large-text usability. Those checks remain for the interactive session. The app has not been installed or launched by the build script.

Native surfaces use [MenuBarExtra](https://developer.apple.com/documentation/swiftui/menubarextra), [Settings](https://developer.apple.com/documentation/swiftui/settings), and [SettingsLink](https://developer.apple.com/documentation/swiftui/settingslink).

## Setup file import

The native sheet reviews an encrypted file before applying it. A shared actor reads a bounded regular file and decrypts it away from the UI actor.
It rejects directories, FIFOs, remote URLs and oversized files. One descriptor binds each read.
The password entry clears when opening starts and when the sheet closes. Temporary password copies do not promise memory erasure.
The sheet holds an opaque reviewed proposal; its visible preview excludes credential values. Closing releases that proposal and cancels further steps.
Already completed changes remain retained for recovery.

Import requires the installed setup service, an explicitly enrolled account and prepared service accounts.
The sheet can enable the setup service or open account preparation without closing the review.
The account sheet keeps target-user selection explicit and returns before preparing a default runtime.
The imported file cannot accept local key or credential storage choices.

One explicit import attempt uses a bounded administrator session and rechecks Root before each step.
Unknown provider writes, rejected changes and pending cleanup stop the sequence. There is no automatic creation retry.
Refreshing reads local setup metadata. It does not resolve an unknown provider outcome.
Completed local setup does not prove DNS propagation, provider access, service health or phone connectivity.
Only the listed app preference keys apply after matching, authenticated local completion.
Sparse command caller settings validate against the current destination values before any preference writes.

The UI-facing Core boundaries passed 34 focused tests on their committed source.
The native Debug app passed the ATC build and inert bundle checks for this UI change.
Synthetic light/dark captures cover review, active import, cleanup, unresolved provider changes, missing prerequisites and completion.
A single review batch corrected status placement, copy and synthetic states; the confirmation build and renders passed.
These captures use disposable data and do not validate installed setup behavior.
Installed XPC, native administrator prompts, account setup navigation, file-picker behavior, keyboard focus and VoiceOver remain interactive gates.
The current host runs macOS 27.0.1 and does not qualify macOS 26 runtime behavior.

For synthetic offscreen renders of the actual views:

```sh
swift run --package-path macos/app SetupPreviewSnapshots /tmp/remozio-preview-snapshots
```

The Debug-only helper renders empty, error, scope and import states in light and dark appearance.
It does not open the product app, register services, select real files, use real credentials or contact providers.

## Embedded authority

The `RemozioAuthority` Xcode target is embedded at `Contents/Library/LaunchServices/RemozioAuthority`. Debug and Release use separate signing identifiers. The app does not launch it on startup. The bundle includes the setup daemon manifest.
Explicit setup publishes protected configuration and per-account job declarations before registration.
Installed service execution remains an interactive validation gate.

The executable accepts `--configuration /absolute/protected/configuration.cbor` for the trust-only service. It also accepts `--presence-configuration /absolute/protected/configuration.cbor` for the [presence and wake runtime](../../docs/experiments/authority-runtime-entrypoint.md). Both modes require real and effective Root identity before reading configuration.

Each mode loads its protected configuration and opens the existing journal without initialization or migration. The presence mode restores the pinned hardware signer, starts request and presence listeners, and owns independent wake recovery. It has no trust-only fallback.

SIGTERM and SIGINT stop the listener before closing the journal. Startup diagnostics omit identifiers, paths, and raw errors.

The trust-query service uses storage ceilings of 16 MiB, depth 32, and 262,144 CBOR items, with a five-second SQLite busy timeout and a one-million consumption-row ceiling. These are startup bounds for the current read-only RPC surface. Approval execution and configurable storage policy remain follow-up work.

Protected installation must validate the executable identity and release build floor before activation. It must protect the launch path, provision the service account and journal, and load the correct launchd registration. This build target does not satisfy those installation gates by itself. Do not deploy the ad-hoc build as a privileged service.

The packaging check runs only rejection paths: missing arguments and, as a normal user, non-root startup. It verifies the embedded binary's architecture, signature identity, and runtime flags. It does not start the listener or open a journal. Root activation, signal shutdown with live IPC, and pre-login recovery remain unproven.

## Embedded command child

`RemozioCommandChild` is embedded at `Contents/Helpers/RemozioCommandChild` with separate Debug and Release identities.
This small C executable prepares target credentials in a fresh process. It avoids forking the multithreaded Swift authority runtime.
It does not listen for requests or elevate an ordinary caller.
The authority does not launch it yet.

The [private launch contract](../../docs/macos-command-child.md) defines bounded input, retained descriptors and the release barrier.
The build check verifies both embedded signatures and unprivileged refusal without consuming stdin or writing to the command streams.
The parent supervisor, protected installation and current elevation policy remain required before use.

## Embedded command monitor

`RemozioCommandMonitor` is embedded at `Contents/Helpers/RemozioCommandMonitor` with separate Debug and Release identities.
It prepares one target in its dedicated session and owns that target's final wait result.
Private status buffering preserves cancellation and reaping when Root stops reading.
The [monitor contract](../../docs/macos-command-monitor.md) defines release, control, descriptor and cleanup behavior.
The authority does not launch this helper yet. Its native parent, protected installation and current elevation policy remain required.
The packaging check verifies both helper identities and non-root refusal before any private input is read.

## Embedded command frontend

The app embeds the `RemozioCommandFrontend` target as `Contents/Helpers/remozio`.
Debug uses `dev.remozio.command-frontend.debug`; Release uses `dev.remozio.command-frontend`.
Both tools preserve actual C argv bytes and require the separator before the target command.

```sh
remozio run [options] -- executable [arguments...]
remozio sudo [options] -- executable [arguments...]
```

The tool loads public installation metadata from `/Library/Application Support/Remozio/frontend.cbor`.
Root ownership and protected local ancestors remain required.
User settings come from the corresponding app's persistent preference domain.
They cannot replace installation identity or authority pins.

The CLI uses bootstrap discovery, authenticated mapped admission, and the original execution session.
It reloads protected pins before each fresh handshake under one readiness deadline.
Only verified busy refusals permit another submission.
An admitted request keeps its original policy and channel.
The loop relays PTY traffic or preserves separate pipe streams; it executes no target locally.

The packaging check verifies signatures, security generation, and byte-identical embedding.
It exercises only help and syntax refusal, including a raw non-UTF-8 argument.
Those paths consume no command stdin, write no command stdout, and log no target arguments.
The check does not submit a valid command or activate a service.

This integration is unfinished and must not be activated as a privileged installation yet.
The actual CLI loop passes composed anonymous-Mach and private-terminal tests, including verified-stop sampling, cleanup retries, and stop/resume.
The [live frontend experiment](../../docs/experiments/live-command-frontend.md) also joins the real frontend, admission owner, executor, monitor and target.
That experiment uses one unprivileged UID, software test keys and explicit fixture identity seams.
Privileged reconciliation and installed service discovery remain release gates.
Headless PTY output routing remains a pending user choice.
Setup provisioning, CLI path installation, Developer ID signing, and real-device approval tests remain separate gates.

## Installed command mode

`RemozioAuthority --command-configuration /absolute/protected/command-host.cbor` selects the existing complete command runtime.
The [host factory](../../docs/macos-installed-command-entrypoint.md) verifies current protected code, release and account metadata before native check-in.
The app bundles its fixed daemon declaration. Bundling does not register or activate it.
Setup must still publish valid host inputs, explicit elevation grants and frontend metadata.
Native installation, hardware custody, target credentials and Mac–Pixel pairing remain separate gates.

## Embedded approval transport

`RemozioTransport` is embedded at `Contents/Library/LaunchServices/RemozioTransport`.
Debug and Release have separate signing identifiers and retain security generation 1.
It accepts `--configuration /absolute/protected/transport.cbor` for direct approvals.
It also accepts `--wake-configuration /absolute/protected/wake.cbor` for the optional [wake recovery runner](../../docs/experiments/transport-wake-recovery.md).
The optional `--remote-configuration PATH` adds the [native approval relay](../../docs/experiments/native-approval-relay.md).
It includes the same transport metadata, an optional wake worker, and a fixed loopback WebSocket port.
The relay forwards opaque TLS bytes only to the current approval listener. Cloudflare provisioning remains pending.
The process loads Root-owned public metadata and requires the configured service UID as both its real and effective UID.
It rejects Root and the recorded interactive owner account.
The [native account check](../../docs/macos-service-account-startup.md) verifies a nonlogin shell, directory membership and process groups before private access.
Provisioning must still create an exclusive dedicated account and protect its key custody.

```mermaid
flowchart LR
    P[Enrolled phone] <-->|Pinned TLS 1.3| T[Dedicated transport process]
    T <-->|Authenticated current IPC| A[Root authority]
    A --> J[Protected journal]
    C[Protected configuration] --> T
    K[Provisioned transport identity] --> T
```

The configuration contains installation scope, account UIDs, authority code pins, one explicit identity location and a transport public-key pin.
It contains no private key bytes, approval key or provider credential.
The identity lookup disables authentication UI and checks the exact configured reference.
The hardware path requires a Secure Enclave P-256 private key, a matching certificate key, the configured SPKI and a current certificate validity interval.
It never searches for a replacement identity or generates a new key at startup.

The process starts the existing authenticated authority feed before accepting phone channels.
It uses the existing discovery and request-exchange handler; decisions remain Root operations.
Signal cancellation closes the service. Authority loss or listener failure closes this incarnation and returns a temporary failure.
A subsequent launch reloads configuration and performs a fresh authority handshake.
Launchd registration and restart policy are not installed by this change.

The optional wake worker restores the configured signer and creates fresh authenticated channels after recoverable failures.
Identity and configuration failures stop wake delivery. They do not stop the direct service.
Shutdown waits for the wake worker before closing the direct service.

The bundle check exercises syntax and missing-provisioning refusal only, with unread stdin and no command stdout.
Unit tests cover configuration bounds, account separation, exact lookup, blocked authentication and wrong item types.
They do not access an actual keychain identity or start a configured transport.

Pre-login identity access, TLS signing without UI, dedicated-account key custody and actual enrolled-phone delivery remain unproven.
Apple's [Mac keychain guidance](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) requires daemons outside user contexts to use the file-based keychain.
The earlier enclave TLS probe used an interactive disposable identity; it does not establish daemon support.
The [explicit transport file path](../core/transport-identity.md) supports the approved fallback as a separate provisioning choice.
Version 1 hardware configuration remains compatible. Version 2 names one service-owned private file under Root-owned ancestors.
Startup validates the private key, certificate and installation pin without a keychain search.
Lookup failures never switch custody paths. Authority and credential recipient loaders do not use the file format.
Disposable tests verify native signatures after reload; dedicated-account isolation and pre-login TLS remain activation gates for either path.
Setup, protected activation, service registration and real-device tests remain required before deployment.

## Embedded push gateway

`RemozioGateway` is embedded at `Contents/Library/LaunchServices/RemozioGateway`.
It owns the existing SQLite gateway journal, OAuth client, token cache, and bounded delivery scheduler.
The gateway runs in a dedicated account. It requires matching real and effective UIDs before reading private files.

```mermaid
flowchart LR
    R[Root authority] <-->|Signed local IPC, version 1| G[Dedicated gateway process]
    C[Root-owned public configuration] --> G
    K[Private provider credential and receipt key] --> G
    G --> J[Existing private gateway journal]
    G -->|Fixed HTTPS endpoints| F[Google OAuth and FCM]
    F -.->|Opaque wake, phone integration pending| P[Enrolled phone]
```

The process accepts only `--configuration /absolute/protected/gateway.cbor`.
Public configuration pins the registration, Root code, receipt key, service account, provider project, and local limits.
It contains no private keys or provider credentials.
Startup opens an existing journal. It never initializes, migrates, resets, or replaces one.

The private receipt key has a separate purpose and matches its configured public key.
Its public point must also match the private scalar. This software key cannot grant approval or certify recipients.
The key remains local to this Mac. Shared setup exports must exclude it.
Root and credential recipient keys retain their separate hardware custody requirements.

The listener admits one signed Root connection. Each invocation checks the kernel peer attributes before starting asynchronous work.
A harmless version handshake precedes snapshots and commands.
Snapshots carry the full registration, Root incarnation, increasing sequence, retained enrollment state, presence routing, and a short lease.
Lease expiry blocks provider handoff. Heartbeats preserve current flights and original request deadlines.
Connection loss retires the lease immediately. Shutdown cancels and drains work before closing the journal.
A replacement process needs fresh configuration, authentication, recovery, and Root state.

Root can read signed recovery pages before delivery becomes active.
The Root client returns unverified recovery data. Its query owner must verify signatures and reconcile retained history.
Candidate and recipient controls still need valid Root signatures and durable revision checks.
Token probes run as bounded service-owned tasks, so provider I/O does not occupy the control connection.
Provider acceptance does not prove phone delivery or user approval.

The bundle check verifies both build configurations, signatures, security generation, byte-identical embedding, and refusal without provisioning.
Unit tests use disposable files, keys, clocks, and provider fixtures. They do not install accounts or contact Google.
Native signed IPC, protected provisioning, launchd registration, restart behavior, and provider delivery remain activation gates.
The restricted transport submission endpoint and its credential are still pending. Root control does not replace that endpoint.
The gateway target does not activate push or register its service.

## Open at login

Settings now controls `SMAppService.mainApp`. Turning on **Open Remozio at login** registers the current app for future logins. Turning it off unregisters the main app and leaves the current app running. No separate login helper is required.

The form reads macOS status when it appears, when its scene becomes active, after a change, and on explicit refresh. It distinguishes registration awaiting approval from an eligible login item. Pending approval exposes an explicit **Open Login Items settings** button. Registration does not automatically reopen settings or override revoked consent. Errors retain the measured system status; UserDefaults supplies no successful-registration claim.

This setting controls the GUI app only. Protected daemon installation and authenticated authority readiness remain separate. The eight controller tests use fake drivers. Builds and tests perform no actual login registration. Actual registration, Login Items approval/revocation, logout/restart and native accessibility remain interactive checks. See [controller ownership](../core/mac-login-item-controls.md).

## Pairing sheet

The native sheet opens the authenticated Root channel before exposing its public invitation.
QR and copied text contain public pins only. A current TLS-bound phone candidate needs native administrator authorization before staging.
The returned Root transcript supplies the comparison code and local elapsed countdown.
An explicit **The codes match** action combines with a valid fresh phone proof before one Root commit.
The sheet distinguishes a verified Mac registration, receipt delivery, and a lost Root reply.
It never claims phone activation from a local write or retries an uncertain commit.

Public setup metadata is loaded from `presence-client-<UID>.cbor` and `pairing-client-<UID>.cbor` under the protected Remozio directory.
The files must agree on Mac, account and owner scope. They are not published by this UI change.
Closing the sheet aborts its channels and joins owned work, including pending native authorization cleanup.
The app carries no administrator form in its display state.

Nine focused logical coordinator tests pass. The Debug Xcode scheme builds the actual sheet.
Native prompts, installed service identity, phone hardware setup and the first complete approval remain interactive integration gates.

## Pair a phone

The main window opens the native pairing sheet. The app first authenticates the protected Root and transport endpoints.
The sheet shows a public QR invitation, equivalent copied text, and a bounded phone picker.
Choosing a phone requests macOS administrator authorization. The Root returns the complete staged transcript for comparison.
The Mac and Android app display the same code. An explicit Mac confirmation and a verified phone biometric proof gate one Root commit.
A missing commit reply remains Unknown. A lost delivery reply remains registered on this Mac; neither state claims phone activation.

The app reads Root-owned presence-client and pairing-client metadata for the current UID. Protected bootstrap must publish those files.
The sheet does not create configuration files, install services, or bypass the native identity checks.
The snapshot helper also renders synthetic pairing states. These captures establish layout, without enrollment or installed-service evidence.
