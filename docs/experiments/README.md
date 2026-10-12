# Experiment sequence

The [design specification](https://remozio-plan.seebrock3r.chatgpt.site/) defines the product. Experiments establish evidence before implementation relies on platform behavior.

| Work | Status | Next evidence |
| --- | --- | --- |
| Android biometric key | [Pixel signing and lifecycle observations](evidence/2026-10-03-pixel-platform.md) | Enrollment retention, reboot continuity, and production approval integration |
| Swift/Kotlin approval flow | [Synthetic peer harness](approval-flow.md) | Durable admission, real enrollment, encrypted transport, and device keys |
| Swift build and XPC identity checks | [Measured with ad-hoc signing](macos-xpc.md) | macOS 26 and Developer ID repeats |
| Single app and background services | [Bundle build and seals checked](macos-packaging.md) | SMAppService registration, protected placement, update replacement |
| Release signature inspection | [Reproducible default and opt-in Developer ID controls](macos-release-signing.md) | Notarization, protected placement, and activation |
| Keys and durable authority | [Disposable enclave signing and restoration measured](macos-key-custody.md) | Pre-login availability, code access, crash and rollback cases |
| Journal consumption and recovery | [Process-crash boundaries measured](macos-authority-journal.md) | Protected local checkpoint, physical durability, production recovery |
| Command executable binding | [Path replacement and descriptor behavior measured](macos-execution-binding.md) | Accepted pathname/recheck contract; protected executor integration |
| Command caller identity | [Kernel audit token, code pin, exec and exit measured on macOS 26 and 27](macos-command-caller.md) | Production IPC, trusted signing floor, protected admission |
| Command input transfer | [Fileport identity, queued input, later streaming and PTY resize measured](macos-command-fileport.md) | macOS 26 repeat, authenticated descriptor channel, resource budgets, capture and executor integration |
| Command job control | [Private leader and session monitor measured](macos-command-job-control.md); [current monitor with nested Bash jobs measured](macos-nested-shell.md) | [Native mixed streams measured](../macos-native-stdio-layout.md); frontend signal integration, protected deployment and physical validation remain |
| Streaming encrypted channel | [TLS](tls-channel.md) and [WebSocket carrier](websocket-carrier.md) harnesses | Android keys, Cloudflare integration, protected identities, and reconnect |
| Native TLS key custody | [Disposable enclave identity and TLS exchange measured](macos-enclave-tls.md) | macOS 26 runtime, pre-login access, protected service identity, Android hardware peer |
| Presence signals | [One-shot probe prepared](macos-presence.md) | GUI-session observations, remote desktop usability, lock and brightness support |
| UI adapters | Needs interactive session | Authorized dialog fixtures |
| Per-Mac push and tunnel | Pending configuration | FCM delivery and independent Mac endpoints |
| Android ADB bridge | [Pixel discovery and loopback observations](evidence/2026-10-03-pixel-platform.md) | Wi-Fi-off fallback, listener exposure, foreground lifetime, reconnect and Stop |
| Setup exports and APK updates | Pending | Independent import, signature checks and retained pairing |

## PR sequence

1. Reproducible native Mac experiment harness and XPC evidence.
2. Build and CI infrastructure for Mac experiments, followed by app/service packaging experiments.
3. Protocol and state-machine implementation, driven by shared Swift/Kotlin conformance vectors.
4. Privileged authority and transport integration after the relevant evidence gates pass.
5. Prompt adapters, Android approval flow, push, and ADB in separate vertical changes.

Each PR records its checks and limits. An experiment result does not certify an untested configuration. Device-dependent end-to-end tests are reserved for the user's next available computer session.

## Accepted limits

The [2026-10-03 decisions](../design-decisions.md) exclude whole-Mac backup rollback and accept pathname execution after a final recheck. Other security and recovery requirements remain. Pixel checks come first; Mac service and session-state tests come last.

## Interactive session preparation

Use the [interactive handoff](interactive-handoff.md) as the single checklist for the session. It separates prepared probes from work that still needs fixtures or integration.

Before starting:

- Confirm an Apple Silicon Mac with macOS 26 or later and a supported Pixel with Android 17 or later. Record the actual OS versions; macOS 26 compatibility still needs a macOS 26 host.
- Choose the artifacts and signing identities named by the relevant procedure. Keep private signing keys on their intended devices.
- Agree on each device-setting change. Use disposable keys and synthetic requests.

### Prepared checks

The handoff's [first-session checklist](interactive-handoff.md#first-session-prepared-checks) covers app surfaces, the biometric probe, ADB endpoint discovery/reachability, XPC, enclave signing and loopback TLS. Follow each linked procedure and its cleanup steps.

The ADB endpoint probe does not enable a listener or implement the bridge. Its Wi-Fi-off check needs an explicitly provisioned endpoint. It cannot establish bridge recovery after an app update or restart.

### Later checks

The handoff's [later-session checklist](interactive-handoff.md#later-sessions-fixtures-or-integration-still-needed) preserves the tests for protected services, authority continuity, prompt adapters, presence, cloud delivery, enrollment, ADB and updates. These are not runnable product operations yet.

Service registration, lock/logout/reboot behavior, update replacement, authorized prompt fixtures and remote-desktop presence need their implementation and procedures first. The complete bridge must also support Wi-Fi-off operation, reconnect and explicit Stop before its end-to-end tests.

Do not collect passwords, ADB payloads, notification tokens, or provider secrets in committed evidence. Use the handoff's [evidence record](interactive-handoff.md#evidence-record) for results and limitations.

## Declared SDK code

The [signed dependency experiment](release-dependencies.md) checks schema 2 against the pinned Sparkle SDK.
It verifies nine signed controls and starts no installer. Protected update activation remains pending.

## Inactive release preparation

The [copy experiment](inactive-release-copy.md) checks signed copies, decoded compressed resource data, current floors and owned cleanup. Root placement, crash recovery and activation remain unproven.

## Release file attributes

The [attribute experiment](release-attributes.md) inventories every SDK node through retained descriptors and checks synthetic attributes on a signed app.
Its observations do not select a production copying policy. Compressed resource forks remain unproven.

## Copied release metadata

The [metadata policy](../macos-copied-release-metadata.md) checks copied files, directories and links.
It permits zero file flags and only OS provenance attributes.
Signature verification, protected placement and activation remain separate gates.
