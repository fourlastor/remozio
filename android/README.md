# Android application

The native app targets Android 17 (API 37) and later. Supported-device validation targets Pixels. Other devices need capability checks.

## Build

Use JDK 21 and an Android SDK with `platforms;android-37.0` and `build-tools;37.0.0`. Set `ANDROID_HOME` to that SDK, then run:

```sh
./gradlew :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
```

The debug APK is `android/app/build/outputs/apk/debug/android-app-debug.apk`. Its package ID is `dev.remozio.android.debug`. Production uses `dev.remozio.android` and needs a separately provisioned signing identity. The [release artifact procedure](releases.md) builds and verifies upload candidates. Production signing identity and publication still need configuration.

## Current scope

The launcher reads saved Mac records and shows the app update status card. A fresh installation has an empty Mac list. It uses native Compose, Material 3 Expressive, system light/dark colors, and a scrollable layout for large text. Pairing and request delivery are not connected yet. The update card can check GitHub releases and download a candidate after user selection. Update status uses app-private storage and installer callbacks.

Material 3 uses `1.5.0-alpha29` because the Expressive theme is not in the stable 1.4 release. Other Compose libraries use BOM `2026.09.00`. AGP supplies built-in Kotlin; the app does not apply a second Android Kotlin plugin.

The manifest declares notification permission, but the app does not request it at startup. Backup is disabled. Explicit rules exclude every storage domain from cloud backup and Android device transfers. Before adding secrets or enrollment state, validate those rules on supported devices and use installation-bound key storage.

Build and lint checks do not prove device behavior. Installation, accessibility, launch appearance, animation settings, biometrics, and background behavior need the planned Pixel test session. No device is installed or contacted by these build tasks.

References: [Android 17 setup](https://developer.android.com/about/versions/17/setup-sdk), [AGP 9.3](https://developer.android.com/build/releases/agp-9-3-0-release-notes), [Material 3 releases](https://developer.android.com/jetpack/androidx/releases/compose-material3), and [Android UX motion guidance](https://github.com/rock3r/android-ux-skills).

The [generic notification backend](../phone/core/PUSH.md) is available for future push integration. It is not connected to the launcher or Firebase yet.

## Command inspection

The debug build has a **Preview a sample command** entry and five static status scenes. It opens an invented, read-only capture in a bottom sheet below 600 dp window width, or a bounded dialog on wider windows. The sample is labelled and has no approval controls. Its fixture and entry are absent from the release source set.

The reusable inspection component renders the complete typed command capture. Invocation, target credentials, environment provenance, input, requester signing status, ancestry limits, and caller explanation have separate sections. Labels come from application resources. Request values cannot introduce UI labels or clickable links.

Values use quoted display notation, not shell syntax. Control and format characters, bidi controls, line separators, and non-ASCII spaces are escaped. Malformed UTF-8 becomes explicit byte escapes instead of replacement characters. A toggle shows every original byte in hex, including empty values and distinct Unicode spellings. Neither view truncates values. Ordinary Unicode remains readable; this does not eliminate Unicode glyph confusables.

Inspection state stays in composition memory and is not saved across process death. Closing details does not imply denial or cancellation. The authenticated session adapter supplies status and timing. The optional enrollment-bound controls connect this inspector to biometric approval and no-biometric decline. Live enrollment and transport still need launcher integration. The component alone establishes no trust in a capture.

Five Android-module JVM tests cover empty values, escaped syntax, controls, bidi, malformed UTF-8, Unicode spelling, full-byte round trips, and long values. Android unit tests now run in CI and the local PR gate. Build/lint checks do not establish layout, TalkBack reading order, large-font behavior, or sheet/dialog usability; those remain for the interactive Pixel session.

The layout uses native Material 3 components and their standard motion. There are no custom animations. Its breakpoint follows [window information](https://developer.android.com/reference/kotlin/androidx/compose/ui/platform/WindowInfo); the sheet uses [ModalBottomSheet](https://developer.android.com/develop/ui/compose/quick-guides/content/create-bottom-sheet).

The [status tracker](status-tracking.md) verifies signed updates against retained request bindings and preserves revision, outcome, and timing continuity. It remains separate from live transport and decision controls.

## Status presentation

The inspector can show request age, authorization time remaining, an optional target lifetime estimate, clock uncertainty, and an accepted phone decision. Status labels distinguish actual target timeout, Remozio expiry, disappearance with an unknown reason, and uncertain execution outcomes. An elapsed estimate never selects a terminal headline.

Only the outcome heading uses a polite accessibility live region. Timing text sits outside that node, so countdown updates do not request repeated announcements. Age rounds down and remaining time rounds up without unsigned overflow. The status uses native Material components and no custom animation.

A terminal status hides the capture and its byte toggle. The caller still owns capture disposal; hiding a view is not secure erasure or a history implementation. Pending views without a capture show that details are unavailable. Request identity keeps the sheet state stable across status revisions.

Six debug scenes cover a pending command, an elapsed target estimate, expired authorization, target disappearance, an unknown outcome, and clock uncertainty. They are explicitly labelled static previews. Generic status scenes do not load the command fixture. They do not enter a verifier or transport, grant authority, or infer a result from a timer. The release source set keeps its no-op development entry.

Five presentation tests cover the important outcome distinctions and duration rounding. Live transport, notifications, and interactive TalkBack/layout checks remain outstanding. No device was contacted by this change.

The announcement boundary follows [Compose accessibility semantics](https://developer.android.com/develop/ui/compose/accessibility/semantics): live regions should not wrap frequent countdown updates.

## Authenticated command session

`CommandRequestSession.open` verifies the issued-request signature with a key supplied by a trusted enrollment. It then checks the expected Mac/account, supported command contract, and capture semantics. The owner retains the typed capture and status tracker, without retaining the issued body. This signature check proves origin only. It does not establish freshness, current enrollment, or permission to execute.

A valid terminal status clears the owned capture before publishing its revision. Invalid signatures, conflicting revisions, and old updates cannot purge pending details or restore terminal details. An elapsed countdown alone does not clear the capture. The revision flow carries no capture data. Callers must replace old snapshots; managed memory does not provide a secure-erasure guarantee.

`CommandRequestInspection` connects that owner to the inspector. It samples `SystemClock.elapsedRealtime`, which includes deep sleep, once per second while the host lifecycle is started. Accepted status updates trigger an immediate refresh. The lifecycle cancels the timer and clears its UI snapshot when the host stops. The session remains in memory for the caller to own. Its identity keeps the sheet stable when the first status arrives.

The epoch is process-local, like the session. Neither survives process death. The future enrollment owner must discard sessions when keys or enrollment change. The adapter is not yet connected to the launcher or a transport; the debug scenes remain static. Seven phone-core JVM tests cover signed input, enrollment binding, capability checks, capture cleanup, and replay behavior. Device lifecycle, sleep, and layout checks remain deferred.

Clock and lifecycle behavior follow the [SystemClock contract](https://developer.android.com/reference/android/os/SystemClock) and [lifecycle coroutine guidance](https://developer.android.com/topic/libraries/architecture/coroutines).

The platform-independent request owner and tracker live in [phone-core](../phone/core/README.md). Android supplies lifecycle and elapsed-clock integration. Its shared core also runs against the native Swift peer in the device-free [approval-flow experiment](../docs/experiments/approval-flow.md).

The [sideload update verifier](updates.md) stages APKs privately, verifies their signatures and identity, and binds installer handoff to the verified bytes. A native installer backend now enforces verified copying and durable recording before commit. The application now owns pending update state and exposes installation, permission, cleanup, and confirmation controls. The launcher can check releases, download and verify a candidate, and then offer a separate install action. Update settings control foreground checks and prerelease discovery.

The [transport identity loader](transport-identity.md) validates an existing hardware-backed enrollment key and supplies its handle to the TLS client. Pairing, key creation, and native Pixel validation remain outstanding.

The [phone enrollment store](../phone/core/ENROLLMENTS.md) has an Android adapter with a dedicated hardware encryption key and a no-backup atomic file. It is available to the future enrollment host and does not initialize on app startup.

The [decision identity](decision-identity.md) creates and loads a separate hardware key for biometric-free choices. Its first signing adapter verifies an issued command and signs only an explicit permitted decline. App lifecycle and delivery integration remain outstanding.

The debug-only [ADB endpoint experiment](../docs/experiments/android-adb-endpoint.md) prepares system-picker discovery and explicit loopback reachability checks. It sends no ADB commands and does not implement a bridge. The [Pixel observations](../docs/experiments/evidence/2026-10-03-pixel-platform.md) establish own-phone discovery and IPv4/IPv6 loopback reachability. Wi-Fi-off fallback and bridge lifetime remain untested.

## Saved Mac inventory

The launcher opens the existing encrypted enrollment archive off the main thread. It never generates a storage key or initializes an archive. A key and archive that are both absent produce the empty view. A partial, unreadable or incompatible store produces a retryable error without resetting data.

The application owns one serialized reader across activity replacements. Each read closes its store before returning immutable display metadata: record ID, label and whether setup is incomplete. Credentials and key references never enter Compose state. Cancellation prevents a stopped reader from publishing late rows. Returning to the foreground reads again; there is no background polling.

Active records show **Not connected** and unknown current Mac status. Prepared records show **Setup incomplete**; removed records are omitted. Labels do not merge records or identify authority. Reading a restored active record cannot establish current enrollment, online presence or permission to act. The list starts no channel and exposes no presence controls or approval actions.

The adapter may create the private enrollment directory and its coordination lock, but inventory reads create no key or enrollment archive. The reader uses the archive format's existing maximum limits, with no pruning or new retention policy. Native Keystore and AtomicFile behavior still need the Pixel session. Host tests cover projection, incomplete storage, errors, retry, reader cancellation and owner closure.

The list keeps standard Material 3 Expressive cards and a standard loading indicator. Loading, errors and unknown status all have static text. No custom animation is added. TalkBack, large text and actual lifecycle timing remain device checks.

## Cached audit history

The primary Audit log destination reads existing encrypted history without biometrics. Compact windows use bottom navigation and detail sheets. Wider windows use a navigation rail and dialogs. The history list and request timeline are lazy lists, with a Close button outside the timeline.

Filters select a Mac, request type and outcome. Mac IDs distinguish duplicate labels. Each account and journal epoch remains separate. Events follow sequence order within an established chain, never a shared clock order. Request details ignore list filters and show the complete retained timeline. Gaps, conflicting proofs and unknown segment boundaries stay visible. The cache does not establish current enrollment, current Mac status or a successful recent sync.

Reading never creates an audit key, initializes an archive or prunes evidence. The reader excludes prepared setups and can use retained bindings from removed setups. Those bindings do not prove former activation or grant present authority. Both destinations share an enrollment-read lock, released before audit-cache work begins. Cache access closes before returning immutable evidence. Foreground entry and Retry trigger reads; no background polling or network connection is added. Missing history differs from unreadable history.

The decoder accepts up to 16 MiB per archive, 4,096 proofs, 50,000 records and 4,096 epochs. The reader retains at most 32 MiB of encoded proof data across displayed scopes. These are resource limits, not a total heap bound or disk retention policy. Oversized or unreadable scopes show an error without deleting data. Selecting one Mac gives it the reader budget independently. Retention settings and live synchronization remain future work.

Only closed metadata fields reach the view. Full commands, target values, UI captures and provider error text are absent. History offers no approval or replay action. Authentication labels describe evidence, not proof of a person's identity. Signed decisions, Mac acceptance, dispatch and observed results remain distinct events.

Host tests use disposable software keys and archives. They cover scope separation, filters, gaps, conflicts, ordering, read budgets, corruption and cancellation. Pixel checks still need to validate Keystore access, AtomicFile recovery, TalkBack, large text and the adaptive layouts. No real audit archive or phone was accessed during host validation.

## Notification setup

Settings is a primary destination on compact and expanded layouts. Its Notifications card reads the runtime permission, app switch and request-channel importance when resumed. Refresh reads again. Entering the screen does not request permission, create a channel or post a notification.

Set up notifications creates the existing request channel and asks for permission only after the user taps. Android app and request-channel settings remain available after denial. Creating the channel again preserves the user's channel choices. The request sender and setup screen share its definition. Update notifications retain their separate channel.

Send a local test posts generic, explicitly labelled text on the request channel. It uses a separate notification tag and no enrollment, request or provider data. Repeated tests replace that test notification. Clear local test cancels only this diagnostic. A submitted result means Android accepted the posting call; it does not prove visibility, Firebase delivery, background admission or a working Mac connection.

Permission denial, app disablement, missing channel, disabled channel, lower importance and unavailable status stay distinct. Quiet channels can still run an explicit local test. Do Not Disturb and other system settings can affect visibility even when posting is allowed. There is no automatic permission retry or startup prompt.

Host tests cover the permission and channel classification. Pixel testing still needs permission allow/deny/dismiss, return from system settings, channel changes, TalkBack, large text and actual notification appearance. No device was contacted by the host checks.

The permission flow follows [Android's Compose guidance](https://developer.android.com/develop/ui/compose/notifications/notification-permission). Channel ownership follows [Android notification channels](https://developer.android.com/develop/ui/compose/notifications/channels).

## Biometric key custody

The [biometric key component](../docs/android-biometric-keys.md) creates and inspects hardware-backed, per-use keys. The [command signer](../docs/android-command-biometrics.md) provides a request-bound native biometric prompt. Enrollment registration, launcher integration, and recovery remain pending. The debug probe alias remains separate.

The [command connection owner](../docs/android-command-connection.md) assembles the enrolled Android identity, relay, pinned TLS, request inbox, and outgoing decision checks. Launcher and wake scheduling integration remain pending.

## Native Mac pairing

The launcher has a Pair a Mac action. Compact windows use a Material bottom sheet. Expanded windows use a dialog.
Scan the Mac invitation or paste the same public pairing text. The scanner can require a Google Play services download; paste remains available.
Setup requests local network access, then discovers the separate pairing service. Names and addresses remain untrusted hints.
Pinned TLS verifies the invitation endpoint. Both screens derive the same comparison code from the complete Root transcript.

The Android owner creates fresh hardware transport, decision, and biometric keys. It does not replace an existing enrollment silently.
Explicit code comparison precedes durable PREPARED storage and a fresh biometric operation. A verified Root receipt alone activates the record.
Cancelled biometrics can be retried after another explicit comparison. Expiry prevents a new comparison operation.
Rotation retains the setup owner. Leaving setup closes its channel and joins cleanup. A prepared or uncertain record retains its keys.
Lost receipt recovery and explicit re-enrollment remain integration work. The current UI preserves incomplete records and states that uncertainty.

The debug-only PairingPreviewActivity renders synthetic layouts with inert callbacks. It never opens enrollment storage or creates a setup owner.
Its expiry scene checks return from the biometric screen after the countdown ends. This is a Compose transition check, without biometric hardware.
Native layout captures and JVM tests do not establish installed Mac services, Pixel key custody, or a complete approval flow.
