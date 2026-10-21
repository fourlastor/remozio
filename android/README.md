# Android application

The native app targets Android 17 (API 37) and later. Planned device validation targets Pixels. Other devices need separate capability checks.

## Build

Build with JDK 21 and an Android SDK containing `platforms;android-37.0` and `build-tools;37.0.0`.
Set `ANDROID_HOME` to that SDK and run:

```sh
./gradlew :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
```

The build writes the debug APK to `android/app/build/outputs/apk/debug/android-app-debug.apk`. Its package ID is `dev.remozio.android.debug`.
Production uses `dev.remozio.android` and needs a separately provisioned signing identity.

The [release artifact procedure](releases.md) builds and verifies upload candidates. Production signing and publication still need configuration.

## Current scope

The launcher reads saved Mac records and shows an update status card. A fresh installation has an empty Mac list.
The app uses native Compose, Material 3 Expressive, system light/dark colors, and a scrollable layout for large text.

Pairing and request delivery are not connected yet.
The update card can check GitHub releases and download a candidate after the user selects it.
The app tracks update status through app-private storage and installer callbacks.

The app uses Material 3 `1.5.0-alpha29` because stable version 1.4 lacks the Expressive theme.
Other Compose libraries use bill of materials (BOM) `2026.09.00`.
The Android Gradle plugin (AGP) supplies built-in Kotlin. The app does not apply a second Android Kotlin plugin.

The manifest declares notification permission. The app does not request it at startup.
The app disables backup. Explicit rules exclude every storage domain from cloud backup and Android device transfers.
Before adding secrets or enrollment state, validate these rules on supported devices. Store keys in installation-bound storage.

Build and lint checks do not prove device behavior.
Installation, accessibility, launch appearance, animation settings, biometrics, and background behavior need the planned Pixel test session.
Build tasks neither install the app on a device nor contact a device.

References: [Android 17 setup](https://developer.android.com/about/versions/17/setup-sdk), [AGP 9.3](https://developer.android.com/build/releases/agp-9-3-0-release-notes), [Material 3 releases](https://developer.android.com/jetpack/androidx/releases/compose-material3), and [Android UX motion guidance](https://github.com/rock3r/android-ux-skills).

The [Firebase client settings](../docs/android-fcm-client.md) import public client options at runtime.
The client routes opaque hints through the [generic notification backend](../phone/core/PUSH.md).
Mac delivery registration and authenticated background fetching remain unimplemented.

## Command inspection

The debug build has a **Preview a sample command** entry and five static status scenes.
The sample opens an invented, read-only capture. Windows below 600 dp wide use a bottom sheet. Wider windows use a bounded dialog.
The sample has a preview label and no approval controls. The release source set excludes its fixture and entry.

The reusable inspector shows the complete typed command capture.
It separates invocation, target credentials, environment provenance, input, requester signing status, ancestry limits, and caller explanation into sections.
Application resources supply labels. Request values cannot introduce UI labels or clickable links.

The inspector quotes values for display. These quotes do not represent shell syntax.
It escapes control and format characters, bidirectional text controls, line separators, and non-ASCII spaces.
It displays malformed UTF-8 through explicit byte escapes rather than replacement characters.

A toggle shows every original byte in hex, including empty values and distinct Unicode spellings.
Neither view truncates values. Ordinary Unicode remains readable. Different Unicode glyphs can still look alike.

The inspector keeps state in composition memory. Process death clears that state.
Closing details neither denies nor cancels a request. The authenticated session adapter supplies status and timing.

Optional enrollment-bound controls connect the inspector to biometric approval and decline without biometrics.
Live enrollment and transport still need launcher integration. The inspector alone cannot establish trust in a capture.

Five Android-module JVM tests cover empty values, escaped syntax, controls, bidirectional text, malformed UTF-8, Unicode spelling, full-byte round trips, and long values.
Continuous integration (CI) and the local pull request gate run Android unit tests.

Build and lint checks do not establish layout, TalkBack reading order, large-font behavior, or sheet/dialog usability.
These checks need the interactive Pixel session.

The layout uses native Material 3 components and standard motion. It has no custom animations.
The breakpoint follows [window information](https://developer.android.com/reference/kotlin/androidx/compose/ui/platform/WindowInfo). The sheet uses [ModalBottomSheet](https://developer.android.com/develop/ui/compose/quick-guides/content/create-bottom-sheet).

The [status tracker](status-tracking.md) verifies signed updates against retained request bindings. It preserves revision, outcome, and timing continuity.
Live transport and decision controls remain separate components.

## Status presentation

The inspector can show request age, remaining authorization time, an optional target lifetime estimate, clock uncertainty, and an accepted phone decision.
Status labels distinguish actual target timeout, Remozio expiry, disappearance with an unknown reason, and uncertain execution outcomes.
An elapsed estimate never determines a terminal heading.

Only the outcome heading uses a polite accessibility live region.
Timing text stays outside that node, so countdown updates do not request repeated announcements.
The inspector rounds age down and remaining time up without unsigned overflow.
Status presentation uses native Material components and no custom animation.

A terminal status hides the capture and its byte toggle. The caller must still dispose of the capture.
Hiding a view neither securely erases data nor stores history.
Pending views without a capture report unavailable details. Request identity keeps sheet state stable across status revisions.

Six debug scenes cover a pending command, an elapsed target estimate, expired authorization, target disappearance, an unknown outcome, and clock uncertainty.
Each scene has a static preview label. Generic status scenes do not load the command fixture.

The scenes use no verifier or transport, grant no authority, and infer no result from a timer.
The release source set keeps a development entry that does nothing.

Five presentation tests cover outcome distinctions and duration rounding.
Live transport, notifications, TalkBack, and layout still need interactive checks. Host checks contact no device.

The announcement boundary follows [Compose accessibility semantics](https://developer.android.com/develop/ui/compose/accessibility/semantics). Frequent countdown updates stay outside live regions.

## Authenticated command session

`CommandRequestSession.open` verifies the issued-request signature with a key from a trusted enrollment.
It checks the expected Mac/account, supported command contract, and capture semantics.
The owner retains the typed capture and status tracker. It does not retain the issued body.

The signature check proves origin only. It does not establish freshness, current enrollment, or permission to execute.

The session clears its capture before publishing a valid terminal status revision.
Invalid signatures, conflicting revisions, and old updates cannot remove pending details or restore terminal details.
An elapsed countdown alone does not clear the capture.

The revision flow carries no capture data. Callers must replace old snapshots. Managed memory cannot guarantee secure erasure.

`CommandRequestInspection` connects the session owner to the inspector.
While the host lifecycle is started, it samples `SystemClock.elapsedRealtime` once per second. This clock includes deep sleep.
An accepted status update triggers an immediate refresh.

When the host stops, the lifecycle cancels the timer and clears the UI snapshot.
The caller still owns the session in memory. Session identity keeps the sheet stable when the first status arrives.

The epoch and session exist only within the process. Neither survives process death.
The future enrollment owner must discard sessions when keys or enrollment change.
The adapter has no launcher or transport connection yet. Debug scenes remain static.

Seven phone-core JVM tests cover signed input, enrollment binding, capability checks, capture cleanup, and replay behavior.
Device lifecycle, sleep, and layout checks remain pending.

Clock and lifecycle behavior follow the [SystemClock contract](https://developer.android.com/reference/android/os/SystemClock) and [lifecycle coroutine guidance](https://developer.android.com/topic/libraries/architecture/coroutines).

The platform-independent request owner and tracker are part of [phone-core](../phone/core/README.md).
Android supplies lifecycle and elapsed-clock integration.
The shared core also communicates with the native Swift peer in the device-free [approval-flow experiment](../docs/experiments/approval-flow.md).

The [sideload update verifier](updates.md) stages APKs privately and verifies their signatures and identity.
It binds installer handoff to the verified bytes. The native installer backend requires verified copying and durable recording before commit.

The application owns pending update state and exposes installation, permission, cleanup, and confirmation controls.
The launcher checks releases, downloads and verifies a candidate, then offers a separate install action.
Update settings control foreground checks and prerelease discovery.

The [transport identity loader](transport-identity.md) validates an existing hardware-backed enrollment key. It supplies the key handle to the TLS client.
Pairing, key creation, and native Pixel validation remain pending.

The [phone enrollment store](../phone/core/ENROLLMENTS.md) has an Android adapter with a dedicated hardware encryption key and a no-backup atomic file.
The future enrollment host can use this adapter. App startup does not initialize it.

The [decision identity](decision-identity.md) creates and loads a separate hardware key for choices that need no biometrics.
Its first signing adapter verifies an issued command and signs only an explicit permitted decline.
App lifecycle and delivery integration remain pending.

The debug-only [Android Debug Bridge (ADB) endpoint experiment](../docs/experiments/android-adb-endpoint.md) supports system-picker discovery and explicit loopback reachability checks.
It sends no ADB commands and implements no bridge.
The [Pixel observations](../docs/experiments/evidence/2026-10-03-pixel-platform.md) establish discovery of the same phone and IPv4/IPv6 loopback reachability.
Wi-Fi-off fallback and bridge lifetime remain untested.

## Saved Mac inventory

The launcher opens the existing encrypted enrollment archive off the main thread. It generates no storage key and initializes no archive.
If both key and archive are absent, the launcher shows an empty view.
A partial, unreadable, or incompatible store produces a retryable error. The launcher does not reset data.

The application keeps one serialized reader across activity replacements.
Each read closes its store before returning immutable display metadata: record ID, label, and whether setup is incomplete.
Credentials and key references never enter Compose state.

Cancellation prevents a stopped reader from publishing late rows.
The reader runs again when the app returns to the foreground. It does not poll in the background.

Active records show **Not connected** and unknown current Mac status. Prepared records show **Setup incomplete**. The list omits removed records.
Labels neither merge records nor identify authority.

Reading a restored active record cannot establish current enrollment, online presence, or permission to act.
The list opens no channel and offers no presence controls or approval actions.

The adapter can create the private enrollment directory and its coordination lock. Inventory reads create no key or enrollment archive.
The reader uses the archive format's existing maximum limits. It neither prunes records nor adds a retention policy.

Native Keystore and AtomicFile behavior still need the Pixel session.
Host tests cover projection, incomplete storage, errors, retry, reader cancellation, and owner closure.

The list uses standard Material 3 Expressive cards and a standard loading indicator.
Loading, errors, and unknown status have static text. The list has no custom animation.
TalkBack, large text, and actual lifecycle timing still need device checks.

## Cached audit history

The primary Audit log destination reads existing encrypted history without biometrics.
Compact windows use bottom navigation and detail sheets. Wider windows use a navigation rail and dialogs.
The history list and request timeline use lazy lists. The Close button stays outside the timeline.

Filters select a Mac, request type, and outcome. Mac IDs distinguish records with duplicate labels.
Each account and journal epoch remains separate. Events follow sequence order within an established chain. They do not follow a shared clock order.

Request details ignore list filters and show the complete retained timeline.
Gaps, conflicting proofs, and unknown segment boundaries stay visible.
The cache cannot establish current enrollment, current Mac status, or a successful recent sync.

Reads create no audit key, initialize no archive, and prune no evidence.
The reader excludes prepared setups. It can use retained bindings from removed setups.
These bindings neither prove former activation nor grant current authority.

Both destinations share an enrollment-read lock. The reader releases this lock before audit-cache work and closes cache access before returning immutable evidence.
Foreground entry and Retry trigger reads. The reader neither polls in the background nor opens a network connection.
The UI distinguishes missing history from unreadable history.

The decoder accepts up to 16 MiB per archive, 4,096 proofs, 50,000 records, and 4,096 epochs.
The reader retains at most 32 MiB of encoded proof data across displayed scopes.
These limits bound specific resources. They neither bound total heap use nor define disk retention.

Oversized or unreadable scopes show an error without deleting data. Selecting one Mac gives that Mac the reader budget independently.
Retention settings and live synchronization remain unimplemented.

Only fields from the closed metadata schema reach the view. The view excludes full commands, target values, UI captures, and provider error text.
History offers no approval or replay action.

Authentication labels describe evidence. They do not prove a person's identity.
Signed decisions, Mac acceptance, dispatch, and observed results remain separate events.

Host tests use disposable software keys and archives.
They cover scope separation, filters, gaps, conflicts, ordering, read budgets, corruption, and cancellation.
They access no real audit archive or phone.

Pixel checks still need to validate Keystore access, AtomicFile recovery, TalkBack, large text, and adaptive layouts.

## Notification setup

Settings is a primary destination on compact and expanded layouts.
Its Notifications card reads runtime permission, the app switch, and request-channel importance when resumed. Refresh reads these values again.
Entering the screen requests no permission, creates no channel, and posts no notification.

**Set up notifications** creates the existing request channel and asks for permission only after a user tap.
Android app and request-channel settings remain available after denial. Creating the channel again preserves the user's choices.
The request sender and setup screen share the channel definition. Update notifications use a separate channel.

**Send a local test** posts generic text with an explicit test label on the request channel.
It uses a separate notification tag and no enrollment, request, or provider data.
Repeated tests replace that notification. **Clear local test** cancels only the diagnostic notification.

A submitted result means Android accepted the posting call.
It does not prove visibility, Firebase delivery, background admission, or a working Mac connection.

The card distinguishes permission denial, app disablement, a missing channel, a disabled channel, lower importance, and unavailable status.
Quiet channels can still run an explicit local test.
Do Not Disturb and other system settings can affect visibility even when Android permits posting.
The app neither retries permission automatically nor prompts at startup.

Host tests cover permission and channel classification. They contact no device.
Pixel testing still needs to cover allowing, denying, and dismissing permission, plus returning from system settings.
Channel changes, TalkBack, large text, and actual notification appearance also need Pixel checks.

The permission flow follows [Android's Compose guidance](https://developer.android.com/develop/ui/compose/notifications/notification-permission). Channel ownership follows [Android notification channels](https://developer.android.com/develop/ui/compose/notifications/channels).

## Biometric key custody

The [biometric key component](../docs/android-biometric-keys.md) creates and inspects hardware-backed keys that require authorization for each use.
The [command signer](../docs/android-command-biometrics.md) opens a native biometric prompt bound to the request.
Enrollment registration, launcher integration, and recovery remain pending. The debug probe uses a separate alias.

The [command connection owner](../docs/android-command-connection.md) connects the enrolled Android identity, relay, pinned TLS, request inbox, and outgoing decision checks.
Launcher and wake scheduling integration remain pending.

## Native Mac pairing

The launcher has a Pair a Mac action. Compact windows use a Material bottom sheet. Expanded windows use a dialog.
The user can scan the Mac invitation or paste the same public pairing text.
The scanner can require a Google Play services download. Paste remains available.

Setup requests local network access, then discovers the separate pairing service. Names and addresses remain untrusted hints.
Pinned TLS verifies the invitation endpoint. Both screens derive the same comparison code from the complete Root transcript.

The Android owner creates fresh hardware transport, decision, and biometric keys. It never silently replaces an existing enrollment.
The user must explicitly compare codes before durable PREPARED storage and a fresh biometric operation.
Only a verified Root receipt activates the record.

After cancelling biometrics, the user can retry following another explicit comparison. Expiry prevents a new comparison operation.
Device rotation retains the setup owner. Leaving setup closes its channel and waits for cleanup.

Closing fresh setup before any biometric proof submission discards only its matching local preparation and unused keys.
Under the enrollment lock, archive removal commits before native key retirement.
Active records, changed data, other key references, and other prepared borrowers prevent cleanup.

A missing or unreadable archive preserves the keys.
If key retirement fails, the app retains the closed owner so Close can retry safely.
Any proof submission attempt preserves the record and keys, including after a lost reply. Process restart also preserves uncertain setup.

### Check incomplete pairing

Incomplete records offer **Check pairing**. This action uses the retained hardware transport identity and the separate enrolled receipt protocol.
The direct-first connector can use a retained relay route after direct connection failure.
Only a verified receipt activates the retained preparation.

Recovery requests no new biometric proof.
Missing receipts, connection errors, and cancellation before activation preserve the existing preparation and keys.
The 30-second deadline covers network work only.

After the activation boundary, a verified receipt commit finishes even if the caller cancels.
Every check refreshes saved inventory after cleanup, including after cancellation or a lost result handoff.
The displayed state follows durable storage.

Stopping the UI cancels recovery and waits for I/O before releasing the prepared-record lease.
The app requests local network permission only after the explicit action.
Denial skips local area network (LAN) discovery but still permits a retained relay route.

A failed check reports that setup remains incomplete. It never claims that the Mac did not commit.
Explicit re-enrollment remains unimplemented. The [receipt recovery contract](../protocol/pairing-receipt.md) defines recovery behavior.
Native Pixel permission, key custody, and lifecycle behavior still need interactive checks.

### Pairing previews

The debug-only `PairingPreviewActivity` renders synthetic layouts with callbacks that do nothing.
It neither opens enrollment storage nor creates a setup owner.
Its expiry scene checks the Compose transition back from the biometric screen after the countdown ends. It uses no biometric hardware.

Native layout captures and JVM tests do not establish installed Mac services, Pixel key custody, or a complete approval flow.


## Combined inbox registry

The request registry can acquire all active Mac/account owners from one archive snapshot.
It retires changed owners before constructing replacements and preserves stable owners for unchanged records.
Prepared and removed records do not create command owners. Archive read failure invalidates existing owners instead of returning stale rows.
A construction failure affects its own row. A failed retirement blocks every replacement for that same Mac/account, including a new record ID.
Other accounts remain independent. Cancellation stops new construction after mandatory stale-owner retirement.
The returned metadata uses stable record, Mac and account identities; duplicate labels do not merge owners.

Fourteen registry tests cover both individual and combined acquisition. The affected Android unit suite passed 336 cases through ATC.
These tests use synthetic archives and software keys. They contact no device or peer.
The application foreground coordinator, default combined inbox, filters and exact notification navigation remain the next integration slice.
The existing screen still displays one selected Mac; acquiring owners alone does not connect them or grant an approval.
