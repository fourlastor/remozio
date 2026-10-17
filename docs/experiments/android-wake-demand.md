# Android wake demand

`PendingWakeDemand` retains opaque fetch hints across journal reopen. `AndroidWakeDemand` stores them in credential-protected storage excluded from backups.
This component is not connected to FCM delivery yet. It holds no request details, routes, authority keys or approval decisions.

Each provider configuration has a generation. Each accepted mark has a new 32-byte revision.
Completing an older revision cannot clear a newer wake for the same Mac.

```mermaid
sequenceDiagram
    participant W as Wake ingress
    participant J as Durable journal
    participant F as Fetch owner
    W->>J: Mark revision A
    F->>J: Retain ticket A
    W->>J: Mark newer revision B
    F->>J: Complete ticket A
    J-->>F: False; B remains pending
    F->>J: Retain ticket B
    F->>J: Complete ticket B after authenticated delivery
    J-->>F: True; exact demand removed
```

The application must select a generation under the current provider lock. An old worker cannot select its saved generation.
The journal limits entries and encoded bytes. A failed or uncertain write retires its cached owner until reopen.
Malformed archives are refused without reset. An exclusive file lock prevents concurrent storage owners.

## Measured controls

The [Android 17 evidence](evidence/2026-10-17-android-wake-demand.json) records nine passing instrumented controls.
Four exercise actual Android storage: reopen, exact revision, exclusive ownership, malformed archives and provider replacement.
Five exercise WorkManager's testing runtime with synthetic fetch callbacks.

KEEP discards a new job while the previous job remains unfinished. APPEND_OR_REPLACE can attach a new job to an active prerequisite.
Cancelling that prerequisite later also cancels the dependent job. An independent job survives that cancellation.
The remaining controls preserve a new wake during fetch and between journal clear and worker termination.
These observations require independent admission before coalescing. They do not prove a complete delivery implementation.

## Reproduce on an emulator

Set `JAVA_HOME` for JDK 21 and `ANDROID_HOME` for SDK 37. Keep the SDK emulator and platform-tools directories on PATH.
Run `python3 scripts/prepare-android-wake-probe.py .build/wake-probe-<new-name>` from the repository root.
The script refuses an existing destination. It copies tracked sources into an isolated fixture and starts no build or device operation.
The fixture uses a separate package, a plain Application and a test-only WorkManager initializer.

1. Validate and run the generated `compile-plan.json` through `atc batch --file <plan> --validate --json`, then without `--validate`.
2. Claim an Android 17 emulator through ATC. Save a uniquely named baseline snapshot before running the device plan.
3. Validate and run `device-plan.json` through ATC. Verify nine tests, zero failures, zero errors and zero skips in its XML report.
4. Restore the baseline, delete only the temporary snapshot and free the lease through ATC.

The fixture allows 60 seconds for ADB operations. Test assertions and coroutine deadlines remain bounded separately.
Do not run this storage-clearing experiment on a personal phone or an existing Remozio package.

## Remaining integration

The application still needs durable admission before KEEP, independent notification work, bounded fetch guards and startup reconciliation.
A guard must reuse the enrolled connection owner, preserve foreground priority and recheck provider and enrollment state around every fetch.
An enqueue failure, cancellation or busy foreground owner must retain demand. A pending journal entry alone does not prove that a runnable worker exists.

No system JobScheduler delivery, quota behavior, process-death recovery, FCM delivery, authenticated network fetch or physical Pixel result is claimed.
The tests use [WorkManager's integration-test runtime](https://developer.android.com/develop/background-work/background-tasks/testing/persistent/integration-testing).
