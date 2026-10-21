# Android request notifications

Notification taps now use the default combined inbox. They never send a decision.
The existing generic push notification remains a navigation hint with no request identity or approval action.

## Authenticated targets

The connection observer posts a request notification only after it receives a signed pending status.
The target contains the enrollment record, Mac, account, epoch, request ID and issued-request digest.
Each target has a separate immutable PendingIntent. The URI parser accepts only the fixed version and canonical encoding.
The app resolves the target against the current enrolled connection and authenticated request session.
Display labels, incoming intent extras and request IDs alone cannot select a request.

A matching request without signed status waits for that status. The inbox projection observes signed revisions and closure.
Terminal status or exhausted authorization time produces the unavailable notice instead of opening inspection.
A missing request can arrive during the existing snapshot timeout. The app shows unavailable when that wait ends.
The notice makes no claim about a particular outcome that the phone did not observe.

The observer cancels terminal or retired targets. The system notification timeout uses the authenticated remaining time when known.
Publication and cancellation failures do not stop observation of later signed updates.
Uncertain publication attempts remain tracked for cleanup. No notification contains a decision action.

## Navigation and lifecycle

One retained navigation owner controls the root inspection surface.
A new tap cannot replace an open review or its biometric operation. The latest tap waits until that review closes.
Pairing also defers notification navigation. Neither deferral sends or approves anything.
An exact target can open outside the current list filter. A generic inbox tap resets the filter to all scopes.
Configuration recreation retains handled-intent state. A new process must resolve its intent against current authenticated state again.

## Measured evidence

The affected suites pass 356 Android tests and 281 phone-core tests through ATC, with no failures, errors or skips.
Twelve inbox and notification tests cover scope identity, immutable target encoding, queued taps, signed arrival, terminal tombstones and expiry.
They also cover publication failure, cleanup and the existing combined inbox contracts.
The final passing run retains unchanged source hashes and both XML report sets.

The first finish review found a race: a terminal session could remain in the inbox without being closed.
A notification tap could therefore select that retained session. Navigation now checks its signed status before opening.
The new control covers retained cancellation, signed zero remaining time and locally elapsed authorization time.
The confirmation review found no material regression in that fix.

A leased API 37 emulator ran a debug-only probe with fabricated public target identities.
It published two real local notifications and verified separate PendingIntents.
Sending those intents retained the same MainActivity and navigation ViewModel. Fabricated targets could not select a request.
The probe cancelled both notifications and verified their removal. A settled MainActivity capture shows the unavailable notice.
This receipt predates the final signed-status navigation fix. The final fix has unit and source-review evidence only.

The initial probe failed a check. Its original diagnostics remain retained.
The revised probe awaited asynchronous notification state and used an independent bounded lifetime; it then passed.
The accepted capture is `async-native-untrusted-target.png`. The earlier unrelated screen capture is not evidence.
The emulator returned to its complete pre-test snapshot. The owned snapshot was deleted and the lease released.
No physical device, enrollment key or installed Mac service was used.

## Remaining qualification

The probe used PendingIntent delivery, rather than tapping the system notification shade.
It does not prove FCM delivery, background recovery, a matched live host request, pairing, hardware biometrics or activity restoration after process death.
Runtime interaction while another approval or pairing operation is open still needs qualification.
The dark, larger-text and expanded captures belong to the earlier inbox baseline. They do not verify this extension in those configurations.
The private source needs the full repository gate before publication.

Private evidence remains under `.build/agent-checkpoints/`:

- `android-request-notification-stale-target-gate-20261021/`: final affected suites, source hashes and retained XML reports.
- `android-request-notification-native-20261021/`: APK, probe receipts, accepted capture and initial diagnostics.
- `android-combined-inbox-visual-20261021/round2/`: baseline display context only.
