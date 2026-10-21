# Combined Android inbox

The default Requests destination observes every active Mac/account through the application foreground coordinator.
Macs, Audit log and Settings remain separate destinations. Compact windows use a navigation bar; wider windows use a rail.

## Identity and ownership

Each row retains its authenticated request session and exact connection owner.
Its list key includes the enrollment record, Mac, account and request IDs. Labels are never identity keys.
A repeated request ID on another Mac or account therefore produces a separate row.

Filters change the displayed list. They do not acquire, close or reconnect a transport.
A selected request remains bound to its session when another request arrives or the filter changes.
Removal, replacement, session closure or loss of its owner prevents that selection from opening an approval.
The connection also checks ownership when it sends a decision.

Equal Mac labels gain identity suffixes. Suffixes expand when prefixes collide.
Account suffixes distinguish accounts on the same Mac. Neither suffix establishes authority.
The authenticated enrollment and signed request establish the scope.

Connection status describes the transport only. The interface continues to state that current host presence is unknown.
A disconnected peer can retain requests whose status has changed elsewhere.

## Evidence

The Android unit suite passes 349 cases through ATC, with no failures or skips.
Five inbox tests cover scope collisions, observation without reconnection, retained selection, replacement refusal and empty owners.
The suite also includes eight foreground coordinator tests and fourteen registry tests.

The debug APK renders disposable, software-signed requests through the production inbox surface and navigation shell.
Its fixture wire cannot deliver a decision. It creates no enrollment or Android signing key.
The activity displays a synthetic preview notice.

A leased API 37 emulator produced seven final captures:

| Scene | Evidence |
| --- | --- |
| Compact, light | Three distinct scope rows and the four navigation destinations |
| Compact, dark | The same content with dark Material roles and legible system icons |
| Larger text | Compose font scale 1.3, with wrapping labels |
| Expanded, light | Landscape phone, navigation rail and a visible first Review action |
| Expanded, dark | The same expanded composition with dark Material roles |
| Empty | Pairing explanation and the Pair a Mac action |
| Storage unavailable | An explicit error and retry action |

The first review required compact list summaries and legible system icons in the forced-dark fixture.
The second review scored both fixes resolved. That verdict covers those fixes only.
The full inspection retains the detailed timing and outcome explanations.
List summaries retain the phase, deadline bounds and material uncertainty warnings.

Some initial expanded recaptures remained in portrait. They were rejected and retained as diagnostics.
After the test app state was cleared and rotation settled, both accepted expanded captures measured 2424 by 1080 pixels.
No product source changed during that recapture.

The emulator returned to its complete pre-experiment snapshot. The temporary snapshot and lease were then removed.
No physical device or installed Mac service was used.

## Remaining qualification

These results do not prove a real Mac-Pixel approval flow, tablet behavior, gestures or hardware performance.
UI interaction across arrivals, filters and a biometric operation still needs runtime qualification.
The unit tests establish the underlying identity and observation contracts.
Exact authenticated notification navigation remains a separate integration task.
The private source still requires the full repository gate before publication.

Private evidence is retained under `.build/agent-checkpoints/android-combined-inbox-visual-20261021/`.
It includes the two APKs, source hashes, capture manifests, rejected images and the local commit proof.
Unit reports are retained under `.build/agent-checkpoints/android-combined-inbox-review-fixes-20261021/`.
