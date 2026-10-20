# Mac XPC boundary experiment

The probe tests two processes with NSXPCConnection on an Apple Silicon Mac. It sends synthetic nonces, not commands or credentials.

Run from the repository root in a logged-in GUI session:

```sh
mkdir -p experiment-results
python3 scripts/run-macos-xpc-experiment.py --output experiment-results/xpc.json
```

The output must name a new file. The runner builds for macOS 26, copies and ad-hoc signs two executables, and registers a temporary per-user LaunchAgent. It checks removal before deleting the temporary files. It does not use sudo, install a login item, alter permissions, or access application dialogs. An interrupted run attempts the same cleanup. SIGKILL cannot run cleanup; any cleanup failure identifies the temporary service in the report. Remove that service with `launchctl bootout gui/$(id -u)/<reported-service>` before rerunning.

## Measured result

[Recorded evidence](evidence/2026-09-30-xpc.json): macOS 27.0, Xcode 27.0, Swift 6.4, arm64. The binary deployment target is macOS 26. This is not a runtime test on macOS 26.

| Case | Observed result | Payload method ran |
| --- | --- | --- |
| Matching identifiers | Accepted | Yes |
| Wrong client identifier | Rejected, error 4097 | No |
| Client expects a different server identifier | Rejected, error 4102 | **Yes** |
| Wrong server, with a handshake first | Rejected, error 4102 | No |
| Matching peers, with a handshake first | Accepted | Yes |
| Matching peers after rejection cases | Accepted | Yes |

The unguarded wrong-server case checks the recorded dispatch behavior explicitly. A platform that blocks it before dispatch changes this baseline and requires a new documented result. This does not imply weaker security on that platform.

All six expected outcomes passed. The temporary service was removed.

## Implementation consequence

A client code requirement does not establish that the first outgoing method is safe to invoke. On this host, the method ran before the client rejected the reply. Use a harmless, payload-free handshake on the same connection before sending sensitive data or invoking a state-changing method. Repeat the handshake after every new connection. Never treat the connection constructor or activation as authentication success.

The listener applies its client requirement before accepting messages. The client applies its server requirement before activation. This experiment only validates an identifier requirement. Anyone who can ad-hoc sign a binary can copy that identifier. Production requires the specified Apple trust chain, Team ID, component identifier, role, account, session, and build checks.

The first harness run trapped in its error callback because Swift inferred main-actor isolation. Explicit Sendable callbacks fixed the harness. The runner also waits for launchd removal because bootout completion can precede disappearance from the service listing. Neither issue is counted as an OS security result.

## Request-frame extension

[The October 5 evidence](evidence/2026-10-05-request-frame-xpc.json) adds five cases to the six-case baseline. All 11 passed on macOS 27.0.1, targeting macOS 26. The temporary service was removed.

The probe imports `TransportAuthorityXPCProtocol` from the production core. After hello and delivery-version negotiation, it sends synthetic Data through the request-frame selector. Nonempty, empty, and nil replies remain distinct. Wrong client and server identifiers prevent frame dispatch.

This checks the actual Objective-C protocol declaration and NSXPC value bridging across two processes. The synthetic service is not the production root endpoint. It grants no request authority and does not validate protected service routing or release signing.

## Still unproven

- Runtime behavior on macOS 26.
- Developer ID, Team ID, hardened runtime, and release build-floor enforcement.
- SMAppService installation and protected executable placement.
- Root service behavior, lock/logout, reboot, FileVault boundaries, and service updates.
- Credential custody, authority rollback protection, real approval actions, and Android interoperability.

The probe is experiment code, not the production IPC layer. Its hello method has no side effects, and its only payload method echoes a synthetic nonce. Timeouts and crashes fail the experiment; they are not counted as expected rejections.

## State and decision exchange selector

[The exchange evidence](evidence/2026-10-06-request-exchange-xpc.json) adds five cases to the discovery baseline. All 19 passed. The probe negotiates the production exchange selector and tests nonempty, empty, and nil Data replies. Wrong client and server identifiers prevent query dispatch. Synthetic echo bytes do not establish decision verification, durable consumption, or signed-status delivery. Native root tests cover those component checks separately.


## Service account setup selectors

[The October 15 evidence](evidence/2026-10-15-service-accounts-xpc.json) adds six setup cases. All 25 cases passed on macOS 27.0.1, targeting macOS 26.
The temporary per-user service was removed.

The probe inherits the production `AdministrativeSetupXPCProtocol`.
It negotiates the version 3 service-account hello before reading progress or sending synthetic request and authorization bytes.
The preparation selector preserves nonempty, empty and nil Data replies across separate processes.
Wrong client and server identifiers prevent the synthetic request from reaching the service.
The progress selector has no nonce input and returns an empty result.

This tests native Objective-C selectors and NSXPC value bridging in a supported GUI session.
It uses a synthetic service with ad-hoc identifier requirements. It never imports administrator rights or creates accounts.
It does not test the production Root endpoint, installed placement, Developer ID admission, or disabled login.
The owner deferred installed Root and device tests to the interactive installation session.
Those gates remain open; this wire evidence does not close them.

## Runtime preparation selectors

[The runtime publication evidence](evidence/2026-10-15-runtime-publication-xpc.json) adds seven version 4 cases. All 32 cases passed.
The temporary GUI service was removed.
The probe checks runtime hello, progress, preparation, the custody boolean, and nonempty, empty and nil Data replies.
Wrong client and server identifiers prevent preparation dispatch after the handshake.
The selector checks use synthetic bytes. They neither import administrator rights nor publish production files.
They do not prove installed Root admission, native service ownership or complete Mac–Pixel approval.

## Runtime activation selectors

[The activation evidence](evidence/2026-10-15-runtime-activation-xpc.json) adds six version 5 cases. All 38 cases passed.
The temporary GUI service was removed.
The probe checks activation hello, progress and the explicit activation selector, including nonempty, empty and nil replies.
Wrong client and server identifiers prevent payload dispatch after the harmless handshake.
The service echoes synthetic bytes. It neither imports administrator rights nor starts production jobs.
Installed Root and Mac–Pixel behavior remain separate interactive gates.

## Pairing receipt selectors

[The receipt evidence](evidence/2026-10-16-pairing-receipt-xpc.json) adds five receipt cases. All 43 cases passed on macOS 27.0.1, targeting macOS 26.
The temporary GUI service was removed.
The probe negotiates the production receipt extension after the harmless hello. It preserves nonempty, empty and nil Data replies.
Wrong client and server identifiers prevent receipt payload dispatch.
The service echoes synthetic bytes. It has no committed enrollment, Root journal or authority key.
These results establish native selector bridging. Installed Root behavior and Pixel receipt recovery remain interactive checks.

## Phone push registration selectors

[The registration evidence](evidence/2026-10-17-push-registration-xpc.json) adds five cases. All 48 cases passed on macOS 27.0.1, targeting macOS 26.
The temporary GUI service was removed.
The probe negotiates the production registration selector after the harmless hello.
Nonempty, empty and nil Data replies remain distinct. Wrong client and server identifiers prevent registration payload dispatch.
The service echoes synthetic nonces. It does not handle provider tokens, consume a Root proof or contact FCM.
Installed Root admission, hardware signing and phone delivery remain separate gates.

The runner accepts optional `--scratch-path` and `--cache-path` arguments for isolated SwiftPM storage.
A separate cache disables the shared dependency cache. It does not change pinned package versions or XPC admission.


## Settings selectors in capability 8

The extension keeps all 81 preceding cases and adds 14 synthetic cases.
Every new client negotiates `gatewaySettingsHello` and requires capability 8 before another call.
The progress case reads an empty Data reply without a nonce payload.
Retain and resume each distinguish nonempty, empty and nil replies.
Wrong client and server identifiers must stop both operations before their nonce reaches the service.
Retain also checks empty selection and wrong authorization markers. Resume checks a wrong authorization marker.

The probe inherits the production `AdministrativeSetupXPCProtocol` declaration.
Its authorization marker is synthetic text, never an external authorization form.
Retain echoes the nonce. Resume echoes a synthetic mode-and-nonce progress payload.
These values do not represent production progress or a retained revision.
The service imports no rights and performs no settings transition.
The existing ordinary-user GUI service, timeouts and verified cleanup remain unchanged.

The 95-case matrix is prepared coverage, not a recorded live result.
Run it in a supported Mac GUI session and retain a new redacted report before capability 8 publication.
The report must show all cases passed and the temporary service absent.
This measures selector bridging and identifier refusal. It does not prove Root admission, administrator consent or installed services.
