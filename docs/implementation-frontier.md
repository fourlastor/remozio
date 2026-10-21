# Implementation frontier

This source checkpoint follows the approved [plan](../IMPLEMENTATION-PLAN.md) and [later decisions](design-decisions.md).
It is not a completion audit or a claim of product acceptance. The complete approved scope remains open.
The next product change is the default Android inbox for all enrolled Macs.

| Area | Current evidence or inspected source | Remaining boundary |
| --- | --- | --- |
| Command approval | CLI, authority, transport, execution and phone components exist. The interactive handoff identifies their installed gates. | First installed Mac-Pixel approval and denial; actual service and device behavior. |
| Several Macs | The combined registry and app-owned foreground coordinator pass their isolation and cancellation controls. The root lifecycle starts all active peers; the selected-Mac screen observes them. | Default combined inbox, filters and exact notification routing. |
| Phone routing control | Root routing journal supports signed Away control. No phone/app integration was found in the inspected sources. | Authenticated status and Set Away; preserve Mac-only Automatic and Present. |
| Push | The application starts registration and wake workers. Mac import prepares the configured gateway. | Real registration, FCM delivery, background recovery and provider-backed results. |
| Audit history | Cached history UI and a shared sync session exist. This pass did not verify the complete live sync composition. | Verify and integrate live synchronization and retention settings. |
| UI adapters | No Accessibility capture or dispatch call was found in the inspected Mac app/Core Swift targets. | Authorized 1Password and Little Snitch fixtures, capture, bound dispatch and phone UI. Both adapters remain mandatory. |
| Portable setup | Private native import and explicit refusal recovery connect the reviewed file to setup steps. | Full repository gate, installed Root authorization, independent import and provider-backed recovery. |
| Relay | Process, supervisor and HTTP readiness pass the owned loopback experiment. | Installed dedicated identity, native factory, real Access/Tunnel behavior and peer delivery. |
| Distribution | Android update controls and the Mac package/notarization procedure exist. | Verify full updater composition; Sparkle integration and compatible protected activation remain part of the plan. |
| Optional ADB | The Android discovery/reachability experiment exists; no production Android bridge file was found in the inspected main source set. | Complete authenticated byte stream, enabled-pair lifetime, mobile-data fallback, restart and explicit Stop. |

The table distinguishes inspected source from measured runtime evidence. It does not certify the unreviewed parts of each area.
Mac presence, remote-desktop behavior, lock/logout/restart and all real device results remain subject to the [interactive handoff](experiments/interactive-handoff.md).
Source documentation contains historical statements. Verify their current call paths before using them as an implementation status.

## Next focused integration

The application now uses one foreground coordinator across every active Mac/account.
Eight coordinator tests cover healthy refresh, failure isolation, replacement cleanup, storage recovery, lifecycle replacement, missing owners, removal and a cancelled waiting host.
The Android unit suite passes 344 cases. These tests do not prove installed activity or physical device behavior.
The private source still needs the full repository gate before publication.
Keep connection jobs independent. Filters and navigation must not reconnect peers or replace an open request or biometric operation.
Key request rows and selections by their complete enrollment scope, rather than a request ID or label alone.
Expose individual unavailable peers without disabling the other scopes.
Then connect the default combined inbox, preserve the Devices/Audit/Settings surfaces, and bind notification navigation to authenticated requests.
No new confirmation, biometric prompt, forced re-enrollment or hidden connection limit is authorized by this integration.

The current private tree still needs its full local gate. PR #493 awaits its current-head review before the next own PR can publish.
Contributor #489 is merged with attribution and its branch preserved. Its main-branch changes require a fresh material-base comparison before using older gate evidence.
