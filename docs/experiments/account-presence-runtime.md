# Account presence runtime

The account presence runtime connects durable routing modes to request discovery, signed delivery and wake publication.
The Mac app uses a separate control interface through its menu and Settings controls.
The experiment does not install or activate a service on the test host.

```mermaid
flowchart LR
    App[Signed account app] -->|Harmless hello, then scoped controls| IPC[Separate Root Mach service]
    IPC -->|Kernel identity and retained app policy| Owner[Serialized Root journal owner]
    Owner --> Mode[Durable mode and audit event]
    IPC --> Snapshot[Latest coarse presence snapshot]
    Mode --> Router[Account presence router]
    Snapshot --> Router
    Router --> Discovery[Request discovery]
    Router --> Frame[Signed request delivery]
    Router --> Wake[Opaque wake hints and registration]
```

The app and transport have different interfaces and service identities. Phone and transport messages cannot set Present or Automatic. The existing signed phone Away control remains separate. Every app invocation must pass the kernel connection check and the current retained app policy. Root also validates its own code before accessing the journal.

Each mutation contains the configured Mac/account IDs, Root clock epoch, connection ID and the next operation sequence. A mode change also contains the last observed journal revision. Root commits its audit event and mode before replying. A revision conflict returns current state and requires a fresh user action. The client never retries a mode change automatically after a lost reply.

The app displays only confirmed Root state. Connection loss clears current state. Reconnection reloads Root-owned public metadata and reads the mode again. No UserDefaults value can claim a successful mode change. This app slice reads `/Library/Application Support/Remozio/presence-client-<uid>.cbor`; protected installation must create that metadata.

Observations contain coarse signals only: usable remote workspace, lock state, bounded display states and last qualifying input time. Missing values stay unknown. All supplied values share one sample moment. Root rejects stale/future samples and mixed epochs. A discarded old or equal-time publication cannot return success. An old connection cannot withdraw a newer connection's observation. Automatic fallback and its grace interval use the existing presence policy.

## Component evidence

- The source-backed delivery test uses a real request coordinator and verifies the returned signature. It checks manual modes, fresh/expired observations, a presence change during the signing callback, and access to an already delivered request.
- Endpoint tests use the real journal. They check authenticated admission seams, scope/connection/sequence isolation, code-policy changes, revision conflicts, expiry and observer withdrawal.
- Client tests check negotiation, reply freshness, cancellation, invalid receipts and lost replies. The combined client/endpoint test commits a mode change, discards its reply and confirms it after reconnect without another write.
- Mac Debug and Release build checks compile the controls and inspect bundle/signature/runtime metadata. They do not launch the GUI or prove Developer ID deployment.

The component fixtures replace kernel invocation validation and Root self-code validation with explicit seams. Their results do not prove those platform checks. Software fixture signing is not a production custody fallback.

## Live native wire evidence

Run the owned anonymous listener fixture from a supported Mac GUI session:

```sh
python3 scripts/run-macos-presence-xpc-experiment.py \
    --evidence docs/experiments/evidence/account-presence-xpc.json
```

The [retained result](evidence/2026-10-11-account-presence-xpc.json) records a successful run on Apple Silicon with macOS 27.0.1. The build targets macOS 26. The source commit identifies the base of the modified worktree that produced the result.

The fixture uses real `NSXPCConnection` messages, the production interface, codec, endpoint, client channel and journal access. Both ends run in the same test process. The listener pins the running test binary's code hash. It checks kernel peer credentials and the current invocation connection for every selector.

The run proves mode commits, revision conflicts and fresh connection bindings. It commits a mode change before discarding the reply, then reads the committed state after reconnect. An old connection's mutation is rejected on a new connection. A discarded equal-time publication fails over the native connection. A fresh sample succeeds after reconnect. The final mode remains Automatic at revision 3, with exactly three audit events. Closing the observation connection leaves the detector unavailable.

This fixture does not register a Mach service or launch the app GUI. It uses seams for retained app policy and Root self-code validation. It does not prove Developer ID validation, Root or separate service accounts, audit-session isolation, or physical presence signals. The runner rejects a skipped test as evidence. A timeout or interruption retires the owned fixture process tree. The runner retains the log outside its temporary directory when invocation fails, skips, times out, is interrupted, or cannot clean up.

## Remaining integration and physical gates

- Protected installation must provision the distinct app service, app/Root code pins, account UID and both configuration files. The existing authority executable still selects its trust-service runner; selecting the account presence owner remains unfinished.
- The GUI controls use the authenticated channel. A platform observer has not been connected to it. Automatic mode therefore reports detector unavailability until a verified observer supplies observations; it does not infer unlocked state from absent fields.
- Qualify lock transitions, zero brightness, sleep/wake, idle accounting and exclusion of Remozio's own activity. Test usable Chrome Remote Desktop and Screen Sharing sessions, including reading without input and disconnect transitions. Process or listener existence is not a usable remote desktop signal.
- Test native Mach service registration, installed service accounts, signed code floors, audit sessions, cross-connection calls, logout/restart and update recovery. See [the installed-account gate](https://github.com/rock3r/remozio/issues/286).
- Validate controls and offline presentation in the installed GUI. These physical/device checks wait for the user's interactive session.
