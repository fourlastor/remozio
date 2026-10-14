# Authority runtime entrypoint

The embedded authority accepts `--presence-configuration /absolute/protected/configuration.cbor`. This selects the presence and request runtime. The explicit `--configuration` mode retains the earlier trust-only runtime.

Both modes require real and effective Root identity before reading configuration. Selecting the request mode never falls back to the trust-only service.

```mermaid
flowchart TD
    A[Embedded authority executable] --> U[Require real and effective Root identity]
    U --> C[Load protected presence configuration]
    C --> R[Restore pinned hardware signer and one Root journal]
    R --> D[Start request and account-presence listeners]
    D --> W[Independent wake publisher recovery]
    C -->|Temporary storage failure| B[Bounded startup retry]
    B --> C
    C -->|Configuration or continuity failure| F[Stop with a generic diagnostic]
    D -->|Runtime retirement| S[Close owned runtime]
    A -->|SIGTERM or SIGINT| S
```

## Startup and shutdown

Every startup attempt reloads protected metadata. Only temporary storage failures retry. Configuration, history recovery, and continuity repair failures remain distinct terminal states. An already retired runtime never reports successful startup.

The runner owns the asynchronous service and its worker. Shutdown cancels future attempts, waits for an active factory, and closes any service that factory returns. Concurrent close calls share one cleanup attempt. Failed cleanup stays owned for a later retry. Releasing the runner also cancels its worker and schedules cleanup.

The executable handles termination and interruption signals through owned dispatch sources. It waits for cleanup before returning success for cancellation. Shutdown failure returns a failure status. Diagnostics exclude private paths and configuration contents.

## Expiry ownership

Local request observations now retain their request kind after terminal transitions. This changes no signed status or protocol encoding.

Command expiry already closes the original command resources in the coordinator. The runtime accepts that cleanup path. An expired request from an unattached UI adapter fails maintenance instead of pretending that its original UI resources were released. Each future adapter must supply its own cleanup integration.

## Evidence and remaining gates

The focused runtime suite passed 11 tests on 2026-10-11. A regression first reproduced rejection of a target-timeout expiry. The corrected callback accepts both coordinator-owned expiry paths. It covers bounded retries, permanent failures, startup cancellation, cleanup retry, concurrent shutdown, early retirement, release cleanup, and request-kind expiry handling.

The app check builds Debug and Release products and verifies their embedded signatures. It tests usage rejection and both modes' unprivileged rejection. These checks do not install or activate the authority.

[The existing live XPC probe](evidence/2026-10-11-runtime-entrypoint-xpc.json) passed all 19 synthetic cases on macOS 27.0.1. Its temporary per-user agent was removed. The committed report redacts the disposable service name. This checks the existing native protocol selectors and handshake boundaries. It does not exercise the installed authority executable or prove its signal behavior.

[The anonymous presence wire fixture](evidence/2026-10-11-runtime-presence-xpc.json) also passed. It checked native peer credentials, connection binding, conflict state, recovery after a lost reply, and observer withdrawal. It installed no service and issued no approval. Its source record marks the pending review fix as an uncommitted worktree change.

The new [installed command mode](../macos-installed-command-entrypoint.md) attaches the native command receive host after protected host checks. The presence-only mode remains unchanged. Neither mode attaches 1Password or Little Snitch adapters. Those producers must share the existing journal and clock. Protected provisioning, installed service signal behavior, hardware restoration, and physical device approval remain unproven. [Issue 286](https://github.com/rock3r/remozio/issues/286) retains those platform gates.
