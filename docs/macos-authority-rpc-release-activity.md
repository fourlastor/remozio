# Authority RPC release activity

The installed authority retains shared machine activity for each presence and transport operation.
It keeps the reference until its reply callback returns, including a nested callback.
An idle connection retains no activity reference.

This extends the [command activity integration](macos-authority-release-activity.md) and [setup and pairing integration](macos-setup-pairing-release-activity.md).
It does not authorize installation or enable an updater.

## Operation lifetime

```mermaid
sequenceDiagram
    participant Peer as Signed app or transport
    participant Endpoint as Authority XPC endpoint
    participant Root as Retained authority journal
    participant Update as Independent update attempt
    Peer->>Endpoint: Authenticated invocation
    Endpoint->>Endpoint: Check native identity, handshake and work budget
    Endpoint->>Root: Acquire current shared activity reference
    Endpoint->>Root: Run existing policy and operation checks
    Update->>Update: Try exclusive activity
    Note over Update: Busy; keep normal admission available
    Root-->>Endpoint: Existing operation result
    Endpoint->>Endpoint: Revalidate activity file
    Endpoint-->>Peer: Existing versioned reply
    Endpoint->>Root: Close reference after callback returns
    Note over Endpoint: Idle connection keeps no reference
```

The installed transport listener passes the same journal used by its policy and operation handlers.
The presence access obtains activity from its retained journal on each invocation.
Neither endpoint caches an absent barrier during construction.
The installed command runtime attaches its barrier before it starts these listeners.
Raw component constructors can omit the journal or activity provider; they do not establish installed behavior.

All existing selectors, protocol versions and response payloads remain unchanged.
The transport scope covers hello, capability queries, discovery, request frames, decision exchanges, pairing receipts, wake hints and trust checks.
The presence scope covers hello, status, observations and manual mode changes.
A retained request and native command execution keep their independent activity references.

## Refusal and disconnect

An exclusive owner refuses new work before an operation handler or handshake policy read runs.
The endpoint uses its existing failure response and closes the connection.
A fresh connection can retry after the exclusive owner releases activity.
A failed exclusive attempt does not withdraw observers or freeze ordinary requests.

Handler failure releases its provisional reference and operation budget.
Changed activity metadata suppresses the successful reply and retires the affected barrier.
The endpoint does not roll back or retry an operation whose outcome is uncertain.

Disconnect closes the connection but does not release activity held by an executing handler.
That handler retains its local reference until it returns and completes its existing reply or suppression path.
Nested reply callbacks can start another operation at capacity one.
Each callback keeps its own reference; closing one cannot unlock the other.

## Validation and limits

Ordinary-account controls use real protected-file checks and independent flock descriptors.
They cover every transport selector, all presence replies, idle admission, attachment after construction, exclusive refusal, handler failure, metadata changes, nested replies and concurrent disconnect.
The anonymous native XPC fixture also attaches a real activity barrier.
Its forwarding object checks independent exclusive refusal immediately before and after each successful native reply callback.
It preserves the original invocation stack and pinned test binary checks.
The [retained native result](experiments/evidence/2026-10-16-authority-rpc-activity-native-xpc.json) records 19 verified invocations and 32 callback checks on macOS 27.0.1.
The same run checks idle acquisition, reconnect, an uncertain committed mode, crossed connection refusal and observer withdrawal.
Three refused operations have no successful reply; they are excluded from the callback count.
The record binds the exact fixture hash. It establishes no macOS 26 runtime result.
Existing native XPC and policy controls remain part of the full repository gate.
These results do not establish installed Root identity, administrator consent or the complete Mac–Pixel flow.

The complete updater still needs all-role quiescence, verified candidate startup, health checks, a durable manifest and floor commit, and crash recovery.
Activity in restricted transport, gateway, GUI and bridge processes needs its own trusted ownership integration.
Observer withdrawal only changes the old authority's in-memory presence state; it grants no update or command authority.
The initial package remains limited to fresh installation or same-build recovery.
Sparkle must not replace the active bundle directly.
