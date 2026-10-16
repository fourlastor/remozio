# Phone request core

The Android app uses this Kotlin/JVM module for authenticated command sessions and signed status tracking.
The classes contain no Android platform APIs, approval controls, or embedded private keys.
The transport package owns the optional relay socket connection.
The audit core manages encrypted storage through caller-supplied adapters.

A session verifies a command against caller-supplied trusted enrollment identity. It retains the typed capture until a verified terminal status clears it. The status tracker preserves request bindings, revision ordering, outcome continuity, and elapsed-time bounds. The caller still owns enrollment invalidation and clock sampling.

Run `:phone-core:test` for the portable unit tests.
They reuse the synthetic command fixture from the Android debug source set.
Production resources and runtime code do not depend on that fixture.

## Swift/Kotlin flow checks

On a Mac, run `python3 scripts/build-approval-flow.py` and then `:phone-core:approvalFlowTest`. The latter is a separate Gradle test task. It starts the compiled synthetic Swift peer and exchanges canonical signed payloads over child-process pipes. Missing native build output fails the task; it does not silently skip integration checks.

The [approval-flow experiment](../../docs/experiments/approval-flow.md) describes its trust setup, tested cases, and limits. The [audit-flow experiment](../../docs/experiments/audit-flow.md) also exercises signed history sync and encrypted cache reload. The portable test task excludes both integration classes, so Linux can run the shared state tests without Mac peers.

## Enrollment ownership

`CommandRequestInbox` accepts trusted enrollment identities and pinned authority keys from local setup. Each enrollment incarnation owns a bounded in-memory request window. Delivery uses that existing handle; request data cannot install trust. Replacing a trusted key explicitly closes the old incarnation and its sessions. Removing one Mac/account does not affect another.

Request keys contain Mac, account, and request IDs. Every delivery authenticates before lookup. Exact duplicate bodies return the existing session, preserving timing and terminal state. Conflicting signed bodies under the same request identity fail. A refreshed authorization uses a new request ID and challenge while preserving target observation and age through the existing status contract.

Closed sessions clear their capture, expose a local closed signal, and reject later status input. This is not a fabricated signed expiry or action outcome. Android removes the inspection and dismisses it when that signal arrives. Already copied snapshots cannot be erased by closing the owner.

Callers supply request-window limits. Product defaults remain undecided.
Terminal handles remain as tombstones during the window.
When capacity is exhausted, the inbox fails explicitly without evicting a visible request or forgetting a terminal result.

Durable history, authenticated reconnect-window rotation, enrollment persistence, and product retention settings remain unfinished.
This layer does not establish freshness or durable replay protection.
It exposes no approval control.

The [wake router](PUSH.md) coalesces opaque hints per trusted enrollment and tracks bounded fetch demand.

The [TLS channel experiment](../../docs/experiments/tls-channel.md) adds a loopback Swift/JVM transport check to the same native flow task. It uses disposable software identities and no devices.

The [WebSocket carrier extension](../../docs/experiments/websocket-carrier.md) keeps outer relay authentication separate from the inner Mac pin. OkHttp dependencies remain test-only.

The [phone TLS engine](TRANSPORT.md) accepts ordered ciphertext without a local socket bridge. The host supplies an enrollment key manager and peer key pin. The relay connector supplies the outer carrier. Android hardware and enrollment integration remain separate work.

`WebSocketRecordTransport` provides [bounded runtime framing](TRANSPORT.md#bounded-websocket-records) through Ktor WebSockets 3.6.0. Its host still owns authenticated HTTPS setup and enrollment lifecycle.

The [relay connector](RELAY.md) authenticates outer HTTPS and validates the upgrade before bounded framing starts. Its host supplies trusted enrollment data and scoped Access credentials.

The [enrollment store](ENROLLMENTS.md) persists prepared, active, and removed ownership records with encrypted replacement. It keeps Mac/account scopes separate. The production setup owner must still validate authorization and freshness before using active records.

The [negotiated TLS channel](../../protocol/session-envelope.md) owns the phone handshake, bounded framing, and session-bound message delivery.

The [signed request receiver](../../protocol/approval-message.md) connects negotiated channels to the existing inbox. Enrollment ownership guards delivery and exposes the same sessions as observable app state.
