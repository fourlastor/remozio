# Authenticated gateway control history

The gateway returns pages of retained root-signed controls for an explicit revision range, within configured limits.
The latest receipt alone cannot explain every missing local revision.
The root's existing query owner authenticates each page with a fresh nonce and the pinned gateway key.
It also verifies every retained root signature independently.

This is evidence retrieval. It does not import controls, repair counters, apply revocations, restore enrollment, or prune history.

```mermaid
sequenceDiagram
    participant R as Root query owner
    participant G as Gateway service
    participant D as Gateway database
    R->>G: Fresh query: after revision A, through revision B, maximum N
    G->>D: Read ordered controls in (A, B], plus one lookahead row
    D-->>G: At most N controls and hasMore
    G-->>R: Gateway-signed page bound to nonce, registration, A and B
    R->>R: Verify gateway signature and each root receipt
    R->>R: Check order, bounds, count, query lifetime and single use
    Note over R: Missing revisions stay missing; they are never inferred away
```

## Bounds and wire format

The dedicated query uses deterministic CBOR, schema version `1`, and message kind `2`.
Its fields are:

| Key | Value |
| --- | --- |
| 0 | Schema `1` |
| 1 | Kind `2` |
| 2 | Encoded pinned registration |
| 3 | Fresh 32-byte nonce |
| 4 | Exclusive lower revision |
| 5 | Inclusive upper revision |
| 6 | Maximum records, from 1 through 16 |

The reply uses kind `3`. Fields 0 through 5 retain the same meaning and binding, apart from the reply kind.
Field 6 is an array of receipt maps. Field 7 is the Boolean `hasMore`.
Each receipt map contains kind at key 0, canonical root payload at key 1, root signature at key 2, and revision at key 3.
The supported receipt kinds remain candidate `1`, activation `2`, and phone revocation `3`.
Unknown schemas, fields, kinds, and inconsistent receipt metadata are rejected.

The signed input is the UTF-8 bytes `Remozio/GatewayControlHistory/v1`, one zero byte, then the canonical reply.
The gateway signature uses raw P-256 ECDSA. Head replies retain their original signing purpose and wire format.
A head query cannot accept a history response, even if the gateway signs a response containing the head query's nonce.

Queries are limited to 1,024 bytes. Replies are limited to 1,100,000 bytes and 16 controls.
A receipt is still limited to 65,536 payload bytes plus its 64-byte signature.
Head and history queries share the existing owner capacity, monotonic deadlines, clock checks, and invalidation lifecycle.
The database reads at most one additional row to determine `hasMore` and detect a duplicate revision at the page boundary.
No database schema migration is needed.

## Missing history and pagination

The gateway may legitimately lack intermediate controls. Its accepted revisions need not be consecutive.
A signed page does not turn an omitted control into proof that no revocation occurred.
`coversRequestedRange` is true only when this page covers every revision in its requested range and has no continuation.
It describes receipt coverage, not permission to restore trust.

For a multi-page recovery read, the host must retain the original upper bound and validate consecutive revisions across every page.
Continue after the last returned revision only when `hasMore` is true. An empty final page is an incomplete range, not a reason to repeat the same query.
The requested upper bound stays fixed when the gateway receives newer controls.
When the range comes from an authenticated head, compare its terminal receipt with that head's retained receipt before using the collected history.
Do not combine pages from different registrations, lifecycle epochs, gateway pins, or recovery attempts.

A complete set of signed receipts still needs comparison with protected local trust history.
Unknown revocations and unknown trust-changing controls follow the plan's restricted recovery path.
Automatic reconciliation may only use evidence that proves the missing changes are eligible for that path.
This API provides no counter-repair or enrollment mutation method.

## Host gates and evidence

Authenticate the registered caller and use a protected channel before invoking `controlHistoryReply`.
Retained receipts contain operational metadata, although they contain no registration token or provider credential.
Keep the gateway signer local, serialize its service calls, and invalidate the root query owner when trust changes.
Gateway key provisioning, HTTP or XPC wiring, history collection, and recovery policy remain service integration work.

Eight new tests use the real protected gateway database and disposable signing keys.
They cover all control kinds, pagination, missing revisions, new controls arriving during a query, both signatures, replay, invalid ranges, duplicate records, protocol versions, query limits, expiry, unsigned revisions, and restart.
The tests run without a network endpoint, provider credentials, a phone, or a privileged service.

The [bounded history collector](gateway-history-collection.md) now checks continuity across pages and anchors completion to the authenticated head.
Root storage reconciliation remains separate.
