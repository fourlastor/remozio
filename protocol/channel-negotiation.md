# Channel negotiation version 1

The Swift and Kotlin `ChannelNegotiation` owners bind capability offers to one fresh, mutually authenticated TLS connection.
Before creating an owner, the host must authenticate both enrolled transport keys.
It must retain the expected desktop host, account, phone, and enrollment epoch.
This protocol does not enroll devices or authenticate an untrusted transport.

Sender role 1 is the enrolled desktop-host side on either platform. The legacy
`macID` scope position identifies that host; `.mac`/`MAC` source names may remain.
This [approved interpretation](https://github.com/rock3r/remozio/issues/441#issuecomment-6253309933)
keeps negotiation 1, pairing transcript 1, tags, proof purposes, ordering and
canonical bytes unchanged. It creates no role 2 and provides no platform or
hardware attestation. References to Mac below retain the legacy endpoint name.

```mermaid
sequenceDiagram
    participant P as Enrolled phone
    participant M as Enrolled Mac
    Note over P,M: Fresh pinned mutual TLS 1.3 connection
    P->>M: Phone offer and fresh nonce
    M->>P: Mac offer and fresh nonce
    Note over P,M: Independently select highest safe common version
    P->>M: Phone confirmation of transcript hash
    M->>M: Verify phone confirmation
    M->>P: Mac confirmation of same transcript hash
    P->>P: Verify Mac confirmation
    Note over P,M: Session metadata available; operations need separate verification
```

Offers may cross on the same connection. Each owner emits its own offer before accepting the peer's offer. The Mac must verify the phone confirmation before producing its confirmation. The phone must produce its confirmation before accepting the Mac confirmation. Repeated or out-of-order messages close the owner. Reading an unfinished result reports an error without advancing state.

## Host obligations

Use the platform CSPRNG for a fresh 32-byte nonce on every connection. Never reuse an owner, nonce, TLS context, or transcript on reconnect. Enforce an overall handshake deadline and bounded framing before calling these parsers. Close the owner and channel when enrollment changes or any network operation fails. Keep all handshake messages on the same authenticated TLS connection; a transcript hash alone is not authentication.

`confirmation()` returns bytes for transmission. It does not prove delivery. The host must send them successfully before publishing a connected session or sending application messages. A retained `NegotiatedChannel` is immutable metadata, not a live admission token; the host must recheck the current connection and enrollment around every await.

Transport identity grants no action authority. Keep the request signature, action schema, features, expiry, current enrollment, and decision consumption checks. Do not use a biometric key for this routine handshake. Initial pairing must bind the same negotiated values to its separate verified enrollment transcript.

## Offer encoding

Use the existing deterministic CBOR subset. All fields are mandatory; additional fields fail.

| Key | Value |
| --- | --- |
| 0 | Handshake schema: unsigned 1 |
| 1 | Sender role: phone 0, desktop host 1 (legacy Mac name) |
| 2 | Array of four 16-byte values: desktop host ID (`macID`), account ID, phone ID, enrollment epoch |
| 3 | Fresh 32-byte nonce |
| 4 | Exact supported envelope versions, positive and strictly increasing; 1–16 entries |
| 5 | Request capability rows, sorted by kind, wire version, then schema version; 0–64 rows |
| 6 | Exact audit versions, positive and strictly increasing; 0–16 entries |

A request row is `[kind, wireVersion, schemaVersion, features]`. Kind uses the issued-request tags (command 0, 1Password access 1, unlock 2, Little Snitch 3). Wire and schema versions are positive. Features are unsigned IDs in strictly increasing order, with 0–64 entries. Duplicate contracts fail even when their feature sets differ. Unknown kind or feature IDs remain opaque capability data; they never enable an unknown operation or renderer. Empty request and audit sets are valid.

Each offer has a 65,536-byte limit, depth limit 5, and 5,000 CBOR items. The parser checks these limits before constructing typed capabilities. These are handshake bounds, not command-capture or ADB transfer limits. A changed structural limit or field meaning needs an understood handshake schema.

## Transcript and confirmation

Select the highest exact common envelope version at or above the trusted local security floor. The floor comes from local software or authenticated policy. No common version fails this channel; it does not remove pairing or affect another Mac. The peer cannot supply an update requirement or lower local policy through this format.

Hash the canonical CBOR map below with SHA-256:

| Key | Value |
| --- | --- |
| 0 | Text `dev.remozio.approval.channel` |
| 1 | Unsigned handshake schema 1 |
| 2 | Canonical phone offer bytes |
| 3 | Canonical Mac offer bytes |
| 4 | Selected envelope version |

Both endpoint scopes must match retained enrollment state. Roles must differ, and nonces must differ. The hash becomes the 32-byte session ID. Altering an offer, scope, nonce, capability, or selected version changes it.

Each confirmation is `{0: 1, 1: senderRole, 2: sessionID}`. Its limit is 128 bytes. The owner requires an exact canonical match for the expected peer role and transcript. TLS authenticates these confirmations. A copied hash or confirmation received outside that connection is not evidence of peer identity.

## Evidence and remaining integration

Shared vectors cover identical Swift/Kotlin offers, session hashes, confirmations, malformed fields, ordering, and bounds. Owner tests cover reflection, replay across changed nonces, scope substitution, local floors, tampered capabilities, premature access, and permanent closure after a protocol failure. Unknown future request kinds round-trip without granting support.

The [negotiated TLS message hosts](session-envelope.md) now supply framing, deadlines, and session-bound application sequences over the native byte adapters. Production enrollment admission, reconnect policy, UI status, and persisted capability admission remain separate work. Physical Pixel tests remain required. No production action is enabled by these tests.
