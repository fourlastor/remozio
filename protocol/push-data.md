# Opaque push data

`PushData` defines the provider's string-to-string data map in Swift and Kotlin.
The phone treats a parsed message as an untrusted hint.
It grants no approval authority.

| Message | Exact keys | Decoded byte lengths |
| --- | --- | --- |
| Approval wake | `wake_v1`, `enrollment_v1` | 32, 32 |
| Token challenge | `candidate_v1`, `token_challenge_v1`, `enrollment_v1` | 16, 32, 32 |

Values use standard, padded, canonical Base64. Unknown, missing, mixed and version-mismatched fields fail.
The parser checks field count and encoded length before Base64 allocation. It rejects alternate alphabets, whitespace, nonzero padding bits and incorrect decoded lengths.
Constructors enforce lengths. Kotlin constructors and getters copy byte arrays. Descriptions and parse errors omit payload values.
The wake format preserves the existing FCM request shape.

```mermaid
sequenceDiagram
    participant G as Mac gateway
    participant F as FCM
    participant P as Phone
    participant R as Mac authority
    G->>F: Candidate ID, provider challenge, enrollment tag
    F->>P: Token challenge data
    P->>P: Parse closed shape; resolve retained enrollment
    P->>R: Return matched proof over authenticated channel
    R->>R: Check pending candidate, current trust and expiry
    Note over R: Consume proof before issuing activation
```

The diagram describes required integration. This change supplies the provider request and shared parser, not a Firebase service or authenticated phone channel.

The phone must resolve the enrollment tag against retained enrollment state. The tag and candidate ID cannot enroll a Mac or select an untrusted endpoint.
The challenge must arrive through the provider. Fetchable registration metadata must omit it; otherwise a phone could claim receipt without a provider delivery.
The authority must compare every field of the full retained candidate and bind the actual channel peer to the phone enrollment.
Duplicated, late or reordered pushes cannot extend candidate lifetime or replace current registration state.
Routine registration recovery remains automatic and requires no biometric prompt.

## Provider request

`FCMTokenProbe` takes verified candidate evidence and caps its TTL by both remaining deadlines and an explicit maximum.
It checks the clock epoch, clock regression, wall expiry and monotonic expiry. Milliseconds round down to seconds.
A zero TTL asks FCM to deliver immediately or discard the message. It does not disable expiry.
Firebase documents the [TTL range and zero-TTL behavior](https://firebase.google.com/docs/cloud-messaging/customize-messages/setting-message-lifespan).

Token probes always use normal priority and contain no notification payload or approval details.
Firebase reserves high priority for time-sensitive, user-visible content; silent registration uses [normal priority](https://firebase.google.com/docs/cloud-messaging/customize-messages/setting-message-priority).
Normal-priority delivery can be delayed. The controller must recover registration automatically when an unexpired proof cannot arrive.
The request retains the package restriction, fixed provider endpoint, response bounds and redacted error handling from the wake sender.
Provider acceptance does not prove phone delivery.

Build a fresh probe immediately before each attempt. The transport does not own the clock, durable attempt state or current enrollment.
The coordinator must commit attempt state, recheck trust and revocation, enforce rate limits, and apply expiry-aware retry policy before sending.
Verified candidate evidence and a constructed probe are not dispatch permits. This layer does not call the provider automatically.

## Evidence

Shared fixtures contain two valid maps and 76 malformed maps. Both language suites verify exact bytes, shape separation, canonical encoding and redaction.
Native tests also cover normal priority, both deadlines, TTL rounding, invalid clocks and intercepted send results.
No provider credentials, real provider requests or device installs are needed for these tests.
