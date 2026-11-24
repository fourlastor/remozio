# Pairing receipt recovery, version 1

A prepared phone can retrieve a receipt after the Mac commits pairing but the original reply is lost.
This exchange can recover an existing enrollment. It cannot create, replace or restore a revoked enrollment.

```mermaid
sequenceDiagram
    participant Phone as Android incomplete setup
    participant Transport as Mac transport
    participant Root as Mac authority
    Phone->>Transport: Enrolled TLS 1.3; remozio-receipt/1
    Note over Phone,Transport: Retained transport pins; envelope negotiation v1
    Phone->>Transport: Query retained setup ID
    Transport->>Root: Current phone binding and setup ID
    Root->>Root: Validate host, transport policy and committed transcript
    Root-->>Transport: MAC_COMMIT proof or unavailable
    Transport-->>Phone: One matching response; close
    Phone->>Phone: Verify against retained transcript before activation
```

## Admission and compatibility

Use the enrolled listener and its existing discovery records. Select ALPN `remozio-receipt/1` through the TLS handshake.
Never select this mode from an application frame. Do not fall back to the approval ALPN on failure.
TLS 1.3, mutual pinned identities, disabled resumption, disabled tickets and rejected early data remain required.
The setup listener's unpaired admission is never used here.

The existing channel negotiation and session envelope remain version 1. The phone offers no command or audit capabilities. Denied LAN permission does not block an existing relay route.
The Mac dispatches the immutable TLS purpose before command discovery. A receipt connection accepts exactly one query and then closes.
The network exchange has a 30-second deadline. Closing or stopping the phone UI cancels and joins its owned I/O.
Check cancellation before local activation. After that boundary, finish the verified receipt commit without network timeout or caller cancellation.
The caller always refreshes saved inventory after cleanup, even if cancellation prevents delivery of the activation result.

The transport-to-authority XPC extension negotiates `pairingReceiptVersion` after the harmless base hello and credential verification.
Version 1 supports `pairingReceipt`; zero means unavailable. Other extension versions cannot receive a binding or setup ID.
An old service that lacks these selectors can retire the connection. Recovery remains unavailable until compatible components run together.
A missing receipt does not change ordinary frame, discovery or decision extension versions.

## Canonical payload

Carry each frame inside the existing session envelope and four-byte length framing.
The payload limit is 160 bytes, depth 1 and 11 CBOR items. Reject unknown fields, kinds, versions, types and noncanonical encodings.

| Map key | Value |
| --- | --- |
| 0 | Text `dev.remozio.pairing.receipt` |
| 1 | Unsigned version 1 |
| 2 | Unsigned kind: query 0 or response 1 |
| 3 | Setup ID, exactly 16 bytes |
| 4 | Query: null. Response: null or a 64-byte P-256 signature |

The response setup ID must equal the retained query ID.
The proof signs the original complete transcript with the existing `MAC_COMMIT` purpose and retained authority key.
The response envelope does not replace transcript signature verification.
Root checks its own code, the current transport policy and phone binding before and after signing.
Expired setup time does not undo an enrollment that already committed.

## Uncertain outcomes

A null response means the receipt is unavailable. A TLS, network, policy, signature or storage failure has the same uncertainty boundary.
None proves that the Mac never committed. Keep the retained record and keys after every failure or cancellation. A cancellation after the activation boundary can leave a committed ACTIVE record.
Never resubmit a biometric enrollment proof, recreate keys, reset pairing or infer an absent enrollment from a timeout.
If the Mac never committed, enrolled TLS admission can reject the phone. Explicit re-enrollment remains a separate facility.

On Android, activation verifies the receipt again under the enrollment lock and checks the retained record and lease.
Transfer the prepared-record lease into its cleanup owner without a cancellable handoff. Check cancellation before opening network I/O.
Join native I/O before releasing the lease. A storage failure keeps the preparation so an explicit later check can retry.
The UI refreshes the Mac list after activation. An active saved record still makes no claim about current Mac connectivity or presence.

## Evidence

Swift and Kotlin share three valid and fourteen invalid vectors in `vectors/pairing-receipt-v1.json`.
Component tests cover real software signatures, encrypted prepared-record activation, policy changes, cancellation and malformed responses.
A native/JVM loopback fixture checks the TLS purpose through direct and opaque relay routes. Its receipt bytes are synthetic.
The native XPC experiment checks production selectors across processes. Its service is an ordinary-user fixture.
These checks do not establish Root installation, hardware custody, Pixel UI behavior or complete Mac–Pixel approval.

## Signed expiry payload for re-pair

This payload is for the separate recovery path in #901. The version 1 enrolled lookup above does not accept it. The codecs define and verify the payload. The recovery listener and Root producer use the lookup below. Android routes saved incomplete re-pair attempts through that lookup after the original setup closes.

The signed input is a canonical CBOR map with these fields.

| Key | Value |
| --- | --- |
| 0 | Text `dev.remozio.pairing.expired-without-commit` |
| 1 | Unsigned version 1 |
| 2 | 16-byte setup ID |
| 3 | 32-byte digest of the retained pairing transcript |
| 4 | Array of Mac ID, account ID, phone ID, and candidate epoch. Each is 16 bytes. |
| 5 | 16-byte predecessor epoch for the same phone ID |
| 6 | 16-byte trust revision from the retained transcript |
| 7 | Unsigned transcript expiry in Unix milliseconds |
| 8 | Unsigned reason. Zero is deadline elapsed. One is retired authority incarnation. |

The outer map is limited to 1 KiB and contains the canonical input as bytes at key 0 and a raw 64-byte P-256 signature at key 1. Reject unknown fields and noncanonical inputs. Like other Root signatures, this format accepts both high-S and low-S signatures. A claim can have multiple valid receipt byte sequences. Use the setup ID and transcript digest to identify the attempt. Both reason values attest that the exact attempt can no longer commit. The retired-incarnation reason does not assert that the wall deadline passed.

Verify all claims against the retained re-pair transcript. Verify the signature with its pinned Root authority key and the dedicated signing input. An ordinary pairing transcript is ineligible. Swift and Kotlin share the signed, malformed, and signature or binding rejection cases in `vectors/pairing-expiry-receipt-v1.json`.

## Recovery lookup for a phone without an active enrollment

The Mac offers the separate ALPN `remozio-pairing-recovery/1` on the existing Transport listener.
Both direct and relay connections use TLS 1.3 with resumption, tickets, and early data disabled.
The phone pins the Mac transport key from its retained transcript. Transport checks the candidate certificate format and confines the connection to recovery. Root authenticates the retained candidate key through the exporter-bound proof.
Root reserves capacity for six persistent Transport links and one overlapping replacement. If its connection limit leaves no capacity for recovery, Root still starts and advertises no recovery support. Transport admits at most two recovery connections and keeps an enrolled connection slot available.
An older Transport or Root can leave the route unavailable. Enrolled receipt lookup keeps its version 1 binding and selectors.

Each message has a four-byte unsigned big-endian length followed by a tag byte and the fields below.
The total message length after the prefix is at most 1,025 bytes.

| Tag | Direction | Body |
| --- | --- | --- |
| 0 | Phone to Mac | 16-byte setup ID, 32-byte transcript digest, and four 16-byte IDs in scope order |
| 1 | Mac to phone | 32-byte random challenge |
| 2 | Phone to Mac | 64-byte raw P-256 proof |
| 3 | Mac to phone | Empty refusal |
| 4 | Mac to phone | 64-byte raw `MAC_COMMIT` signature |
| 5 | Mac to phone | Signed expiry receipt encoded as above |

The scope order is Mac ID, account ID, phone ID, and candidate epoch.
The proof signs the UTF-8 string `dev.remozio.pairing.recovery-lookup/1`, one zero byte, a 32-byte TLS exporter, the challenge, and the lookup body.
Use the exporter label `EXPORTER-dev.remozio.pairing.recovery-lookup/1` with empty context.
Transport opens a Root connection only after it reads a well-formed lookup. The connection counts toward Root's existing connection limit. Root issues one challenge for each well-formed lookup. It consumes that challenge once and binds it to the handshake deadline.
Root verifies the Transport caller and its current code policy before reading the verified journal.
It matches the exact transcript and verifies the proof under its retained candidate transport key.
Root rechecks the record, the caller policy, and the active lease before returning a signed result.

Root returns `MAC_COMMIT` only for the exact eligible committed enrollment.
It returns expiry proof only after maintenance or startup publishes a durable terminal state.
A pending stage stays inconclusive after its deadline. Absence and failed proof use the same refusal.
The listener closes after one response. The lookup changes neither journal records nor the enrollment.
The phone keeps its preparation and keys on refusal and verifies any proof against the retained transcript.

If a global failure or a failure after valid proof prevents a signed result, the connection can close without a frame. Treat that closure as inconclusive.

On Android, the saved attempt keeps its existing prepared-record lease for the whole explicit check.
A check can make up to three lookups in one 30-second network budget, with one- and two-second delays between attempts.
If the route or exporter is unavailable, or every reply is inconclusive, Android keeps the exact preparation and keys.
A signed commit uses the existing verified activation path.

Before retiring an attempt, Android closes and joins its recovery I/O and then verifies the signed expiry again against the exact prepared row under the enrollment lock.
The encrypted archive commits that candidate as removed before Android deletes its unused keys.
After interruption, an unreadable archive leaves all keys and archive bytes intact. A committed removed row lets Android finish its own cleanup from a readable snapshot.
