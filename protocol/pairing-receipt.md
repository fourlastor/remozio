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

This payload is for the separate recovery path in #901. The version 1 enrolled lookup above does not accept it. The codecs define and verify the payload. The recovery listener, Root producer, and phone retirement are separate changes.

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

The outer map is limited to 1 KiB and contains the canonical input as bytes at key 0 and a raw 64-byte P-256 signature at key 1. Reject unknown fields and noncanonical inputs. Both reason values attest that the exact attempt can no longer commit. The retired-incarnation reason does not assert that the wall deadline passed.

Verify all claims against the retained re-pair transcript. Verify the signature with its pinned Root authority key and the dedicated signing input. An ordinary pairing transcript is ineligible. Swift and Kotlin share the signed, malformed, and signature or binding rejection cases in `vectors/pairing-expiry-receipt-v1.json`.
