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
