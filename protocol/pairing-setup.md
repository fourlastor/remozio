# Restricted pairing exchange, version 1

An unpaired phone can submit public claims through a separate TLS profile. This exchange grants no approval or enrollment authority.
The invitation supplies the expected Mac pins. The phone must authenticate those pins through an independent setup surface.

```mermaid
sequenceDiagram
    participant Phone as Android setup owner
    participant Transport as Mac transport role
    participant App as Signed Mac app
    participant Root as Mac authority
    Phone->>Transport: Fresh TLS 1.3; pairing ALPN
    Transport->>Phone: Hello
    Phone->>Transport: Public phone proposal
    Transport->>App: Claims bound to the TLS candidate key
    App->>Root: Stage through authenticated local channel; admin authorization
    Root->>App: Fresh complete transcript
    App->>Transport: Returned transcript
    Transport->>Phone: Complete transcript
    Note over App,Phone: Independently verify and confirm the complete transcript
    Note over Phone: Retain PREPARED; request fresh hardware biometric proof
    Phone->>Transport: Setup ID, digest, biometric signature
    Transport->>App: Checked proof
    App->>Root: Commit with confirmation and admin authorization
    Root->>App: Receipt after durable commit
    App->>Transport: Authority receipt
    Transport->>Phone: Checked receipt
    Note over Phone: Verify receipt before activation
```

The diagram includes required integration. The current components implement the network exchange and the existing local staging adapter.
The signed app control bridge, production startup, setup screens, and hardware enrollment integration remain separate work.

## TLS and discovery

Use fresh TLS 1.3 with ALPN `remozio-pairing/1`. Disable resumption, tickets, and early data.
The phone pins the invitation transport key. The Mac requires a valid P-256 client certificate and binds its key to the proposal.
A client certificate proves key possession. It does not prove enrollment, hardware custody, or administrator consent.

This listener is separate from `remozio/1`, which accepts enrolled approval peers. Never insert a setup candidate into that peer set.
Local discovery uses `_remozio-pairing._tcp.` and the full Mac/account IDs in its service name.
Discovery supplies address hints only. TLS and invitation checks supply the expected identity.
Loopback fixtures do not advertise a service.

The default listener permits two concurrent candidates. Configuration permits 1 through 64.
The handshake limit defaults to 15 seconds and cannot exceed 60 seconds. The setup limit defaults to five minutes and cannot exceed it.
These elapsed limits do not replace the independent Root deadline or current-policy checks.

## Canonical frames

Prefix each deterministic CBOR frame with a four-byte unsigned big-endian length.
Reject zero lengths and lengths above 132,256 bytes before reading the body. Frame limits are depth 2 and 20 items.
Use exactly these map fields:

| Key | Value |
| --- | --- |
| 0 | `dev.remozio.pairing.exchange` |
| 1 | Version 1 |
| 2 | Message kind below |
| 3 | Kind-specific body |

| Kind | Direction | Body |
| --- | --- | --- |
| 0: hello | Mac to phone | null |
| 1: proposal | Phone to Mac | Canonical phone proposal bytes |
| 2: transcript | Mac to phone | Canonical complete pairing transcript bytes |
| 3: proof | Phone to Mac | Setup ID (16 bytes), digest (32 bytes), signature (64 bytes) |
| 4: receipt | Mac to phone | Setup ID (16 bytes), digest (32 bytes), signature (64 bytes) |

Reject unknown versions, kinds, fields, malformed types, noncanonical encodings, and trailing bytes.
A proof-shaped frame is not an authenticated proof. Verify the complete transcript signing input and its required purpose.
No frame can carry administrator authorization, commands, credentials, or an approval response.

The phone proposal uses exactly four fields: domain `dev.remozio.pairing.proposal`, version 1, canonical phone offer bytes, and three key rows.
Each row contains a 16-byte key ID and a valid 65-byte P-256 point, in transport, decision, biometric order.
All three IDs and points must differ. Proposal limits are 66,000 bytes, depth 3, and 24 items.
The proposal must use the phone role. The setup channel checks the invitation scope and exact returned phone claims.
Version 1 supports adding an enrollment. Replacement has no representation in this proposal.

## Authorization and recovery

The local adapter constructs a temporary legacy transcript from authenticated Root context and the phone claims.
It uses the existing local version 1 staging call. Root replaces the temporary Mac fields with fresh setup values.
Temporary IDs, challenges, revisions, and times never travel over the setup network. Confirm and sign only the actual returned transcript.
This adapter does not change the existing local handshake or administrator authorization contract.

Accept one proposal, one returned transcript, one proof, and one receipt, in order.
Bind both signatures to the same setup ID and digest. Use PHONE_BIOMETRIC for the phone proof and MAC_COMMIT for the receipt.
The network owner verifies signatures mathematically. Root still checks consent, current policy, freshness, and durable commit.
The Android owner must persist PREPARED before submitting its hardware proof. It activates only after the authority receipt passes verification.

A failed receipt delivery leaves the result ambiguous. Preserve PREPARED and use the existing recovery contract.
Never resubmit the commit automatically. Closing the listener stops admission, aborts I/O, cancels handlers, and awaits their actual completion.

## Evidence boundaries

Shared Swift and Kotlin vectors cover all five frame kinds, phone claims, malformed fields, limits, and type confusion.
Injected streams test fragmentation, state transitions, deadlines, cancellation, and receipt rejection. They prove no TLS identity or hardware custody.
The native/JVM loopback experiment uses real TLS and disposable software keys. It tests the complete restricted exchange and negative identity controls.
Its authority receipt is a software fixture. It does not prove Root durability, administrator consent, Pixel biometrics, or installed account separation.

The [measured TLS record](../docs/experiments/evidence/2026-10-14-pairing-setup-tls.json) retains the four native/JVM results and source hashes.
