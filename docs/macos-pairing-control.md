# Local app control for phone pairing

The signed Mac app can open a temporary pairing listener through the dedicated transport service.
This connection carries public phone claims, the actual Root transcript, a checked phone proof, and the Root receipt.
It carries no administrator form, command decision, credential release, private key, or enrollment authority.

```mermaid
sequenceDiagram
    participant App as Signed Mac app
    participant Root as Root pairing channel
    participant Control as Transport control channel
    participant Phone as Phone setup exchange
    App->>Root: Authenticate; obtain public context
    App->>Control: Authenticate; begin with context invitation
    Control-->>App: Actual listener port
    Phone->>Control: TLS-bound public phone proposal
    App->>Control: Read candidate snapshot
    App->>Root: Stage selected proposal with admin authorization
    Root-->>App: Fresh complete transcript
    App->>Control: Transfer actual transcript for the selected candidate
    Control->>Phone: Transcript
    Note over App,Phone: Independently verify and confirm the complete transcript
    Phone->>Control: Fresh biometric proof
    Control-->>App: Proof bound to the selected transcript
    App->>Root: Commit with confirmed digest and admin authorization
    Root-->>App: Receipt after durable commit
    App->>Control: Deliver the receipt once
    Control->>Phone: Receipt
    Note over Phone: Verify receipt before activating PREPARED
```

The app must use its independent authenticated Root channel. The transport owner never stages or commits Root enrollment.
The control client checks the proposal scope, stable candidate claims, monotonic progress, and the mathematical proof before exposing it.
The network session independently checks the TLS key, complete transcript, phone signature, and receipt purpose.

## Local identity and lifetime

Protected metadata declares distinct interactive and transport UIDs, exact app and transport code hashes, and the control Mach service.
Both sides apply the existing code-signing requirement. The client performs a harmless version handshake before sending setup data.
The exported object checks the original NSXPC invocation stack before moving work to an asynchronous task.
The transport constructor checks its dedicated account. The app constructor checks its owner UID and process incarnation.

One control connection owns one temporary listener. It can expose two candidates by default; configuration permits one through eight.
The network listener opens only after the signed app requests setup. Closing the app connection aborts its candidate I/O and cancels its tasks.
Shutdown joins the actual RPC tasks, proof readers, network byte readers, and network handlers. Concurrent owner shutdown calls join the same drain operation.
A bounded byte reader remains active while setup waits for local authorization. It detects peer EOF without another app operation.
Expired or disconnected candidates disappear from the next snapshot. Their disappearance grants no denial, activation, or commit claim.

A lost receipt reply is ambiguous. This control incarnation never repeats receipt submission or Root commit.
The Android PREPARED record must remain available for the existing explicit receipt-recovery contract.
A successful local write does not prove that the phone verified the receipt or activated its enrollment.

## Version 1 and bounds

`setupHello` selects local protocol version 1. It is separate from the Root pairing handshake and network ALPN `remozio-pairing/1`.
The bounded snapshot uses deterministic CBOR with exactly keys 0 through 2:

| Key | Value |
| --- | --- |
| 0 | Snapshot version 1 |
| 1 | Actual nonzero listener port |
| 2 | Candidate rows |

Each row contains a 16-byte local candidate ID, canonical phone proposal bytes, a closed phase enum, and an optional 64-byte proof.
The ID selects only a candidate within this control connection. It is neither a phone identity nor a Root setup token.

| Phase | Meaning |
| --- | --- |
| 0 | Public proposal available |
| 1 | Sending the returned transcript |
| 2 | Awaiting the phone proof |
| 3 | Proof available for independent app and Root checks |
| 4 | Sending the authority receipt |
| 5 | Local receipt write completed |

A proof is present only in phases 3 through 5. Snapshots allow at most 530,000 bytes, depth 3, and 96 items.
Reject duplicate IDs, changed claims, backward phases, unknown versions or fields, invalid proofs, and trailing bytes.
The metadata format has exactly 14 fields, at most 4,096 bytes, depth 2, and 96 items.
It contains public pins and configuration only. Loading still requires Root ownership and protected ancestors.

## Transport startup

The explicit `--pairing-configuration` mode combines existing transport metadata with the control configuration.
It preserves optional wake and relay companions. It checks matching Mac/account IDs, owner and service UIDs, and distinct Mach service names.
Existing configuration modes and schemas remain unchanged. Pairing remains absent from them.
The signed transport job must declare the configured control Mach service during installation.
The entry point authenticates its ordinary authority feed before exposing local setup control.

## Evidence and remaining work

Focused tests use software keys, an injected ingress, and logical local RPC dispatch. They cover a complete control exchange, malformed metadata,
unknown versions, changed claims, invalid proofs, lost replies, cancellation, expiry, invocation rejection, and concurrent actual drainage.
The Debug Xcode scheme compiles the app and embedded services. Ad-hoc build signing proves no production peer identity.

These checks prove no installed Mach service, dedicated-account separation, native signature acceptance, administrator consent, or hardware biometric.
Installed boundaries remain tracked in #286. The Mac setup UI, Android hardware setup composition, protected configuration publication,
and the first actual Mac–Pixel approval remain required integration work.
