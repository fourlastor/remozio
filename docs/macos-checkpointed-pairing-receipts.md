# Checkpointed pairing and commit receipts

An Android pairing stays prepared until the Mac confirms its durable commit.
The configured authority provides that confirmation through its journal owner.

```mermaid
sequenceDiagram
    participant Setup as Authorized local setup
    participant Owner as Shared authority owner
    participant Journal as Journal and continuity
    participant Enclave as Secure Enclave signer
    participant Phone as Authenticated phone
    Setup->>Owner: Retained transcript and biometric proof
    Owner->>Owner: Check Root code and administrator consent
    Owner->>Journal: Commit enrollment, audit and retained transcript
    Journal-->>Owner: Independent checkpoint completed
    Owner->>Enclave: Sign the Mac commit input
    Enclave-->>Owner: Commit receipt
    Owner->>Journal: Recheck current committed enrollment
    Owner-->>Setup: Receipt and retained gateway control
    Setup-->>Phone: Receipt for the prepared transcript
    Note over Phone,Journal: A lost reply does not mean the enrollment failed
    Phone->>Owner: Recover receipt through its current authenticated binding
    Owner->>Journal: Load that exact active committed pairing
    Owner->>Enclave: Sign its retained Mac commit input
    Owner->>Journal: Recheck binding and committed pairing
    Owner-->>Phone: Receipt; no second enrollment write
```

## Host contract

`AuthorityJournal.commitPairing` uses the existing request owner, audit writer and continuity checkpoint. It requires real and effective Root identity and an independent continuity store. Unpaired owners cannot use either public pairing method. Its public interface accepts only the restored Secure Enclave signer. Software signing remains an internal test seam.

The setup host must authenticate the complete human transcript before this call. It must retain the authorized attempt and supply a synchronous native administrator recheck. The recheck runs inside the commit transaction. No network payload can provide this authorization callback. The host must also establish the trusted transport key and protocol floor when constructing the attempt.

The owner checks the Mac/account scope and authority key. It verifies current authority code, then rechecks administrator consent. The existing attempt validates the biometric proof, trust revision, replacement target and elapsed deadline. Enrollment, revocation, audit events and the retained transcript share one write and one independent checkpoint.

The signer receives the existing version 1 Mac commit input only after durable success. The owner verifies its returned signature and rechecks current code and active enrollment before returning it. Receipt generation does not create another journal owner, service, key or authorization policy.

## Ambiguous completion

| Result | Required handling |
| --- | --- |
| Authorization, proof or expiry fails before commit | Do not activate the phone |
| Commit succeeds, but signing or delivery fails | Keep the Android record prepared; recover the receipt |
| Receipt verifies against the retained transcript | Activate that exact prepared Android record |
| Enrollment is revoked or its binding changes | Do not return a receipt through the old binding |
| Mac restarts after commit | Recover from the committed transcript and proof |

`AuthorityJournal.pairingReceipt` requires the current authenticated phone binding. It signs only the retained active pairing for that setup ID, phone and epoch. A late receipt can reconcile durable enrollment after the original attempt expires. It cannot revive revoked trust or authorize another enrollment.

The initial commit returns its revision, receipt and any signed gateway removal control. If receipt generation fails after commit, the host must reconcile durable state. It must not interpret the exception as proof of rollback or silently retry enrollment.

## Evidence and remaining integration

Eight component tests cover checkpoint completion before signing, replay, rejected consent, invalid proof, expiry, clock failure, replacement, restart recovery, invalid receipts, stale bindings and revocation during signing. The existing enrollment regression suite still passes.

These tests use disposable same-user stores and software fixture signatures. They do not prove Root hardware custody, administrator dialogs or installed IPC.

The usable setup host, invitation transport, QR/text presentation and Android activation UI remain to be connected. The native installation and target credential gates remain open. No protected service installation or physical Mac–Pixel approval ran for this change.
