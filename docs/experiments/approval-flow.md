# Synthetic approval flow

This harness connects the native Swift request coordinator to Android's Kotlin request owner.
The peers exchange canonical request, decision, and status bodies with P-256 signatures over child-process pipes.
They use synthetic identities and a synthetic command capture.
The harness never executes the captured command.

```mermaid
sequenceDiagram
    participant C as Kotlin test controller
    participant M as Swift request owner
    participant A as Phone session A
    participant B as Phone session B
    C->>M: Provision disposable test keys and capture
    M->>A: Signed issued request and pending status
    M->>B: Same signed request and status
    A->>M: Signed decision arrives first
    B->>M: Competing signed decision
    M->>M: Check stored enrollment; commit A and its audit event
    M-->>B: Reject unavailable request
    M->>A: Signed status names accepted phone
    M->>B: Same signed status
    C->>M: Simulate lost outcome
    M->>M: Commit Unknown and its audit event
    M->>A: Signed Unknown outcome
    M->>B: Same Unknown outcome
    A->>A: Remove owned command capture
    B->>B: Remove owned command capture
```

## Run

Use an Apple Silicon Mac, Xcode with a macOS 26 or later SDK, and JDK 21:

```sh
python3 scripts/build-approval-flow.py
./gradlew :phone-core:test :phone-core:approvalFlowTest
```

The native build is also part of `scripts/check.sh`. The Mac CI job runs the integration task after building it. The Kotlin CI job runs the portable phone tests on Linux. Android consumes the same `phone-core` module.

The build script normalizes the executable path to `.build/approval-flow/ApprovalFlowPeer`, independent of SwiftPM's build-directory layout. Its build log is `.build/approval-flow/swift-build.log`. The peer refuses root execution. Both pipe readers bound frames before allocating an unbounded line. The controller bounds response waits and terminates its child after each case.

The controller creates a private temporary parent directory and passes it as the peer’s second argument, after the capture path. The peer creates a 0700 journal directory with 0600 files. The controller removes the fixture only after confirming the child has stopped. A Debug-only `@testable` import permits normal-user fixtures through the internal storage initializer. The public production initializer remains root-only. A compile-time guard rejects Release builds of this peer; that negative build check passed locally. No app, device, or network endpoint is contacted.

## Trust and simulation boundary

The test controller generates disposable Mac and phone keys in memory. It supplies the Mac private scalar through the private test-control pipe, and pins the corresponding public key independently of the peer's response. The Swift peer signs through CryptoKit; Kotlin signs through the host JDK. No key is written to a fixture or included in a release app.

This bootstrap is test provisioning, not a pairing protocol or a production trust channel. Control messages for revocation, clock changes, target disappearance, and outcome loss exist only in the harness. The fixture provisions two durable enrollments with distinct decision and biometric keys. Each decision also carries private test-channel identity and epoch fields; the owner checks these separately from the signed decision. These fields are controller assertions, not authenticated transport evidence. A key labelled Biometric in this fixture is an ordinary disposable test key. These checks do not prove Android Keystore protection, biometric consent, Secure Enclave custody, or application signatures.

The peer serializes input from its pipe. `ApprovalRequestCoordinator` admits the validated capture, generates request bindings, retains the capture, consumes decisions, and records outcomes. Admission follows two enrollment audit events and creates its own event. Accepted is published only after the write returns successfully. The harness queues both phone decisions before reading either response and repeats with each arrival order.

The same owner reconciles `PendingRequestDelivery` after revocation, consumption, expiry, and disappearance. Its synchronous callback simulates local queue acceptance for both phones. Tests inspect active and withdrawn queue identities through counts; no notification or transport task starts. Terminal closure discards the delivery owner so it also releases its capture reference.

Live statuses come from `ApprovalRequestState.statusPayload` with a separate observation revision. Disappearance remains Unknown internally and uses the compatible v1 Cancelled/target-disappeared form on the wire. Refreshes advance observed age while retaining the age at the terminal transition. A fresh phone session can reconcile the signed terminal snapshot and clear its capture.

Fault controls install a temporary SQLite trigger that rejects the audit insert inside the real transaction. The fixture removes the trigger after the operation and identifies the expected constraint error. These prove rollback and publication ordering for an audit-write failure. They do not simulate physical disk failure or an ambiguous commit. Unsigned snapshots expose journal metadata only to the private test controller; they are not the audit transport protocol.

The reopen control closes and reopens the database in the same process, then creates a fresh audit epoch linked to the previous head. It discards the retained capture. Consumed requests without a terminal outcome receive an explicit authority-restart observation and become Unknown. Existing terminal outcomes remain unchanged. An unconsumed pending request is cancelled and audited before closing the old journal. A new, empty coordinator never reconstructs its capture. The private controller retains only status metadata for the ongoing test session; post-reopen status simulation remains separate from the live owner.

This is a journal lifecycle simulation, not process-crash recovery. Disposable keys, the synthetic clock, status revision, and cached request identity remain in memory. It does not implement production startup continuity, admission storage reservations, rollback protection, checkpoint verification, or a dispatch permit.

Unknown comes from an explicit outcome-loss or authority-restart observation. It is not inferred from a timeout. The success control is also a synthetic observation: no command or UI action occurs.

## Cases

Seventeen integration tests cover:

- Each admission generates fresh request IDs and challenges and commits its creation event.
- A wrong channel identity or enrollment epoch cannot consume an otherwise valid decision.
- Disappearance closes both delivery queues and clears both phone captures. Reconnect preserves terminal timing and cannot restore controls.
- A decision-key decline closes delivery and cannot be overridden by a later command approval.
- Either phone wins when its valid decision arrives first; a competing decision and a replay cannot win again.
- Both phone sessions accept the same signed status, retain the winning phone, and clear captures on Unknown. Replayed pending status cannot restore details.
- Revoking one phone rejects its decision while leaving the other able to decide.
- The retained Mac deadline rejects an otherwise valid phone signature.
- Altered request bindings and a wrong signing purpose leave the request available for a later valid decision.
- A narrow decision key cannot authorize a command, and tampered Mac status cannot replace verified phone state.

- A rolled-back consumption publishes no Accepted status, leaves no consumption or audit event, and lets the other phone win.
- A rolled-back outcome publishes no Unknown status and retains the capture until a later committed transition.
- Reopening after consumption or simulated dispatch preserves the winner, starts a fresh epoch, and records Unknown. Further reopening preserves that terminal outcome.
- Reopening a pending request clears its capture and publishes Cancelled without consuming it.
- A verified synthetic success survives reopening without becoming Unknown or creating another outcome event.

- Signed journal replies carry the committed winner and outcomes through phone sync into encrypted cache. Offline reload retains evidence without fresh-sync claims.
- Rolled-back events remain absent from phone history. Reopening adds a linked Unknown outcome, retains the winner, and does not duplicate records on repeated sync.

## Committed audit history

The same peer also serves `auditHistory` and `auditPage` controls through the journal-backed `AuditReplyBuilder`. These controls use the disposable authority key already pinned by the test controller. They read actual committed events, with two records per page. They do not add a production endpoint or authorize a phone to read history.

```mermaid
flowchart LR
    J[Committed consumption and outcome events] --> R[Coherent journal read]
    R --> S[Signed audit reply]
    S --> P[Phone verifies key, nonce and scope]
    P --> C[Encrypt cache before publication]
    C --> H[Phone history]
    C --> O[Offline reload: retained evidence, no fresh observation]
```

The phone fixture uses the real `AuditSyncSession` and `EncryptedAuditCache`, a disposable AES key, and an in-memory ciphertext store. It pauses and resumes a bounded sync with a one-response budget. This proves codec and cache integration on the JVM. It does not prove Android Keystore custody, Android file durability, or background delivery.

The separate [audit peer](audit-flow.md) retains synthetic restoration and unavailable-history cases. Those cases still use invented history and are not production recovery evidence.

Transport authentication, encrypted channels, production enrollment, admission storage reserves, protected checkpoint recovery, real device keys, and target execution remain outside this experiment. Enrollment records persist in this disposable store; their provisioning is controlled test setup. Signed reconnect snapshots prove phone reconciliation, not network freshness or session authentication. The harness establishes interoperability of the current production codecs and verifiers, not completion of the full approval product.

The Kotlin peer signs with standard `SHA256withECDSA` DER output. The shared strict P-256 converter produces the 64-byte wire signature consumed by the Swift verifier. This exercises the format conversion needed by Android Keystore without claiming hardware-backed signing on the host JVM.
