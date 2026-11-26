# Android decision identity

The decision key is separate from transport and biometric keys. It supplies signatures for choices that do not require biometrics. The first adapter supports an explicit command decline only.

```mermaid
sequenceDiagram
    actor User
    participant Host as Future request host
    participant Signer as Decision identity
    participant KS as Android Keystore
    participant Mac as Mac authority
    User->>Host: Decline the displayed command
    Host->>Signer: Original signed request
    Signer->>Signer: Verify authority, scope, contract and permitted decline
    Signer->>Signer: Bind request digest, challenge, phone and key
    Signer->>KS: Sign the cancellation input
    KS-->>Signer: DER signature
    Signer->>Signer: Convert and verify the signature
    Signer-->>Host: Signed decision carrier
    Host->>Mac: Send through authenticated channel
    Mac->>Mac: Recheck enrollment, expiry and first-winner consumption
```

## Key lifecycle

`AndroidDecisionKeyCreation.create` creates a fresh P-256 key with a random decision alias. It requires a worker thread and holds the shared file-owner lock throughout creation and validation. Only SHA-256 signing is enabled. No biometric prompt or authentication grace period is configured.

StrongBox is preferred. Only its typed unavailability permits a TEE attempt, and only while the alias remains absent. Existing aliases, unexpected provider errors and uncertain partial creation never trigger replacement or deletion. A failed creation can leave an unused alias for later explicit recovery.

Creation returns a public enrollment reference. It does not enroll the phone, activate a record, or grant any Mac authority. The setup flow must register it through the separately authorized enrollment transaction.

`AndroidDecisionIdentities.load` requires an active enrollment record. It checks the local alias, generated hardware custody, signing policy, P-256 curve and expected public point. Private-key encoding must be unavailable. These checks provide local evidence, not remote attestation. Missing or invalid keys fail without automatic recovery.

The self-signed certificate supplies public-key material only. It is not a transport certificate or a trust assertion. No certificate chain or certificate expiration grants decision authority.

## Signing boundary

`declineSession` takes the authenticated command session that the app displays. It checks the session against the enrolled Mac, account and authority key. The session checks the negotiated schema and verifies that the current status allows the captured decline action.

The method constructs the complete decision itself. Callers cannot select a signing purpose, key ID, phone identity or approval action. It signs the canonical cancellation input and verifies the resulting wire signature before returning a carrier. It exposes no raw signing operation. Command execution and other biometric choices remain unavailable through this key.

The enrollment host must call this method only for an explicit choice on the displayed request. It must close the identity when the enrollment is removed or its trust changes. Close prevents subsequent signatures from that handle; it does not delete the underlying key. Other active enrollments remain independent.

The request host binds the explicit UI choice to its retained session and closes stale sessions. The Mac independently validates current enrollment, request expiry and atomic consumption. A lost reply leaves the outcome uncertain.

## Evidence and remaining work

JVM tests use disposable software keys to verify cancellation signatures for all four command schemas. They also cover session binding, current status, permitted actions and invalid key handles. Phone Core tests cover malformed and unsupported requests during session admission. Policy tests exercise hardware classifications and creation fallback failures.

The launcher does not create or load these keys yet. Pairing, request controls, network dispatch and phone removal integration remain separate work. Real Keystore behavior, process restart, device lock, update continuity and Pixel custody checks remain for the physical-device session.

The production biometric key and its retention policy remain separate from this decision key. The [biometric experiment](../docs/experiments/android-biometric-key.md) records measured signing and lifecycle results; enrollment retention remains unproven.

Platform references: [key generation policy](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder) and [local key information](https://developer.android.com/reference/android/security/keystore/KeyInfo).
