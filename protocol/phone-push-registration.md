# Enrolled phone push registration, draft version 1

This draft connects the existing gateway token-possession contract to an enrolled phone channel.
It does not enroll a device, approve a request, or authorize an ADB session.
The transport and authority exchange are implemented. Protected startup configuration and Android runtime wiring remain pending.
No installed service enables token registration yet.

## Channel boundary

Use a separate mutually authenticated TLS purpose: `remozio-push-registration/1`.
Authenticate the retained enrollment transport keys and pins before application exchange.
Use the existing negotiated envelope, scope, session and sequence checks.
Advertise no approval or audit capability on this channel.
Unsupported peers fail this purpose without weakening or replacing their ordinary approval connection.

Every exchange uses a fresh 16-byte correlation ID and one request/reply pair.
Offer and Proof travel phone to host. Prepared and Outcome travel host to phone.
A reply must match its request correlation and expected role.
Route fallback finishes before application transmission. Never replay an uncertain application exchange automatically.

An offer and its later proof can use different connections.
The host retains the actual candidate, expiry and replay state independently.
The phone rechecks current enrollment and provider generation/token revision after each suspension.
The Root authority derives authenticated phone/account/epoch scope from the protected transport admission.
Application fields cannot supply that authority.

## Frame

Encode exactly one deterministic CBOR map:

| Key | Value |
| --- | --- |
| 0 | Text `dev.remozio.phone.push.registration` |
| 1 | Unsigned schema `1` |
| 2 | Kind: Offer `0`, Prepared `1`, Proof `2`, Outcome `3` |
| 3 | Correlation bytes16 |
| 4 | Typed body below |

Use local limits of 8192 bytes, depth 4 and 64 items.
Reject unknown fields, versions, kinds, malformed types, noncanonical encodings and trailing bytes.
These bounds do not derive from provider input.

### Offer

The body is `[token, projectID, senderID, packageName]`, with four text values.
The token is 1–4096 printable non-space ASCII bytes.
The project ID is 1–128 ASCII bytes matching `[A-Za-z0-9][A-Za-z0-9_.:-]*`.
The sender ID is 1–32 ASCII decimal digits.
The package name is 1–255 ASCII bytes matching `[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+`.

These are private routing hints, not a request to choose a gateway or mint enrollment authority.
The host must compare them with current protected gateway policy and the enrolled Android application contract.
The phone uses its current configured provider and token candidate, never arbitrary values from a push message.
Do not include tokens in descriptions, logs, audit or exception messages.

### Prepared

The body is an ordered array with exactly fourteen values:

| Index | Value |
| --- | --- |
| 0–7 | ownerID, macID, accountID, gatewayID, lifecycleEpoch, phoneID, enrollmentEpoch, candidateID: bytes16 each |
| 8 | Token digest: bytes32 |
| 9 | Enrollment routing tag: bytes32 |
| 10 | Positive candidate revision |
| 11 | Operation ID: bytes16 |
| 12–13 | Issued and expiry Unix milliseconds; expiry is later than issue |

This is a projection of the retained candidate, with the provider challenge removed.
Do not serialize the complete GatewayTokenCandidate into a phone-fetchable response.
The challenge must reach the phone through the provider path only.

The phone checks enrollment scope and tag, and compares the token digest with its current candidate.
Match provider challenges by the exact candidate ID and enrollment tag.
Knowledge of the candidate ID alone does not prove token possession.
Recheck current enrollment, token revision and deadlines before sending the proof.
Root checks its retained candidate and current trust again before consuming anything.

### Proof

The body is a byte string containing the existing canonical GatewayTokenProof.
Its independent CBOR limits are 1024 bytes, depth 4 and 32 items.
Reconstruct its binding from the prepared metadata plus the matching provider-delivered challenge.
The caller must not supply a different owner, gateway, phone, scope or token binding.
Root validates the full retained candidate, fresh challenge, current enrollment, expiry and replay state.
The authenticated channel supplies the phone identity; successful parsing is not authentication.

### Outcome

The body is one unsigned tag:

| Tag | Meaning |
| --- | --- |
| 0 | Unavailable: no affirmative result is established |
| 1 | Proof committed: Root consumed this candidate proof |
| 2 | Mapping confirmed: Root verified and retained gateway activation of the corresponding current mapping |
| 3 | Superseded: this candidate is no longer current |
| 4 | Expired: the retained candidate is expired |
| 5 | Incompatible: the locally supported contract cannot serve this operation |

Proof committed is not mapping confirmed.
Provider acceptance is not phone delivery.
A previous mapping confirmation is not a current connectivity or desktop-presence claim.
Do not return Mapping confirmed from a successful codec call, an enqueue future, or proof consumption alone.

## Integration and recovery requirements

A provider challenge can precede Prepared metadata.
Android needs a bounded challenge join that checks the current provider sender, generation, token revision and trusted enrollment.
Challenge payloads are never displayed as approval requests or logged.
Disablement, token rotation, re-enrollment and revocation must prevent an older response from publishing success.
No network suspension may occur while holding the provider or enrollment storage lock.

Registration is independent for every active host enrollment in the same app.
No primary Mac or central enrollment service is introduced.
Ordinary registration and recovery must not request a biometric prompt.
Resource limits and retry policy stay local and configurable.

Complete the production path through the existing protected authority IPC and gateway control channel.
A network-facing transport cannot select Root policy, expose the challenge, or claim a gateway acknowledgment it did not validate.
Current enrollment and provider checks must surround actual publication, not only start a request.

## Candidate evidence and remaining work

Swift and Kotlin pass the same nine valid and twenty-two invalid fixtures.
Focused controls check challenge exclusion, role separation, redaction, mutable input, scope matching and distinct outcome tags.
The phone channel and native authority exchange also have focused controls.
The native/JVM interoperability suite passes 69 controls, including direct and relay registration sessions.
A live Mac XPC experiment passes 48 controls, including five registration selector cases.
These checks use disposable software keys and synthetic payloads. They do not establish installed Root or FCM behavior.

The authority consumes proofs through the request owner and independent continuity checkpoint.
Registration uses a separate IPC connection, so unsupported Root versions cannot retire the ordinary approval connection.
The Root producer exposes challenge-free metadata. It returns Proof committed after consumption, never Mapping confirmed.

Still required: protected startup policy, actual provider challenge ingress, current-generation join/recovery,
gateway activation and its acknowledgment, production app wiring and real FCM delivery.
A mapping-status query and recovery contract remain required before the phone can display Mapping confirmed.
The first foreground Mac–Pixel approval remains independent of this push-registration work.
