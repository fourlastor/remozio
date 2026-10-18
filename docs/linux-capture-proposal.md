# Linux command capture: agreement proposal

The proposal was **accepted with explicit allocations on 18 October 2026** in
[issue #441](https://github.com/rock3r/remozio/issues/441#issuecomment-6253309933).
`L` is now schema 4; requester and credential keys 0–8, desktop-role semantics,
initial pipes/terminate-only behavior and Android wording are defined in the
[protocol contract](../protocol/command-capture.md#linux-requester-and-execution-shape-schema-4).
Interpretation and codec/UI work are approved; production Linux issuance is not.
The original unallocated proposal below is retained as design history.

## Original proposal (17 October 2026)

Status: proposal only, 17 October 2026. No schema number, field tag or feature ID
is allocated here. `L` below denotes a future Linux command-capture schema,
distinct from the existing Mac schemas 1–3. It is not an encodable version today.
This narrows the [Phase 0 contract](linux-host-contract.md) for upstream agreement;
it does not enable issuance or claim that the strict caller profile is implemented.

## Contract selection

Propose command kind 0, existing request wire 1, schema `L`, and no optional
features. Linux caller semantics are mandatory schema semantics, not an optional
feature on Mac schema 3. Unknown feature IDs remain opaque; they cannot select a
Linux renderer or weaken caller checks. Reserve a number only in the reviewed
protocol change that adds both codecs, shared fixtures and Android admission.

Reuse [channel negotiation 1](../protocol/channel-negotiation.md), subject to an
explicit agreement that its existing issuer role 1 and `macID` scope slot identify
an enrolled desktop host on either platform. Keep their bytes and existing Mac
behavior unchanged; use host-neutral UI labels. This is a proposed clarification
of their role, not evidence that Linux already participates in that handshake.
If upstream requires those semantics to remain Mac-exclusive, a separately
versioned handshake must precede Linux integration; do not invent role 2 locally.

An upgraded phone may advertise Mac schemas and `L`; a Linux authority advertises
only the command contracts it can actually issue. Retain the exact capability
intersection per enrolled host/account/phone/epoch and authenticated connection.
Choose a new immutable request using the existing [compatibility policy](../protocol/compatibility-policy.md),
then require signed outer schema = inner schema = selected supported contract.
A Mac-only phone reports Linux command approval unavailable while retaining that
pairing and its other host connections. Never encode Linux as schema 3 to reach it.
Reconnect rechecks support; it cannot translate a pending request, change its
digest, lower trusted floors or create another consumption opportunity.

## Capture shape and preserved bytes

Use a closed deterministic CBOR map with the same fourteen root positions as
[schema 3](../protocol/command-capture.md); position 0 contains `L`. Positions
1–8 and 11–13 keep their meanings and existing value encodings. Position 9 gets
the Linux requester below. Position 10 initially requires exactly the existing
ancestry value “unavailable / empty entries / unsupported,” so no Linux value
ever occupies an ancestor's Mac PID-version slot. Adding useful Linux ancestry
is a later schema change, not fabricated completeness in the first milestone.

Preserve raw absolute path bytes, full argv including argv[0], SHA-256 and
device/inode observations, working directory, target credentials, and the full
effective environment. Retain existing NUL rejection, strict environment-name
ordering, explicit nulls, byte/depth/item limits, unknown-field rejection and
unverified-rationale label. Do not add Unicode normalization or shell expansion.
Root executable is the requested command; requester executable is the frontend.

The initial `L` contract is pipes mode with terminate-on-disconnect only. Root 13
still carries all three retained stream observations/access/semantic flags;
terminal is null and PTY mask is zero. Root 6 must equal layout stdin. All existing
source kinds remain representable, including caller-controlled TTY descriptors
used as ordinary retained streams; this does not establish private-PTY routing.
Paths and opaque stream bindings never authorize reopening a stream. PTY routing,
Linux terminal-device encoding and continue-running are deferred to a separately
negotiated contract, rather than advertised without an execution implementation.

## Linux requester: proposed logical members

Each member below is mandatory; nullable members use explicit null. Nested maps
are closed. Names specify the proposed layout; numeric CBOR member allocation
belongs to the protocol review. Reuse existing shared scalar/file codecs.

| Member | Proposed value and constraint |
| --- | --- |
| `profile` | Exact text `linux-protected-single-thread-v1`; unknown profile fails. This names the required admission policy, not a caller-supplied assurance level. |
| `pid` | Positive UInt32, at most Int32.max, as observed in the admitted host PID namespace. Presentation only; never an authorization lookup key. |
| `processBinding` | Random bytes16 assigned by the authority to one retained kernel process instance; stable only within its monitor incarnation. Not a pidfd, OS identifier, secret or transferable capability. |
| `monitorIncarnation` | Fresh random bytes16 for the protected monitor lifecycle. Restart creates a new value and invalidates pending bindings. No boot UUID or kernel handle is transmitted. |
| `execEpoch` | Positive UInt64, scoped to that monitor/process binding; advanced at each successfully observed exec. Never derived from PID, start ticks, inode or pathname. Overflow retires the binding. |
| `executable` | Existing executable triple: observed raw absolute path, device/inode, SHA-256. Captured at the acknowledged trace stop; it describes a file observation, not a signed publisher. |
| `credentials` | Closed map: four UInt32 UIDs (real/effective/saved/filesystem), four UInt32 GIDs with the same roles, and strictly increasing unique supplementary UInt32 groups. Capture OS values; initial profile requires unchanged equal UID roles and equal GID roles. |
| `sessionID` | Positive UInt32 at most Int32.max, or null when unavailable. It is descriptive and grants no terminal authority. |
| `codePolicyDigest` | SHA-256 bytes32 of the exact protected frontend/loader admission policy used by the authority. A host assertion identifying policy, not independent phone verification of its enforcement. |

All fields are covered by the request digest and host signature. No Apple signing
status, team identifier, cdhash or fake PID version is present. No package-name or
“verified publisher” substitute is introduced. The original submission ID,
nonce and caller-channel binding remain at root 12, with their existing lengths;
they bind the request exchange, while `processBinding` names the retained process.

The authority associates these values with the actual per-message kernel sender
and retained pidfd locally. A live pidfd establishes lifetime, not unchanged
execution. A monitor-local exec counter only describes events observed under its
continuous trace ownership. The first accepted epoch follows verified protected
launch; any subsequent exec invalidates that pending request, even to the same
file. Re-admission requires a fresh capture and decision, never updated signed bytes.

Issuance requires the Phase 0 single-thread, host-namespace, unchanged-credential
profile, protected launch/code policy, and validated final stopped-caller handoff.
Fork/clone, namespace transition, monitor loss and unsupported LSM access refuse
admission. No permissive `unknown` profile is encodable. Lost monitoring cannot
be repaired by matching wire epochs. These host claims do not prove absence of
injection, trusted currently executing memory, or human origin to the phone.
The [caller experiment](experiments/linux-caller.md) proves only its owned-process
fixtures; it does not yet satisfy this issuance gate.

## Android and codec integration

Add a typed Linux requester/capture variant while sharing existing invocation and
stream codecs. Current [Swift](../protocol/swift/Sources/RemozioProtocol/CommandCapture.swift)
and [Kotlin](../protocol/kotlin/src/main/kotlin/dev/remozio/protocol/CommandCapture.kt)
models require Mac PID/signing fields; do not populate those with sentinels.
Advertise `L` only when verification, bounded parsing and rendering all exist.

The Android inspection screen shows “Linux requester,” observed frontend path,
PID, account credentials and “Protected frontend policy (host assertion).” Exact
details expose the policy digest, process binding, monitor incarnation and exec
epoch with their scope explanation. They never become a publisher badge. Show
ancestry unavailable, preserve current exact byte/control/bidi-safe rendering,
and distinguish requested command from requester executable and caller-controlled
streams. A supported schema does not override expiry, fresh biometrics, enrollment,
current grants, durable consumption or the accepted pathname-execution limit.

## Required shared fixture matrix

| Area | Valid / invalid controls before advertising `L` |
| --- | --- |
| Canonical bytes | Identical Swift/Kotlin Linux vectors; unchanged complete Mac corpus; unknown/missing/extra maps, wrong schema, wrong types, noncanonical CBOR and resource limits fail. |
| Invocation/streams | Empty argv elements, non-UTF-8/control paths, environment ordering, every existing source kind/access/flag combination allowed by stream rules; NUL, duplicate env, mismatched stdin, PTY, nonzero mask, terminal and continue-running fail. |
| Requester | UInt64 epoch above UInt32.max survives; zero/overflow epochs, malformed byte lengths, unknown profile, PID bounds, unequal credential roles, unsorted/duplicate groups and nonempty ancestry fail. |
| Binding | Each requester/stream mutation changes digest; changed host/account/epoch/channel scope or outer/inner schema mismatch fails. Parsing matching epochs alone must not create local admission authority. |
| Compatibility/UI | Mac-only and mixed-host offers, disjoint `L`, missing renderer, reconnect without `L`, unknown features and retained requests; only the affected host operation is unavailable, with no legacy fallback. |
| Local monitor tests | PID reuse, same-path exec, thread/namespace/credential changes and monitor restart invalidate pending bindings; codec fixtures alone cannot satisfy these OS checks. |

Upstream decisions are narrow: allocate `L` and its closed requester map; approve
the existing desktop-role interpretation; accept pipes/terminate-only and unavailable
ancestry initially; approve the host-assertion UI wording. Production issuance
still waits for measured protected caller, hardware identity and service gates.
