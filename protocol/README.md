# Protocol foundations

Swift and Kotlin use the same conformance vectors for this directory's deterministic encoding subset.
Both languages also implement the [action policy](action-policy.md), [compatibility policy](compatibility-policy.md), and typed [command capture parsers](command-capture.md).

Prompt capture schemas, authenticated negotiation, and durable consumption remain separate deliverables.
Parsing a value does not authorize an action.

## Deterministic CBOR subset 1

The encoding follows the [RFC 8949 core deterministic rules](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1). Arguments use their shortest encoding. Containers have definite lengths. Map keys are sorted by their encoded bytes; for the supported unsigned keys, numeric order produces this order.

| Supported value | Representation |
| --- | --- |
| Unsigned integer | Major type 0, full UInt64 range |
| Arbitrary bytes | Major type 2 |
| UTF-8 text | Major type 3, valid UTF-8 only |
| Ordered array | Major type 4 |
| Field map | Major type 5, unique unsigned integer keys |
| False, true, null | `f4`, `f5`, `f6` |

Reject every other CBOR type, negative integer, tag, float, indefinite length, reserved argument, non-minimal argument, unordered or duplicate map key, invalid UTF-8 sequence, truncation, or trailing byte. A message contains exactly one value.

Text retains its exact UTF-8 spelling. There is no normalization or replacement of malformed input. The Swift value type also compares text by UTF-8 bytes. Opaque identity, command argument, and credential bytes must use byte strings where the eventual schema requires them. Map field numbers do not define action semantics by themselves.

## Resource bounds

Every encode and decode call requires explicit byte, depth, and item limits. These are local resource guards, not negotiated values from an untrusted peer. No payload is truncated. Byte, depth, and item failures are distinct errors. The caller must map a legitimate oversized capture to the design's `Request too large` result.

The root has depth zero. Each array member, map key, and map value adds one depth level. Every value, container, and map key counts as one item. The configured depth cannot exceed 64, to bound recursive stack use. Limits apply to encoding as well as decoding.

The codec checks the total input size before making its parser copy. It checks lengths before converting them to machine integers or slicing storage. It bounds collection counts before allocating parsed elements. The encoder bounds map counts before sorting keys.

The test harness uses 1 MiB, depth 32, and 65,536 items. These are test budgets only. Production capture limits still require argv/environment measurements and realistic UI fixtures; this change does not set a product payload cap.

## Conformance and use

`vectors/cbor-subset-v1.json` is language-neutral. Valid vectors must decode and re-encode to identical bytes. Invalid vectors must fail. Separate semantic tests check decoded values, integer boundaries, text byte preservation, resource limits, and sliced input. A deterministic malformed-input corpus checks that accepted inputs re-encode identically. It is a regression check, not a substitute for coverage-guided fuzzing.

```sh
swift test --package-path protocol/swift --triple arm64-apple-macosx26.0
./gradlew :protocol-kotlin:test
```

The macOS gate runs the Swift tests. The Kotlin Gradle task and its required CI job run the Kotlin tests on JDK 21. The Kotlin module has no Android device or UI dependency. Its value objects copy mutable input collections and byte arrays. Its encoder rejects unpaired UTF-16 surrogates instead of replacing them. The encoding subset number is not an authenticated wire version. Both codecs currently pass the same byte fixtures. Release compatibility claims still wait for the signed contract and authenticated negotiation.

On Linux, `./scripts/check-linux-protocol.sh` runs the existing Swift suite using
Swift Crypto; macOS continues using CryptoKit. See the [Ubuntu portability
evidence](../docs/experiments/linux-swift-protocol.md) for the toolchain and runtime
requirements. This adds neither a Linux capture schema nor hardware key custody.

## Next security layers

Message schemas must reject unknown critical fields, enums, purposes, and versions. Declared optional fields must remain in the signed bytes. Verifiers must bind both the immutable request and the exact action contract, with separate signature domains and enrolled key purposes. Encoding success alone must never select a key class, infer consent, or permit dispatch.

## Kotlin build inputs

The build pins Kotlin 2.4.20 and Gradle 9.7.0, within the [documented compatibility range](https://kotlinlang.org/docs/gradle-configure-project.html). Install JDK 21 before running the wrapper. JSON support is a test-only dependency for reading the shared fixtures; production CBOR has no serialization dependency.

The wrapper scripts and JAR come from the Gradle `v9.7.0` tag. The JAR matches the [published wrapper checksum](https://services.gradle.org/distributions/gradle-9.7.0-wrapper.jar.sha256): `7a9ce74cff467ca1bf60a4fcd9f05185acceda4d0f382434d393e17864262c5d`. CI checks this before executing it. The wrapper properties also pin the distribution checksum. Update these values together when upgrading Gradle.

The [request lifecycle](lifecycle.md) defines consumption, expiry, and terminal outcomes in both languages.

The [signing input](signing-input.md) separates approval messages by protocol, wire version, type, and purpose.

The [native signature verifiers](approval-signatures.md) implement the P-256/SHA-256 wire representation.

The [decision payload](decision-payload.md) defines strict typed decision claims. Parsing remains separate from authority validation and consumption.

The [issued-request wrapper](issued-request.md) binds capture bytes and metadata, verifies capture digests, and requires explicit local contract support.

The [request status contract](request-status.md) separates signed lifecycle claims from request age and target lifetime estimates. Its Swift and Kotlin codecs do not establish freshness or transition authority.

[Audit event metadata](audit-metadata.md) defines the closed, payload-free record contract for future journal storage and phone history.

[Audit batches](audit-batches.md) define bounded epoch-scoped pages and a signing domain separate from approvals.

[Audit history status](audit-history-status.md) authenticates epoch discovery, prior boundaries, unavailable history and ahead-of-head cursors.

[Gateway token registration](gateway-token-registration.md) defines candidate probes, bound phone receipts, and the separate gateway signature domain.

[Gateway recipient controls](gateway-recipient-controls.md) define separate signed activation and phone-epoch revocation claims.

[Gateway submission controls](gateway-submission-controls.md) define Root-signed rotation and revocation claims for wake-only transport credentials.

[Opaque push data](push-data.md) separates approval wake-ups from provider-only token challenges in Swift and Kotlin.

[Phone routing controls](routing-away.md) define the separately signed Away-only command for an enrolled Mac/account.

The [channel negotiation contract](channel-negotiation.md) binds bounded capability offers, fresh nonces, and version selection to one enrolled TLS connection.

The [negotiated message hosts](session-envelope.md) preserve framing across the handshake and bind application payloads to session IDs and sequences.

The [signed approval carrier](approval-message.md) retains exact bodies and signatures for delivery through the negotiated channel.

The [pairing invitation](pairing-invitation.md) carries public Mac pins through matching QR and text payloads. It does not activate trust.

The [restricted pairing exchange](pairing-setup.md) carries public phone claims, the returned transcript, and purpose-bound proofs through a separate TLS profile.

The [pairing receipt recovery exchange](pairing-receipt.md) retrieves an existing commit proof through a separate enrolled TLS purpose.

The [bounded pending snapshot contract](pending-request-snapshot.md) defines transfer completion and retained status queries. Production adapters remain separate work.
