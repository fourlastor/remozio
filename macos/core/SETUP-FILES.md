# Encrypted setup files

`SetupFileEncryption` encrypts and decrypts the container for portable setup exports.
The protected setup host must supply an allowed payload and validate its schema before preview or import.
The codec does not export configuration, read credentials, install services, or apply imported settings.

## Version 1 container

The file uses [JWE compact serialization](https://www.rfc-editor.org/rfc/rfc7516.html). Its fixed algorithms are `PBES2-HS512+A256KW` and `A256GCM`, as specified in [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8). JOSESwift 3.0.0 supplies the cryptographic implementation; the package version and resolved revision are pinned.

| Field | Contract |
| --- | --- |
| `typ` | `remozio-setup-v1+jwe` |
| `alg` / `enc` | The fixed algorithms above; no negotiation |
| `p2s` | Fresh random 32-byte salt |
| `p2c` | Export: 220,000; import: 220,000 through 1,000,000 |
| Content key / nonce | Fresh random 256-bit key and 96-bit GCM nonce |
| Payload | 1 through 1,048,576 bytes |
| Encoded file | At most 1,400,000 bytes |
| Password | 1 through 1,024 UTF-8 bytes; no normalization or truncation |

The work factor follows the current [OWASP PBKDF2-HMAC-SHA512 guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). It replaces the library's 1,000-round default. Password strength still matters against offline guessing. The setup UI must explain this and offer a strong password; this codec does not estimate entropy.

The profile accepts exactly the five protected header fields above.
It requires compact sorted-key JSON and canonical unpadded base64url.
Canonical reserialization rejects duplicate keys and alternative representations before the library parses them.
The importer rejects compression, extra headers, other algorithms, and unknown type versions.
It accepts only this setup-file profile.

The codec checks all lengths and the iteration range before password derivation.
It returns plaintext only after successful authentication.
Errors contain no input, password, decrypted content, or provider error details.
The codec creates no plaintext staging file.

Swift and provider copies cannot be reliably erased.
Callers must avoid retaining or logging secrets.
Derivation runs synchronously and must stay off the UI thread.
The host must serialize imports to limit concurrent resource use.

## Integration boundary

The payload schema below selects shared configuration explicitly. It excludes authority keys, device keys, pairings, ADB keys and grants, approval credentials, audit history, pending requests, and another Mac's tunnel run identity. A valid password or container does not make a payload safe to apply.

File selection, category preview, protected import, independent identity creation, and credential provisioning remain pending. This component never mutates live state. Copies of exported credentials remain usable until those credentials are revoked; deleting an export does not revoke them.

## Evidence

The tests cover wrong passwords, altered encrypted parts and headers, duplicate fields, unsupported algorithms, excessive derivation work, and size limits. They also open a fixture generated independently with Node's crypto provider. Reproduce the public synthetic fixture with:

```sh
node scripts/generate-setup-encryption-fixture.mjs
```

The fixed keys in that generator are test data only. Tests also verify fresh export randomness, exact Unicode password handling, and a maximum-size payload. No real provider credentials or device keys are used.

## Typed setup payload

`PortableSetup` encrypts a selected configuration and decodes it into an immutable proposal. It never reads current machine state. `preview` lists included categories and provider scope identifiers without passwords, private keys, or tokens. The caller must show this scope before export and again before import confirmation.

The decrypted payload uses deterministic CBOR, with a 65,536-byte limit, a depth limit of four, and at most 128 items. Every map has exactly the documented keys. Unknown fields, duplicate keys, unsupported versions, invalid types, and invalid settings fail the whole import. Nothing is partially applied.

| Root key | Value |
| --- | --- |
| 0 | Payload version, unsigned integer `1` |
| 1 | Shared defaults map |
| 2 | FCM map, or null when omitted |
| 3 | Cloudflare provisioning map, or null when omitted |

The defaults map has keys 0, 1, and 2. Each holds an ordered array of unsigned integers:

- Presence: idle milliseconds, observation lifetime milliseconds, unavailable grace milliseconds.
- Wake delivery: maximum entries, maximum attempts, minimum enrollment interval milliseconds, maximum lifetime milliseconds, maximum TTL seconds.
- Delivery scheduler: maximum flights, minimum send interval milliseconds, retry base delay milliseconds, maximum retry backoff milliseconds.

The existing `PresenceConfiguration`, `GatewayWakePolicy`, and `GatewayDeliveryPolicy` validators apply. Current routing mode, per-device overrides, cryptographic policy, biometric requirements, and ADB enablement have no payload fields. Presence defaults may be applied only through local protected Mac setup. An Android request must not invoke this import path.

The FCM map has text values at these numeric keys: 0 project, 1 client email, 2 private key ID, 3 PKCS#8 private key PEM. Key import uses the existing FCM validator. OAuth audience and scope remain fixed by Remozio. No raw service-account JSON or caller-selected endpoint is retained.

The Cloudflare map has text values: 0 account ID, 1 zone ID, 2 DNS suffix, 3 provisioning API token. IDs use 32 lowercase hexadecimal characters. DNS labels use lowercase ASCII, with normal label and total length bounds. The token has 1 through 4,096 printable ASCII bytes. There is no tunnel identity or run credential field.

These checks establish syntax, not online permission or credential purpose. Before provisioning, the setup host must verify account/zone access, the DNS suffix's scope, and the token's required permissions. Opaque token text alone cannot prove that it is a provisioning token. Imported credentials must create fresh machine resources; they must never attach the new Mac to another Mac's tunnel identity.

The first payload version covers the implemented presence and push settings. Update, retention, and other settings need schema support as their components arrive. Version changes must be explicit; unknown settings must not silently become active.

Tests use a disposable synthetic RSA key, synthetic provider identifiers, and no provider calls. They check full and settings-only round trips, redacted descriptions, preview contents, unknown fields at each map boundary, integer overflow, and malformed provider input. Protected application, identity creation, credential storage, and the setup UI remain pending.
