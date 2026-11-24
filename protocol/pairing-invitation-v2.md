# Pairing invitation v2

Version 2 proves possession of a local pairing invitation before the host presents a candidate. This document specifies the invitation, proof and prelude. The current clients and listeners continue to use their existing setup protocol until a later integration enables v2.

## Invitation

Encode a deterministic CBOR map with exactly the following fields. Accept at most 768 encoded bytes. The QR code and copied text use the prefix `remozio-pairing:v2:` and the same unpadded base64url payload, at most 1,043 ASCII characters including the prefix.

| Key | Value |
| --- | --- |
| 0 | Version 2 |
| 1 | Canonical v1 public invitation as a byte string |
| 2 | 16-byte Authority window ID |
| 3 | 32-byte invitation secret |
| 4 | Use tag 0 for initial enrollment or 1 for re-pair |
| 5 | Null for initial enrollment. For re-pair, the four 16-byte values for Mac ID, account ID, predecessor phone ID, and predecessor epoch |
| 6 | Window lifetime for display, from 1 to 300,000 milliseconds |

The predecessor Mac and account must match the public invitation. Decoding checks canonical bytes, lengths and the exact set of keys. The Authority controls actual expiry using its elapsed clock. Handle the serialized invitation as a credential. The secret travels in the user’s local QR or copy flow and stays out of network frames and logs.

## Connection proof

Use TLS 1.3 pinned to the Mac transport key, with ALPN `remozio-pairing/2`. The challenge is 32 bytes from Transport. Derive 32 exporter bytes on the same TLS connection with label `EXPORTER-dev.remozio.pairing.invitation/2` and empty context. Transport supplies the challenge and exporter to the Authority through its authenticated local channel. [TLS 1.3 exporters](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)

Derive a 32-byte key with HKDF-SHA256, the invitation secret as input keying material, the window ID as salt, and the UTF-8 string `dev.remozio.pairing.invitation-key/2` as info. Produce the full 32-byte HMAC-SHA256 tag over a deterministic CBOR array of five elements, in this order. [HKDF](https://www.rfc-editor.org/rfc/rfc5869.html#section-2)

1. Text `dev.remozio.pairing.invitation-proof/2`.
2. SHA-256 of the invitation’s six-key public map, canonically encoded after omitting key 3.
3. The Transport challenge.
4. The TLS exporter.
5. SHA-256 of the canonical phone proposal.

Encode the four byte values as CBOR byte strings. The proof binds the public pins, window, intended use, predecessor, lifetime (key 6) and proposal. Proof generation and verification reject proposals with a different Mac or account scope or a phone key that reuses a Mac public key. The Authority compares the tag in constant time. Transport still checks that the proposal’s transport key matches the TLS peer. Only the Authority decides expiry, exclusive reservation and enrollment consent.

## Prelude and recovery

The prelude uses the existing length-prefix framing for a deterministic CBOR map. Its body limit is 66,128 bytes. The exact map keys are 0, 1, 2 and 3. Key 0 is `dev.remozio.pairing.exchange`, key 1 is version 2, key 2 is the kind, and key 3 is the body.

| Kind | Direction | Body |
| --- | --- | --- |
| 0 | Transport to phone | 32-byte challenge |
| 1 | Phone to Transport | Array of the canonical phone proposal byte string and the 32-byte tag |

Under `remozio-pairing/2`, the proposal in the proof is the only proposal. The peer sends no subsequent v1 Proposal frame. The Authority checks the transcript against the proved proposal with `proposal.validate`. When v2 is active for a window, the Authority rejects setup with ALPN `remozio-pairing/1` for that window. This prevents a peer from using the public invitation in key 1 to bypass proof of possession. These requirements apply when v2 is integrated.

Following proof, the existing transcript, biometric proof and receipt formats retain their encodings. Authority staging still follows candidate selection and administrator authorization. Recovery keeps its separate ALPN, exporter domain and signed expiry receipt. The v2 vectors bind a fresh synthetic re-pair transcript to the new prelude and verify its recovery proof, commit receipt and expired-without-commit receipt.
