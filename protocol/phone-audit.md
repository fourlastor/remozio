# Phone audit carrier, version 1

Swift and Kotlin use the same canonical carrier. It preserves existing signed history and batch payloads.
The carrier grants no approval, command, enrollment, or credential authority. Parsing does not verify a signature or create trusted audit evidence.

## Envelope

Use the dedicated application protocol `remozio-audit/1`. Every field in this closed CBOR map is required.

| Key | Value |
| --- | --- |
| 0 | Domain `dev.remozio.phone.audit` |
| 1 | Schema version `1` |
| 2 | Kind from the table below |
| 3 | Fresh query nonce, 32 bytes |
| 4 | Payload for the selected kind |

| Kind | Payload |
| --- | --- |
| 0 | History query: `[epoch, after]` |
| 1 | Page query: `[epoch, generation, after]` |
| 2 | History response: `[original payload bytes, raw signature]` |
| 3 | Page response: `[original payload bytes, raw signature]` |
| 4 | Failure: `0` means unavailable; `1` means incompatible |

For history discovery, both fields are null. Otherwise, the epoch has 16 bytes and the cursor is an unsigned integer.
A page query has a 16-byte epoch and unsigned generation and cursor values. Integers retain the full unsigned 64-bit range.
Unknown domains, versions, kinds, fields, and failure codes fail parsing.

## Bounds

A query permits at most 256 bytes. A response payload permits 1 through 1,048,576 bytes. A signature has exactly 64 bytes.
The complete carrier permits 1,048,832 bytes, depth 3, and 20 CBOR items. A lower channel budget must also hold.
These limits grant no storage retention or pruning authority.

## Trust

The caller must match the kind and nonce to its original pending query. The existing receiver must then verify the typed payload and signature.
It must check the trusted Root key, Mac, account, epoch, generation, cursor, nonce, and elapsed deadline before retaining evidence.
An unsigned failure never means empty history or a successful sync. Cancellation and transport failure preserve retained evidence and the established authority key.

The shared fixtures contain 32 valid carriers and 89 malformed carriers. They preserve all 23 existing signed history and batch fixtures byte for byte.
The prepared tests cover both languages, original signature purposes, bounds, invalid fields, and mutable byte ownership.
Codec tests do not qualify installed Root authorization, XPC, TLS admission, cache ownership, or phone synchronization.
Runtime audit selection remains a separate protected operation.
