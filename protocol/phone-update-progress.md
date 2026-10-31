# Read-only phone update progress

The separate carrier uses `remozio-update-progress/1`.
Its CBOR domain is `dev.remozio.phone.update-progress`.
It carries Status, Response and Failure messages only.
It cannot carry a challenge, scheduling control, artifact, target action or security floor.

Every frame has exactly five keys: domain 0, wire version 1, message kind 2, query nonce 3 and payload 4.
The wire version is 1. The query nonce has 32 bytes.
Status has kind 0 and a null payload.
Response has kind 1 and a two-item array: canonical progress bytes and a 64-byte Root signature.
The nested progress status must contain the same nonce.
Failure has kind 2 and an unsigned reason: unavailable 0 or incompatible 1.
The frame limit is 8,192 bytes. The nested progress retains its separate 4,096-byte limit.
Unknown fields, roles, reasons, versions and noncanonical encodings fail.

Parsing does not authenticate the Root signature or establish freshness.
The phone must verify the enrolled authority key, full enrollment scope and original query lifetime before presenting a verified observation.
It must recheck current enrollment after verification.
A valid response remains an observation. It cannot acknowledge an uncertain scheduling operation or authorize an install.

An unsigned Failure cannot report Too late or claim that activation started.
The UI needs authenticated progress for that state.
A future control result must retain its own correlation and consumption semantics.
The current scheduling carrier remains separate and unchanged.

The protocol constant does not advertise this channel.
Production routing requires its own authenticated purpose, capability check, Root provider and current machine/account snapshot.
An older Root must leave ordinary approval delivery intact when it cannot supply progress.
Live TLS, Root signing, product controls and physical-device behavior remain separate gates.
