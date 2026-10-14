# Pairing comparison code, format 1

The Mac and Android app display the same code for the complete Root-returned pairing transcript.
Compare it on independently authenticated setup surfaces before confirming enrollment or starting the phone biometric.
Comparing two values supplied by one untrusted message does not authenticate either device.

Use the existing full transcript digest: SHA-256 over the canonical phone-biometric signing input.
Read its first 100 bits from most significant to least significant. Encode consecutive five-bit groups with this alphabet:

```text
23456789ABCDEFGHJKLMNPQRSTUVWXYZ
```

Display the 20 symbols as four groups of five, separated by spaces.
The alphabet excludes zero, one, I and O. Both implementations use the same shared vectors.
The format changes no transcript bytes, signing purpose, wire frame, invitation or receipt.

The displayed code carries 100 bits of comparison data. It is not the full 256-bit digest or an enrollment credential.
Root confirmation still sends and checks the complete digest. Phone signatures and commit receipts bind the complete canonical transcript.
The invitation's diagnostic fingerprint remains separate and unchanged.

The code binds both devices' keys, identities, protocol choice, fresh challenge, setup ID, trust revision and expiry.
Changing setup cancels previous human confirmation and any pending biometric operation.
A matching code never replaces local administrator authorization, fresh biometric signing, current trust checks or receipt verification.

Physical comparison, native administrator prompts and hardware enrollment remain interactive integration checks.

The signed Mac release declares `pairing.invitation` and `pairing.transcript` version 1 for their consuming roles.
The transport declares `pairing.setup-frame`, `transport.pairing-config`, and the local pairing control formats at version 1.
The Root declares its pairing setup configuration and local IPC at version 1.
Its presence startup format declares versions 1 and 2. Version 2 includes the optional pairing configuration.
These declarations do not grant enrollment or enable service installation.
