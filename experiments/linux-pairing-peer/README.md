# Linux pairing peer (experiment)

Software-key mode only. The TLS identity is a file-backed P-256 key, not a TPM key, so nothing here is evidence of
host key custody. The peer is operator-confirmed and is not the protected host service.

This directory holds the M2.2 TLS adapter: a C shim over system OpenSSL 3 for the `remozio-pairing/1` channel.

- TLS 1.3 only, exact ALPN `remozio-pairing/1` (a client offering anything else is refused), no tickets,
  `num_tickets 0`, `max_early_data 0`, no session cache.
- The server demands a client certificate. The verify callback accepts any chain, and after the handshake the
  shim requires one self-signed, currently valid P-256 leaf and exports its 65-byte uncompressed point. The
  phone pins that key, not the certificate bytes.
- Every handshake, read and write takes an absolute deadline on `CLOCK_BOOTTIME` and an optional cancel
  descriptor. A handshake never runs longer than 60 s. A timeout is never reported as a rejection.
- `remozio_tls_make_identity` mirrors the Mac `TransportTLSCertificate` profile (CN `Remozio transport`, critical
  `CA:FALSE`, critical `digitalSignature`, EKU `serverAuth` and `clientAuth`). It uses OpenSSL, not
  swift-certificates, so the shim has no Swift dependency; the profile is the same.
- The shim sets `SIGPIPE` to ignored for the whole process.

Run `./scripts/check-linux-pairing-peer.sh`. The tests assert the negotiated version, ALPN, ticket count and
resumption, not library defaults, and cover wrong ALPN, TLS 1.2, missing, wrong-curve, expired and not-yet-valid
client certificates, a silent peer, cancellation during handshake and read, a stalled write, peer close and
descriptor leaks.
