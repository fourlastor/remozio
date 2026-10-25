# Linux pairing peer (experiment)

Software keys only. The identity generator returns a P-256 key and certificate in DER buffers. This adapter does
not persist the identity. Host key custody remains unqualified. The peer requires operator confirmation.
Protected host service integration remains pending.

This directory holds the M2.2 TLS adapter: a C shim over system OpenSSL 3 for the `remozio-pairing/1` channel.

- TLS 1.3 only, exact ALPN `remozio-pairing/1` (a client offering anything else is refused), no tickets,
  `num_tickets 0`, `max_early_data 0`, no session cache.
- The server demands a client certificate. The verify callback accepts any chain, and after the handshake the
  shim requires one self-signed, currently valid P-256 leaf and exports its 65-byte uncompressed point. The
  phone pins that key, not the certificate bytes.
- Every handshake, read and write takes an absolute deadline on `CLOCK_BOOTTIME` and an optional cancel
  descriptor. Each wait polls an absolute `CLOCK_BOOTTIME` timer alongside the socket and cancel descriptor.
  The timer includes suspend time and becomes readable after expiry. A handshake has a 60 s deadline cap.
  A timeout is never reported as a rejection.
- `remozio_tls_make_identity` mirrors the Mac `TransportTLSCertificate` profile (CN `Remozio transport`, critical
  `CA:FALSE`, critical `digitalSignature`, EKU `serverAuth` and `clientAuth`). It uses OpenSSL, not
  swift-certificates, so the shim has no Swift dependency; the profile is the same.
- The shim sets `SIGPIPE` to ignored for the whole process.

Run `./scripts/check-linux-pairing-peer.sh`. The tests assert the negotiated version and ALPN. They observe zero
tickets and no reused session in two fresh handshakes. A saved-session resumption attempt and a positive control
for the ticket counter remain pending in [issue 496](https://github.com/rock3r/remozio/issues/496).

The tests cover wrong ALPN, TLS 1.2, missing, wrong-curve, expired and not-yet-valid client certificates, a silent
peer, cancellation during handshake and read, a stalled write, peer close and descriptor leaks. They inspect the
timer clock, absolute arming, handshake cap and descriptor cleanup through `/proc/self/fdinfo`. An actual host
suspend/resume test remains pending.
