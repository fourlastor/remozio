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
- The shim leaves the process's `SIGPIPE` disposition alone. Its socket BIO sends with `MSG_NOSIGNAL`, so a write to a
  reset or closed peer reports `REMOZIO_TLS_CLOSED` (or `REMOZIO_TLS_IO`) instead of raising `SIGPIPE`. Descriptors
  must be sockets.
- A successful accept or connect means only that this side accepted its peer. TLS 1.3 completes the client before
  the server judges the client certificate, and the client sends its last handshake message before it judges the
  server's. A peer that rejects us closes without a TLS alert, so the rejected side first sees an accepted connection,
  then `REMOZIO_TLS_CLOSED` on its first read or write. An integration must treat the first authenticated application
  message, not the handshake result, as evidence that the peer accepted this identity.

Run `./scripts/check-linux-pairing-peer.sh`. The tests assert the negotiated version and ALPN, and that each side
exports exactly the other side's public point, derived independently from that side's private key. They observe
zero tickets and no reused session in two fresh handshakes.

The test-only `CPairingTLSTestSupport` target supplies plain OpenSSL peers configured beyond what the adapter allows.
It is not part of the adapter. With it, the tests show:

- **Ticket counter, positive control:** the adapter client counts the two tickets a ticket-issuing server sends.
- **Saved-session attempt:** a client resumes the ticket-issuing server with its saved session (positive control),
  then offers that session to the adapter server. The adapter performs a full handshake, authenticates the client's
  key, reports no reuse on either side and sends no ticket. The offered session came from another server; the
  adapter has no ticket of its own to resume.
- **Certificate and ALPN negatives at both endpoints:** a leaf signed by another key, with a different issuer name or
  with its own name; an extra chain certificate after a valid leaf; and ALPN lists that add another protocol before
  or after the pairing protocol, or repeat it. The exact single-protocol offer from the same raw client is the
  control.
- **Rejection after the handshake:** the status each side observes, as described above.
- **No `SIGPIPE`:** with the default disposition restored, creating contexts leaves it unchanged, and a write to a
  closed peer reports `REMOZIO_TLS_CLOSED`. The raw test peers use OpenSSL's ordinary socket BIO, so the test process,
  not the adapter, ignores `SIGPIPE` for them.

The tests also cover wrong ALPN, TLS 1.2, missing, wrong-curve, expired and not-yet-valid client and server
certificates, a silent peer, cancellation during handshake and read, a stalled write, peer close and descriptor
leaks. They inspect the timer clock, absolute arming, handshake cap and descriptor cleanup through
`/proc/self/fdinfo`. An actual host suspend/resume test remains pending in
[issue 496](https://github.com/rock3r/remozio/issues/496).

## Durable commit state (`PairingCommitState`)

`PairingCommitStore` holds the peer's trust revision, the consumed setup IDs and the enrolled phones in one state file
(`state.json`) inside a private directory (0700, files 0600). It has no network or TLS code. It takes a decoded
`PairingTranscript`, the phone's biometric proof, a deadline on a suspend-inclusive clock and a cancellation check.

Every open syncs the parent directory first, so no call returns success for a state directory entry that nothing confirmed. A commit then runs under an exclusive `flock` on `state.lock` that honours the deadline and cancellation:

1. rejects a replacement (version 1 has none), an invalid proof, a stale trust revision, a used setup ID, and a phone
   ID or key that is already enrolled;
2. writes the new state (consumed ID, new revision, enrollment, exact transcript) as one atomic change: temporary file,
   `fsync`, `rename`, `fsync` of the directory;
3. checks the deadline and cancellation again. If either fired after the write, it throws `committedLate`. If the
   directory `fsync` fails after the rename, it throws `committedUnconfirmed`. In both cases the caller must not sign
   or send a receipt, and must not commit again.

The caller derives the deadline from the setup limit and the transcript expiry. The store does not read the transcript's
wall-clock window. The store refuses a commit that would pass its bounds (256 enrollments, 4096 setup IDs, 8 MiB) before
it writes, so it can always read back what it wrote. `trustRevision()` and `list()` create the initial state when none
exists, and the configured initial revision applies only then. The module builds on Linux only.

A crash before the rename leaves the old state. A crash after it leaves the complete new state. The tests inject a crash
before each step. The default clock is `CLOCK_BOOTTIME`, which counts suspend. The store refuses a corrupt state file and
never resets it.

This module is part of the software-key experiment. It is not the protected host journal, and it gives no claim about
host key custody.
