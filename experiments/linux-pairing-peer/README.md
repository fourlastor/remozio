# Linux pairing peer (experiment)

Software keys only. The identity generator returns a P-256 key and certificate in DER buffers. The TLS adapter does
not persist the identity; the `remozio-linux-pair` tool below does. Host key custody remains unqualified. The peer
requires operator confirmation.
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
leaks. Every rejection case, including both directions of the post-handshake rejection, closes both outcomes and
requires the process to hold exactly the descriptors it held before. They inspect the timer clock, absolute arming,
handshake cap and descriptor cleanup through `/proc/self/fdinfo`.

### Attended host suspend probe (`remozio-tls-suspend-probe`)

The tests show that each wait arms an absolute `CLOCK_BOOTTIME` timer. They do not suspend the host. That needs an
operator, so the check script builds this probe and never runs it.

The probe completes one loopback handshake, then waits in a server read on a silent peer with a deadline on
`CLOCK_BOOTTIME`. The operator suspends the host before the printed time and resumes it after the second printed time,
so the deadline passes during the suspension. A heartbeat thread finds the resume from the jump between
`CLOCK_BOOTTIME` and `CLOCK_MONOTONIC`.

```sh
./scripts/check-linux-pairing-peer.sh
.build/linux-swift/pairing-peer/build/debug/remozio-tls-suspend-probe --wait-seconds 120 --output suspend-probe.json
```

The JSON records the clock readings, the read status and the kernel release; no host name, address, key or
certificate. The verdict is:

- `passed` (exit 0): the read timed out, a suspension of at least 10 s began before the deadline and ended after it,
  and the read ended within 5 s of resume;
- `inconclusive` (exit 3): the read timed out, but no suspension spanned the deadline. Run it again;
- `failed` (exit 1): any other status, an early return, or a read that ended more than 5 s after a spanning resume.
  A read that waits out its remaining awake time after resume fails here, whatever its total awake time.

It covers a read deadline only. The handshake uses the same wait but is capped at 60 s. One run is evidence for that
host, kernel and sleep state only.

**Attended run, 2026-11-08 ([issue 496](https://github.com/rock3r/remozio/issues/496)): passed.** The host was an x86_64
desktop (Intel Z890 chipset) running kernel 6.17.0-41-generic. The operator suspended it to `deep` (S3, as `PM: suspend
entry (deep)` in the kernel log shows) with `systemctl suspend -i`. The probe ran with `--wait-seconds 180` and
recorded:

| Field | Value |
| --- | --- |
| `suspendedMs` | 215005 |
| `suspensionStartedBeforeDeadline`, `resumeAfterDeadline`, `deadlineExpiredDuringSuspend` | `true` |
| `readStatus` | `timeout` |
| `readEndedAfterResumeMs` | 0 |
| `monotonicElapsedMs` / `realtimeElapsedMs` | 61106 / 276111 |

The read returned its timeout as soon as the host resumed, and did not wait out its remaining awake time. An earlier
run on the same host, with no suspend, reported `inconclusive` as designed. This does not cover `s2idle`, other
hardware or kernels, a handshake that spans a suspension, or a real network peer.

On a GNOME desktop, an application's suspend inhibitor (for example, a desktop app that keeps the session awake)
blocks a plain `systemctl suspend` with `Operation inhibited`. `systemctl suspend -i` ignores inhibitors for that one
suspend.

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

Directory opening uses a no-follow `O_PATH` descriptor before it requires read permission. The store checks ownership
and refuses an existing directory with group or other permissions. It restores mode 0700 through the pinned descriptor
and then opens the same inode for reading. Permission repair requires `/proc/self/fd`; a missing procfs mount causes a
storage error. A restrictive umask test runs in a separate process as a non-root user. Root runs skip that test.

A crash before the rename leaves the old state. A crash after it leaves the complete new state. The tests inject a crash
before each step. The default clock is `CLOCK_BOOTTIME`, which counts suspend. The store refuses a corrupt state file and
never resets it.

This module is part of the software-key experiment. It is not the protected host journal, and it gives no claim about
host key custody.

## Foreground pairing tool (`remozio-linux-pair`)

**Experiment, software keys.** Every command prints `EXPERIMENT: software keys. Not the protected host service.`
The tool is a foreground command that an operator runs and watches. It installs nothing, starts no service and
does not claim the [Linux host contract](../../docs/linux-host-contract.md), which allows no software-key fallback.
Any process of the same user can read its keys.

```
remozio-linux-pair [--state-dir DIR] init [--label LABEL]
remozio-linux-pair [--state-dir DIR] invite
remozio-linux-pair [--state-dir DIR] pair [--listen ADDRESS:PORT] [--no-advertise]
remozio-linux-pair [--state-dir DIR] list
```

- **State.** `--state-dir`, else `$XDG_STATE_HOME/remozio-linux-pair`, else `~/.local/state/remozio-linux-pair`.
  The identity (`identity.json`: random Mac and account IDs, a label, the transport and authority P-256 keys) lives
  in the commit store's directory. It is read and written under the same `state.lock`, with the same no-follow,
  owner and 0600 checks as `state.json`. `init` publishes it once: temporary file, `fsync`, a hard link that fails
  if an identity exists, removal of the temporary name and an `fsync` of the directory. It never replaces an
  identity and refuses a corrupt or partial one.
- **Invitation.** `invite` prints the shared `remozio-pairing:v1:` text and fingerprint, and a terminal QR code
  when `qrencode` is installed. The tool adds no QR dependency.
- **TLS.** Each `pair` run presents the persisted transport key under a fresh certificate in the Mac
  `TransportTLSCertificate` profile (`remozio_tls_issue_certificate`). The phone pins the key, not the certificate.
- **Discovery.** `pair` advertises `_remozio-pairing._tcp` as `R-` plus the unpadded base64url Mac and account IDs,
  the name the Android client looks for, through `avahi-publish` held for the life of the run. avahi renames a
  service after a name collision, so the tool withdraws the advertisement instead. Without `avahi-publish` it
  refuses to start unless `--no-advertise` is given. A loopback listener is never advertised. The listener is IPv4.
- **Exchange.** One candidate at a time, in the order of `protocol/pairing-setup.md`: hello; one proposal whose
  transport key must equal the TLS client key and whose scope must be this Mac and account; a transcript the tool
  mints (fresh setup ID, challenge, enrollment tag and Mac offer with envelope version 1 and no request or audit
  contracts; the phone's claims unchanged; the store's trust revision; a five-minute expiry); operator
  confirmation; one proof; commit; one MAC_COMMIT receipt. A candidate that fails before it receives a
  transcript never reaches the operator, and the tool keeps listening. Any later failure ends the run.
- **Confirmation.** The terminal does not show the comparison code. The operator types the code the phone shows;
  case, spaces and dashes are ignored. A match binds the SHA-256 digest of that exact transcript, and the commit
  refuses any other transcript. Input that arrived before the transcript was sent is discarded. End of input, a
  mismatch or the deadline confirms nothing. No option skips this step.
- **Commit and receipt.** The receipt is signed only after `commit` returns normally. On `committedLate` or
  `committedUnconfirmed` the tool sends no receipt and reports the enrolled state as unknown (exit 4). If the
  receipt cannot be written after a good commit, nothing is retried (exit 3); `list` shows the enrollment.
- **Deadlines.** The setup limit and the transcript lifetime are five minutes on `CLOCK_BOOTTIME`. They bound
  network I/O, the operator prompt and the commit.

**Evidence.** `LinuxPairAuthorityTests` cover identity persistence, concurrent `init`, an interrupted write,
corrupt, symlinked and group-accessible state, the invitation and service-name formats, the TLS key, frame order,
transport-key and scope refusal, code mismatch, end of input, a confirmation bound to another transcript, invalid
proofs, expiry, a duplicate phone, a full store, an undelivered receipt and a late commit.
`:phone-core:linuxPairToolTest` runs the Android protocol client (`PairingSetupChannel`) against the real binary on
loopback with disposable software keys: it enrolls a phone and verifies the receipt, refuses a wrong code without a
receipt or enrollment, and refuses a candidate whose transport claim differs from its TLS key while the right phone
still pairs on the same run.

**Physical iPhone.** The iOS Test connection reaches this tool's transcript over a typed address, with an enclave
transport key on the phone ([result](../../docs/experiments/ios-enclave-tls.md)). The phone's test stops at the
comparison code and sends no proof.

**Not tested.** A complete pairing from a physical phone, mDNS discovery through `avahi-daemon`, an IPv6 listener,
host suspend during setup, and any custody claim for this tool's own keys, which are software keys.
