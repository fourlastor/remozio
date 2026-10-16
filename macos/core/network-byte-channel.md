# Owned native byte channel

`NetworkByteChannel` takes ownership of one unstarted `NWConnection` and starts it once.
The caller must not start or operate that connection separately after construction.
When ready, the channel runs the caller's admission check before exposing byte operations.

This owner does not select TLS identities or authorize application requests. Its caller configures the connection with authenticated peer pins and the required TLS restrictions. Admission verifies the negotiated profile. The callback must be short, synchronous, and free of network access. The synthetic TLS listener checks TLS 1.3, ALPN, and rejected early data after the pinned mutual handshake.

The actor admits at most one outstanding read and one outstanding write. Concurrent callers receive an error instead of joining an unbounded queue. A read returns at most 32,768 bytes; each write accepts between one and 32,768 bytes. The caller streams larger frames and validates their total size separately. This chunk size is not an approval capture limit.

Opening has a configurable deadline from 1 to 60,000 milliseconds, with a 15-second default. Waiting or preparing states cannot extend that deadline. After opening, there is no implicit idle timeout: the protocol owner chooses request and channel deadlines. Cancelling an admitted operation records cancellation synchronously and aborts the entire connection, including the opposite direction. Callback completion and operation admission check that same locked state. A callback that commits completion first stays completed; a later callback cannot succeed ahead of a queued close. Explicit close is idempotent. Both paths release all pending continuations and never retry bytes.

A native error discards any accompanying data and fails the channel. Input EOF can return final bytes, then subsequent reads return nil. The write direction remains available for a final response until the owner closes the channel. Send completion only reports local stack processing. Neither send completion nor EOF proves delivery, approval, or execution. The application ledger remains responsible for uncertain outcomes.

The channel keeps no payload log. Native error details are reduced to a generic failure. It drops its state handler and cancels the connection on close or destruction. Callback arrivals after closure cannot reopen it.

Tests cover admission ordering, simultaneous read/write, rejected concurrent calls, deadline expiry, cancellation, late callbacks, errors, chunk bounds, and EOF response behavior. The JVM/native TLS suite uses this owner for its real loopback socket operations. Production enrollment invalidation, protocol framing, service lifecycle, and device-backed keys remain separate work.
