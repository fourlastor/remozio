# Command receive budget observations

The receiver includes sender authentication in its receive budget.
The strict receive methods discard the queue head and return timeout when authentication exhausts that budget.
The command host maps that timeout to an idle event.
Before the listener repair below, an empty queue and a discarded packet had the same worker observation.

## Native sample

The [sanitized record](command-receive-budget.json) binds a disposable probe and the baseline receiver by source hash.
The probe used the strict `receiveHello` method on ordinary-account Mach ports on macOS 27.0.1.
It created no service, approval or command execution.

| Queue state | Receive budget | Actual send time | Result |
| --- | --- | --- | --- |
| Prequeued | 10 ms | 0.105 ms | Accepted |
| Prequeued | 1000 ms | 0.006 ms | Accepted |
| Late arrival | 10 ms | 9.741 ms | Timeout at 14.697 ms; queue empty |

The final sample reproduces the packet loss path.
It does not establish the cause of the grant-reload failure in [issue 313](https://github.com/rock3r/remozio/issues/313).
Scheduler timing varies, so the sample is not a CI test.

## Diagnostic implementation

Internal fixture observers distinguish preview wait, authenticated-preview budget exhaustion, and packet receive timeout.
A worker observer reports idle, hello, input handled, or a rejection category.
It omits profiles, request bytes, caller bindings and credentials.
Observers run on the receive queue and must return promptly without reentry.
Public construction leaves them disabled.

The grant-reload test records fixed-size, saturating counters only when it fails.
Its original receive budget, two-second wait, policy checks and cleanup assertions remain unchanged.

Four new regression tests exercise real Mach ports and sender authentication.
A fixture clock makes the authenticated discard boundary deterministic.
The tests check empty-queue classification, discarded reply-right cleanup, peer rejection, and worker recovery after a malformed hello.
The diagnostic change added evidence without changing packet handling or authorizing retry.


## Queued listener repair

`CommandReceiveHost` polls through `receiveNext`.
That method now treats its timeout as a queue-wait budget.
After authenticating a queued hello or input, it can receive that packet without waiting again when the budget is exhausted.
The kernel receive uses `MACH_RCV_TIMEOUT` with zero milliseconds.
It still checks the preview sequence, audit token, packet shape, descriptor ownership and current caller.
The host still reloads its policy and checks cancellation before handling input.

The direct receive methods and all client reply methods retain their total deadline checks.
`receiveExecutionEvent` also retains its strict deadline despite sharing the parser with the listener.
Unknown carriers get no listener exception.
No packet is resent, and receipt grants no admission or execution authority.

Five new real-Mach tests force authentication beyond a one-millisecond poll budget through the fixture clock.
They cover a queued hello, all four input carriers, unread pipe bytes, descriptor cleanup, sender rejection and strict reply deadlines.
Existing admission deadline and cancellation tests pass unchanged.
The original grant-reload test keeps its deadlines and assertions.
Its historical CI cause remains unconfirmed.

The [native listener record](queued-listener-receive.json) uses `receiveNext`, unlike the historical strict-method sample.
It accepted prequeued controls at 10 ms and 1000 ms.
A late hello arrived at 8.287 ms and was accepted at 12.999 ms with a 10 ms poll budget.
These timings are observations; the deterministic tests prove the budget boundary.
The probe completed no handshake, registered no service and created no approval.
