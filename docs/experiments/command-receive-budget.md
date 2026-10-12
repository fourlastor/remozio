# Command receive budget observations

The receiver includes sender authentication in its receive budget.
When authentication exhausts that budget, it discards the queue head and returns timeout.
The command host maps that timeout to an idle event.
An empty queue and a discarded packet therefore had the same worker observation.

## Native sample

The [sanitized record](command-receive-budget.json) binds a disposable probe and the baseline receiver by source hash.
The probe used ordinary-account Mach ports on macOS 27.0.1.
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
These changes add evidence; they do not repair the discard behavior or authorize retry.
A behavior fix must preserve client deadlines, caller authentication and uncertainty handling.
