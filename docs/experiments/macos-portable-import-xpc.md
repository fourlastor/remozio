# Portable import over native XPC

The disposable experiment uses the version 9 import selectors on a real anonymous XPC connection.
It connects the production channel actor to the production setup endpoint and account owner.
A test-only driver replaces the installed Mach service connection.
Both peers run inside the same ordinary-user test process.

The listener and each connection pin the running test binary's code hash.
The endpoint checks the kernel UID and PID before acceptance.
Every invocation must use the accepted connection and retain its original kernel credentials.
The production constructor still requires a Root peer with the protected Developer ID policy.

The account owner uses temporary machine and import stores.
Service account records and provider credentials are synthetic fixtures.
The only applied operation prepares a retained relay plan.
Port selection briefly binds an ephemeral loopback socket and closes it.
The experiment sends no provider request and launches no service or connector.

## Checks

| Boundary | Observed result |
| --- | --- |
| Legacy hello | The channel rejects version 1 and sends no import operation. |
| Different code hash | The native handshake fails before an authorization hook runs. |
| Malformed operation | The endpoint refuses the request before checking administrator rights. |
| Refused rights | The injected rights check refuses the write; the retained plan stays absent. |
| Lost reply | The endpoint commits a plan; the test driver discards its reply and invalidates the connection. |
| Fresh readback | A new channel reads progress without another write; the retained plan remains intact. |
| Explicit repeat | Another explicitly requested operation returns a bound result and preserves the same plan. |
| Crossed result | A result for plan preparation cannot validate a retention request. |

Preparing a relay plan does not advance the public import phase.
The experiment therefore reads the actual retained plan as well as the public progress.
It does not infer a committed plan from unchanged progress alone.

## Run

Run from the repository root in an ordinary Mac GUI session:

```sh
python3 scripts/run-macos-portable-import-xpc-experiment.py --evidence /tmp/remozio-import-wire.json
```

Choose unused output paths. The runner retains a test log beside the evidence.
It holds the existing native validation lock and retires its owned process tree on interruption or timeout.
A skipped test or missing evidence fails the runner.
The fixture contains no real authorization form, provider credential or phone identity.

## Evidence and limits

The [retained result](evidence/2026-10-21-portable-import-xpc.json) passed on Apple Silicon with macOS 27.0.1.
The deployment target was macOS 26.0. This does not qualify the macOS 26 runtime.
The focused channel, endpoint and native suites passed nine tests with no failures or skips.
The standalone runner then passed the same native test and retained sanitized evidence.

Administrator authorization uses an injected hook and a zero-filled placeholder form.
This does not test Authorization Services, Root UID admission, Developer ID installation policy or installed service registration.
The production Mach service driver and native administrator prompt remain interactive gates.
Same-process anonymous transport does not establish isolation between installed processes.
The injected lost reply establishes local recovery behavior, not a provider or network failure.
No installed Remozio service, physical phone or frozen recovery artifact was changed.

## Update exclusion during cancellation

The [activity result](evidence/2026-10-21-portable-import-xpc-activity.json) uses the same native transport with an independent update-lock descriptor.
An owned latch holds the setup owner's machine-open operation after authorization.
The client then cancels its request and invalidates the connection.
The test waits for the server's actual invalidation handler before checking the update lock again.

| State | Update admission |
| --- | --- |
| Authenticated idle connection | Allowed |
| Admitted setup operation held by the fixture | Refused as busy |
| Client cancelled and server invalidation observed, with owned work still held | Refused as busy |
| Owned work released and account owner settled | Allowed |

The activity check passed on Apple Silicon with macOS 27.0.1.
The [wire regression](evidence/2026-10-21-portable-import-xpc-followup.json) also passed after the listener fixture changed.
Both runs used the same native test source hash.

To run the activity mode, choose another unused evidence path:

```sh
python3 scripts/run-macos-portable-import-xpc-experiment.py --activity --evidence /tmp/remozio-import-activity.json
```

The latch holds disposable ordinary-user work. It does not test an installed updater or a privileged Root process.
Cancellation does not determine whether an already admitted write commits.
The test reads retained storage after settlement without assuming an outcome from cancellation.
This control does not isolate the final reply-callback boundary.
The endpoint's reply-boundary checks remain separate from this native backend-settlement result.


Native reply delivery can precede release of the handshake activity reference.
The fixture now waits up to five seconds for that reference to settle before it holds the next operation.
The [activity repeat](evidence/2026-10-21-portable-import-xpc-idle-settlement.json) passed with this bounded initial observation on macOS 27.0.1.
It does not relax either exclusion check while owned work remains active.
This repeat has a later test source hash than the original paired wire and activity records above.


## Native reply completion

The [reply completion result](evidence/2026-10-21-portable-import-xpc-reply-delivery-boundary.json) qualifies the callback boundary with an owned native wrapper.
It delegates invocation and work to the production endpoint. It adds no production authorization hook.
The wrapper holds the endpoint's reply callback after the plan commits and its bound result exists.
The normal variant sends the actual native reply first, then holds the callback before returning to the endpoint.
The client confirms that result while an independent update descriptor still reports busy.
The cancelled variant holds before delivery and observes native peer invalidation while the reply remains held.

| Observed state | Update admission |
| --- | --- |
| Authenticated idle connection | Allowed |
| Plan committed and endpoint reply held | Refused |
| Client confirmed the native reply, with the server callback still held | Refused |
| Cancelled peer invalidation handler entered, with the callback still held | Refused |
| Callback returned and owner settled | Allowed |

Both variants passed on Apple Silicon with macOS 27.0.1. Ten existing native and endpoint regression cases also passed without skips.
The [initial pre-delivery hold](evidence/2026-10-21-portable-import-xpc-reply-boundary.json) remains intact with its original test source hash.
The new callback wrapper runs only in the test listener. Production endpoint, peer policy and rights checks are unchanged.
The invalidation entry marker precedes endpoint closure because that closure must wait for the held endpoint lock.
The older settlement test still waits for its original post-close marker.

Run this mode with unused output paths:

```sh
python3 scripts/run-macos-portable-import-xpc-experiment.py --reply-boundary --evidence /tmp/remozio-import-reply.json
```

The runner rejects mixed modes and requires both normal and cancelled evidence.
It retains the test log, test source hash and the exact host/runtime qualification.
This remains a same-process, ordinary-user fixture with synthetic credentials and a placeholder authorization form.
It does not qualify installed Root accounts, Developer ID policy, a real administrator prompt or the macOS 26 runtime.
No provider request, service installation, physical phone test or product update was performed.
