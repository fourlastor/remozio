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
