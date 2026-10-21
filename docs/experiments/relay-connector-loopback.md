# Owned relay process and loopback readiness

The [retained result](evidence/2026-10-21-relay-connector-owned-loopback.json) combines the production process primitive, supervisor and HTTP readiness client.
A disposable C worker replaces Cloudflare. It binds only an ephemeral IPv4 loopback port and uses synthetic credentials.
It retains the normal activity, token and configuration descriptor checks. It has a ten-second lifetime limit.
No installed service, actual credential, provider request or physical phone participates.

| Fixture behavior | Observed result |
| --- | --- |
| Two disconnected responses, then connected | Supervisor recovers without replacing the child. |
| Connected response with another connector ID | The real client reports an invalid response; supervisor remains unavailable. |
| Scope invalidation | Child exits and settles; no replacement starts. |
| Accepted HTTP request with a held response | A private child marker proves the real request reached the server. |
| Two concurrent close calls | Both join the child and readiness work. |
| Child runs before shutdown | Independent update admission reports busy. |
| Shutdown settles | Independent update admission succeeds. |

The native process primitive checks inherited descriptors, controls the environment and reaps only its owned child.
The HTTP client uses its fixed `/ready` path without a proxy, stored credentials or cookies.
The fixture's connected result tests the wire contract. It does not prove a Cloudflare edge connection or approval delivery.
The wrong-identity control checks the specific invalid-response error, rather than accepting an arbitrary network failure.
The lock observations cover the active child and completed shutdown. They do not isolate a late probe after child exit.
The installed transport also retains a baseline activity lock. Its complete service lifetime remains an interactive gate.

Run on Apple Silicon as an ordinary user with macOS 26 or later:

```sh
python3 scripts/run-macos-relay-loopback-experiment.py --evidence /tmp/remozio-relay-loopback.json
```

Choose unused evidence and log paths. The runner holds the native validation lock and retires only its owned test process tree.
It refuses a skipped result, missing evidence, source mutation or a claim of real provider connectivity.
The report retains source and log hashes. Raw logs for the committed report remain in the private checkpoint.

The combined experiment and affected regression suites passed on macOS 27.0.1 with a macOS 26 deployment target.
This does not qualify the macOS 26 runtime.
The installed native factory still requires its dedicated transport identity, protected paths and Developer ID policy.
Those checks were preserved. They require the supervised installation session and remain unproven here.
No complete local gate or push covers this private experiment yet.
