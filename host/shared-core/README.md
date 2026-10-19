# Shared host core

`RemozioHostCore` contains the shared decision verifier, its retained-request,
trust and clock value types, a sleep-inclusive clock sampler, and the SQLite audit
journal tables. The Mac authority uses the same implementations through the
existing `RemozioCore` public names.

Verification checks the exact request, current enrollment, capabilities, permitted
action, signing key and monotonic deadline. A `VerifiedDecision` is verification
evidence only. The authority must still revalidate and consume the decision under
its journal lock before considering dispatch.

`SleepInclusiveClock` reads `mach_continuous_time` on macOS and `CLOCK_BOOTTIME`
on Linux. It floors elapsed time to integer milliseconds and throws on unavailable
clock reads, invalid samples or overflow; it never substitutes another clock.
The Mac `AuthorityClock` wrapper retains its existing epoch ownership.
`LinuxAuthorityClock` creates a fresh authority epoch on each construction and
preserves it across copies. Share one instance across an authority's request
owners, and replace it after restart. Its epoch is not a boot identifier and must
not be restored from persisted requests.

The audit tables retain their schema, bounded reads, writer ownership and explicit
transaction requirements. They borrow an existing SQLite connection. Its owner
remains responsible for protected storage, connection lifetime, serialized access,
durability configuration, recovery and committing audit and consumption together.
An audit write or writer handle grants no execution authority.

This package contains no decision-consumption ledger, protected database owner,
caller monitor, TPM integration, service installation or command execution. It
introduces no Linux capture schema and changes no protocol bytes or production
authority policy.

Run the verifier, clock and audit-table tests with Swift 6.2 or later. Linux also
needs SQLite development headers and library (`libsqlite3-dev` on Ubuntu),
discoverable through `pkg-config`. macOS uses the SDK's SQLite module.

```sh
swift test --package-path host/shared-core --force-resolved-versions
```

The tests use disposable software keys through CryptoKit on macOS and Swift
Crypto on Linux, and temporary SQLite databases. They cover table transaction,
rollback, reopen and bounded-read behavior, not a protected Linux installation or
complete host approval flow. Mac tests retain signing integration with the shared
table types. Clock tests cover integer conversion, failure handling, live kernel
samples and rejection of a replaced authority epoch. They do not establish
physical suspend/resume, reboot recovery or a protected service's time-namespace
policy.
