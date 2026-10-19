# Shared host core

`RemozioHostCore` contains the shared decision verifier, its retained-request,
trust and clock value types, and a sleep-inclusive clock sampler. The Mac authority
uses this implementation through the existing `RemozioCore` public names.

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

This package contains no persistence, caller monitor, TPM integration, service
installation or command execution. It introduces no Linux capture schema or
changes to existing protocol bytes. Clock tests cover integer conversion, failure
handling, live kernel samples and rejection of a replaced authority epoch. They
do not establish physical suspend/resume, reboot recovery or a protected service's
time-namespace policy.

Run the verifier and clock tests with Swift 6.2 or later:

```sh
swift test --package-path host/shared-core --force-resolved-versions
```

The tests use disposable software keys through CryptoKit on macOS and Swift
Crypto on Linux. Their results do not establish hardware custody or a complete
host approval flow.
