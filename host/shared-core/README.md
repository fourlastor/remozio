# Shared host core

`RemozioHostCore` contains the shared decision verifier and its retained-request,
trust and clock value types. The Mac authority uses this implementation through
the existing `RemozioCore` public names.

Verification checks the exact request, current enrollment, capabilities, permitted
action, signing key and monotonic deadline. A `VerifiedDecision` is verification
evidence only. The authority must still revalidate and consume the decision under
its journal lock before considering dispatch.

This package contains no persistence, operating-system clock, caller monitor,
TPM integration, service installation or command execution. It introduces no
Linux capture schema or changes to existing protocol bytes.

Run the existing verifier tests with Swift 6.2 or later:

```sh
swift test --package-path host/shared-core --force-resolved-versions
```

The tests use disposable software keys through CryptoKit on macOS and Swift
Crypto on Linux. Their results do not establish hardware custody or a complete
host approval flow.
