# Signed arm64 Sparkle fixtures

Disposable Developer ID fixtures reproduce the replacement behavior recorded by [the original experiment](sparkle-replacement-boundary.md).

The fixture thins five SDK executables: the framework library, Autoupdate, Updater, Downloader, and Installer. The host executable must already contain only arm64 code. Each signed component passes an explicit Apple Developer ID requirement with the configured Team and exact identifier.

The signer checks hardened runtime flags and exact entitlement dictionaries. It signs nested components individually and verifies the enclosing framework and application. It never exports a private key or signs the original built SDK.

## Measured replacement controls

| Control | Result |
|---|---|
| Hold and release | The bundle stayed unchanged during the hold. Replacement completed after idle and callback release. |
| Host exit while busy | Replacement completed while the synthetic worker stayed alive. |
| Separate staging | Staging replacement completed while the independent active bundle stayed unchanged. |

All replacement bytes matched the signed candidate. All exact fixture jobs and fixture caches were removed. The original SDK remained unchanged.

## Entitlement controls

The no-argument helper path returns 1 before creating an installer. Four separately signed copies measured the effect of the two identity keys.

| Entitlements added | Observed exit | Argument guard reached |
|---|---|---|
| None | 1 | Yes |
| Team identifier only | SIGKILL | No |
| Application identifier only | 1 | Yes |
| Both keys | SIGKILL | No |

All four signatures passed strict static verification. No provisioning profile was supplied. The exact kernel reason for SIGKILL remains unverified. These observations do not prove that a provisioned application cannot use the Team entitlement.

The working fixture retains the helper's application identifier. It derives Team trust from the real signature and adds no Team entitlement. Sparkle's XPC admission checks remain enabled.

## Environment and limits

Measured on Apple Silicon macOS 27.0.1, SDK 27, Sparkle 2.10.0, and a macOS 26 deployment minimum. This is not macOS 26 runtime validation. The fixtures use disposable Ed25519 feed keys and an explicitly selected Developer ID certificate.

No secure timestamp, notarization, protected installation, real service replacement, durable generation commit, or production activation was tested. The worker is synthetic. Remozio's current release manifest still rejects SDK dependencies.

Run the [opt-in controls](../../experiments/sparkle-boundary/README.md#signed-arm64-controls) to reproduce these results. The [recorded JSON](sparkle-signed-arm64.json) contains the source hashes and control results. Static signature verification alone does not prove executable launch or update activation.
