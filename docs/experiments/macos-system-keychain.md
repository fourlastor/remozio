# System Keychain credential experiment

This probe evaluates a possible alternative to persistent plaintext provider files.
The candidate is the file-based System Keychain. It is not the user login Keychain.
Apple documents that a LaunchDaemon cannot use the data-protection Keychain.

Source: [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
The SDK deprecation warnings for the legacy selector and ACL APIs are expected.
They remain an engineering cost if this custody option qualifies.

## Current evidence

The probe compiles on this Mac. Thirteen fake-backend tests pass.
The default `--plan` invocation makes no Keychain calls.
No native item was created, read or deleted during preparation.
No service was installed. No credential, signed reader or service account was provisioned.

These checks do not prove that System Keychain access works for the transport account.
They do not establish code isolation, lock behavior, pre-login availability or update continuity.
The probe has not selected a production custody policy.

## Probe boundary

The item class is a generic password. The service is fixed to `dev.remozio.experiment.system-keychain.v1`.
The account is one canonical UUID. No operation searches other namespaces or keychains.
Creation uses 32 random bytes and an explicit trusted reader. Duplicate creation fails without replacement.
The probe disables Keychain authentication UI. It does not unlock a keychain or change its search list.
Creation and deletion require real and effective Root identity. Reading runs under the actual caller identity.
Read success requires the expected SHA-256 digest. Reports contain no secret bytes or raw error descriptions.

A native failure may occur before or after contacting Keychain.
`keychainOperationRequested` records the requested mode. It is not proof that a mutation occurred.
A timeout or lost creation report requires inspection of that exact experiment item before any retry.

## Supervised test sequence

Do not run native modes during unattended implementation.
Prepare protected, signed fixture binaries and a dedicated disposable account first.
Obtain local administrator approval before creating an item or installing a fixture job.
Use a bounded process supervisor for each native call. Authentication UI stays disabled.

1. Generate a new experiment UUID and record only that UUID and the signed fixture identities.
2. Create one item with the approved reader as the sole explicit trusted application.
3. Record the returned digest. Preserve duplicate-item errors; do not adopt an existing item.
4. Read under the disposable service account from an installed LaunchDaemon.
5. Repeat with the screen locked and after logout. Record the actual UID and numeric status.
6. Restart the fixture process and repeat. This proves process restart only.
7. Reboot and run before any GUI login. Distinguish this result from a post-login read.
8. Read from separately signed unauthorized code under the same account. It must fail without UI.
9. Read from the approved binary under an interactive account. It must fail without UI.
10. Replace the reader through the protected update fixture with the same intended signing requirement.
11. Repeat the service read. Test a changed signing identity separately; it must fail without UI.
12. Delete only the selected probe item. Confirm it is missing and remove only the disposable fixture resources.

No single successful read proves the entire matrix.
Capture timestamps, OS version, code requirements, UID, session state and numeric status separately.
The existing service fixture still needs a bounded adapter for this probe before the matrix is runnable.

## Native command contract

The following are argument shapes, not commands to execute now:

- `SystemKeychainProbe --create UUID --reader /protected/signed/reader`
- `SystemKeychainProbe --read UUID --sha256 EXPECTED_DIGEST`
- `SystemKeychainProbe --delete UUID`

`--plan` is safe and performs no native Keychain operation.
`swift test` uses fake backends and validates the operation boundaries only.

## Connector integration remains separate

Even if Keychain qualifies, cloudflared needs a supported way to receive the token at startup.
Its documented inputs include a token argument, an environment variable and a token-file path.
A Keychain-backed launcher must avoid exposing secrets through arguments, logs or persistent plaintext copies.
A private descriptor or pipe strategy needs its own compatibility and restart tests.
Do not claim that Keychain storage alone resolves connector delivery.

Source: [Cloudflare run parameters](https://developers.cloudflare.com/tunnel/reference/run-parameters/).

## Selection

Prefer Keychain if the service and isolation matrix passes without recurring prompts or lost background availability.
Retain protected file custody as the documented fallback. Record evidence before selecting it.
The separately drafted token-file publisher remains unpromoted while this question is open.
No production storage record, format declaration, XPC endpoint or app flow changed in this experiment.

## Connector input observation

A separate local preflight tested cloudflared 2026.10.1 with invalid synthetic input.
Both `/dev/fd/0` and `/dev/stdin` reached token parsing on two separate process launches.
A child sandbox denied network access and reads under the user home directory.
The input stayed out of arguments, environment variables and captured diagnostics.
No persistent token file or real credential was used.

This observation supports a future pipe-based launcher.
It does not establish a connected tunnel, valid-token delivery or the future bundled connector.
It also does not prove that any Keychain item can be read by a dedicated account.
The System Keychain service matrix must still pass before selecting production custody.
