# Sparkle replacement boundary

Local controls on 11 October 2026 confirmed that holding Sparkle's relaunch callback does not protect other busy components after the host exits.

| Control | Result |
|---|---|
| Hold and release | The original bundle remained unchanged during the hold. Replacement completed after the synthetic worker stopped and the callback was released. |
| Host exit while busy | Sparkle replaced the bundle while the synthetic worker remained alive. The callback was still held when the host exited. |
| Separate staging copy | Sparkle replaced the staging bundle. The independent active bundle remained unchanged while the worker stayed alive. |

The runner checked replacement bytes against the signed candidate. All strict signature checks passed. Each control requested only its loopback feed and archive. All exact fixture jobs and fixture caches were removed.

Environment: Apple Silicon, macOS 27.0.1, SDK 27, package deployment minimum macOS 26, and Sparkle 2.10.0. This is not runtime validation on macOS 26.

The fixtures used ad-hoc application signatures and disposable Ed25519 keys. No production key, authorization prompt, persistent service installation, or Remozio bundle replacement was involved.

## Integration constraint

The approved design requires every affected component to be idle before replacing its active code. A held callback cannot enforce that requirement. The stock installer independently observes host termination.

Sparkle delivery into a separate staging copy can preserve the active bundle during download and staging replacement. Activation still needs its own protected controller, identity checks, generation checks, admission boundary, health checks, and durable commit. This experiment does not select or prove that controller.

Automatic checks and downloads remain part of the design. This result does not authorize killing active work, forcing a drain, or changing update prompts.

## Upstream evidence

The [delegate contract](https://sparkle-project.org/documentation/api-reference/Protocols/SPUUpdaterDelegate.html) states that an install-on-quit update attempts installation when its host terminates. The [pinned installer](https://github.com/sparkle-project/Sparkle/blob/2.10.0/Autoupdate/AppInstaller.m) handles that termination independently.

The [pinned launcher](https://github.com/sparkle-project/Sparkle/blob/2.10.0/InstallerLauncher/SUInstallerLauncher.m) selects the user domain for writable ordinary-account application targets. The experiment verifies that its exact fixture identities do not enter the system domain.

## Reproduce

Follow the [experiment instructions](../../experiments/sparkle-boundary/README.md). The [recorded JSON](sparkle-replacement-boundary.json) includes source hashes, environment details, and control outcomes. Keep the measured JSON records with each later run. A build or refusal-test pass alone does not establish replacement behavior.
