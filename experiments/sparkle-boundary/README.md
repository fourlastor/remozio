# Sparkle replacement experiment

This experiment measures Sparkle 2.10.0 with disposable applications. It does not enable updates in Remozio.

Build the fixture and run its refusal checks:

```sh
swift build --package-path experiments/sparkle-boundary --disable-keychain --disable-netrc
python3 scripts/check-sparkle-boundary-guards.py
```

Run the replacement controls from an ordinary account in a macOS GUI session:

```sh
python3 scripts/run-sparkle-boundary-experiment.py
```

The runner refuses Root execution and Python optimization. It creates an owned temporary directory, unique application identities, and fresh in-memory Ed25519 keys. It signs disposable application copies with ad-hoc signatures. It serves only a signed feed and archive through loopback HTTP. Production delivery must use HTTPS.

Sparkle can create temporary user jobs during these controls. The runner checks that each exact job is absent before starting. It removes only those fixture jobs. It checks the system domain for the same identities and refuses unexpected privileged jobs. It removes the fixture cache and preference domain. It never installs a persistent Remozio service or uses a Keychain certificate.

## Controls

| Control | Action | Required observation |
|---|---|---|
| Hold and release | Keep the host and synthetic worker alive. Hold the callback for one second. Stop the worker, then release the callback. | Original bundle bytes remain unchanged during the hold. Replacement completes after release. |
| Host exit | Hold the callback. Exit only the fixture host while its worker remains busy. | Record whether Sparkle replaces the bundle despite the held callback. |
| Separate staging | Repeat host exit with a separate active copy. | Staging replacement completes. The active copy stays unchanged while the worker remains busy. |

Every successful replacement must match the signed candidate's file and link bytes. A strict code-signature check must also pass. The server must observe exactly one feed request and one archive request per control.

The host-exit result demonstrates an unsuitable integration strategy. It is not an activation safety pass. Staging isolation is a possible delivery boundary; it is not protected installation.

## Routine validation

The repository gate builds this fixture and runs five native refusal tests. Six Python tests check the runner's ownership, alias, hard-link, and job restrictions. The gate does not launch the replacement controls. These require a GUI session and create temporary user jobs.

Native refusal tests never start an updater. They exercise invalid roots, fixture configuration, URLs, archive aliases, hard links, size limits, and disposable signing. They do not prove Root denial through an actual Root invocation.

## Evidence limits

These controls use a synthetic busy worker. They do not prove production admission control, draining, service continuity, or recovery. They do not prove Developer ID trust, notarization, protected placement, generation commits, or compatibility with installed services.

The one-second hold establishes a bounded observation. It does not guarantee that a held callback blocks every replacement path. The host-exit control demonstrates why that claim would be incorrect.

See [the recorded local result](../../docs/experiments/sparkle-replacement-boundary.md). The separate [release identity inspection](../../docs/macos-release-manifest.md) remains an independent requirement.
