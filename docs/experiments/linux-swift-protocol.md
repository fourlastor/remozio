# Swift protocol tests on Linux

The existing `protocol/swift` package builds and passes all 119 XCTest tests on
Ubuntu 25.10 x86_64. This includes its shared canonical byte fixtures, invalid
inputs, signature tampering, scope and version substitution, and resource limits.
All 25 existing `protocol/vectors` files remain byte-identical to the recorded
base revision. [Recorded evidence](linux-swift-protocol-evidence.json) includes
the toolchain, dependency revisions, fixture hashes and test result.

The package imports Apple's platform CryptoKit on macOS and the official
[Swift Crypto](https://github.com/apple/swift-crypto) `Crypto` module on Linux.
The shared manifest permits Swift Crypto 4.5.1 through 5.0.1. The protocol
lockfile retains 4.5.1 and its Swift ASN.1 dependency. Existing Mac package
lockfiles retain 5.0.1. Both targets link `Crypto` only on Linux
through a platform condition. The package graph stays the same across hosts,
while macOS continues to use CryptoKit. Both protocol gates require the resolved
versions and reject incompatible dependency constraints.
The conditional imports preserve the existing calls and wire encoding. This
experiment introduces no Linux capture schema and ports no `macos/core` code.

## Reproduce

Provide Swift 6.2 or later on `PATH` with its runtime dependencies, then run:

```sh
./scripts/check-linux-protocol.sh
```

The runner requires Linux, uses four compilation jobs by default, and keeps
SwiftPM and Clang caches under the ignored `.build/linux-swift-protocol` directory.
Set `REMOZIO_SWIFT_JOBS` to 1–4 and `REMOZIO_SWIFT_WORK_DIR` to an absolute path
to change those settings. It uses the resolved dependency versions. The first
run needs network access to fetch the official dependencies. It adds a focused
Linux check; the repository's existing required Mac/Android checks still apply.

The `Linux Swift protocol` CI job runs this same gate on an Ubuntu 24.04 hosted
runner using the pinned Swift 6.2.4 archive and its verified SHA-256. This is a
protocol regression job, not a claim that installed Linux host services support
Ubuntu 24.04. The job is prepared; a remote CI result is not part of the local
Ubuntu 25.10 evidence below.

## Observed toolchain setup

This host initially had no Swift compiler. The run used the official Swift 6.2.4
Ubuntu 24.04 x86_64 tarball, following the
[Swift.org tarball instructions](https://www.swift.org/install/linux/tarball/).
GnuPG verified its detached signature against the Swift 6.x release key
`52BB7E3DE28A71BE22EC05FFEF80A866B47A981F`, retrieved from Swift.org. The archive
and extracted toolchain stayed in `/tmp/remozio-swift-toolchain`.

`swift --version` ran on Ubuntu 25.10, but SwiftPM initially could not load
`libxml2.so.2`: this host provides `libxml2.so.16`. Official Ubuntu noble-updates
`libxml2` and `libicu74` packages were downloaded using isolated APT metadata,
validated using Ubuntu's signed repository metadata and package hashes, and
extracted under `/tmp/remozio-swift-toolchain/runtime/root`. No installed package
or library symlink was changed. The successful gate used:

```sh
export PATH="/tmp/remozio-swift-toolchain/swift-6.2.4-RELEASE-ubuntu24.04/usr/bin:$PATH"
export LD_LIBRARY_PATH=/tmp/remozio-swift-toolchain/runtime/root/usr/lib/x86_64-linux-gnu
export REMOZIO_SWIFT_WORK_DIR=/tmp/remozio-linux-swift
GIT_CONFIG_GLOBAL=/dev/null ./scripts/check-linux-protocol.sh
```

The Git override bypassed this host's HTTPS-to-SSH GitHub rewrite when fetching
the public dependencies. It is specific to this setup. The observed success
establishes execution with these isolated compatibility libraries on this host;
it does not establish that the Ubuntu 24.04 toolchain runs unmodified on every
Ubuntu 25.10 installation.

## Limits

A Mac fixture passed all 119 protocol tests with the platform-stable manifest.
A forced build rejected an incompatible version constraint and kept the lockfile
unchanged. Restoring the constraint passed with the same lockfile. Full combined
Mac/Android validation remains a separate pre-push and CI gate. Protocol fixture
success does not prove Linux caller identity, TPM-backed TLS, protected
services, privileged dispatch, physical Android pairing or a complete Linux
product. Those require their own experiments and integration checks.
