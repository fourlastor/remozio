#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s .agents/skills/babysit-pr/scripts -p 'test_*.py'
if [ "$(uname -s)" = Darwin ]; then
    swift build --package-path experiments/macos --triple arm64-apple-macosx26.0
    swift build --package-path experiments/key-custody --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
    python3 scripts/run-native-approval-relay-experiment.py
    python3 scripts/check-enclave-timeout.py
    python3 scripts/run-transport-file-tls-experiment.py
    python3 scripts/check-macos-packaging.py
    python3 scripts/check-service-lifecycle.py
    python3 scripts/check-macos-app.py
    python3 scripts/run-macos-release-signing-experiment.py
    swift build --package-path experiments/release-dependencies --disable-keychain --disable-netrc
    swift build --package-path experiments/release-copy --disable-keychain --disable-netrc
    swift test --package-path experiments/release-attributes --triple arm64-apple-macosx26.0
    swift build --package-path experiments/sparkle-probe --disable-keychain --disable-netrc
    python3 scripts/run-sparkle-feed-experiment.py
    swift build --package-path experiments/sparkle-boundary --disable-keychain --disable-netrc
    python3 scripts/check-sparkle-boundary-guards.py
    python3 scripts/build-approval-flow.py
    python3 scripts/run-macos-execution-experiment.py
    python3 scripts/run-macos-self-code-experiment.py
    python3 scripts/run-macos-command-caller-experiment.py
    python3 scripts/run-command-groups-experiment.py
    python3 scripts/run-macos-frontend-composition.py
    python3 scripts/run-macos-live-frontend.py
    python3 scripts/run-macos-command-fileport-experiment.py
    python3 scripts/run-macos-journal-experiment.py
    python3 scripts/run-installation-inventory-experiment.py
    swift test --package-path protocol/swift --triple arm64-apple-macosx26.0
    swift test --package-path macos/core --triple arm64-apple-macosx26.0
    python3 scripts/run-macos-job-control-experiment.py
    python3 scripts/run-macos-nested-shell-experiment.py
    python3 scripts/check-command-transfer.py
fi
git diff --check
