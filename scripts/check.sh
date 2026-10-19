#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

# Keep child output on its original streams; timing never prints command arguments.
run_stage() {
    check_stage_name=$1
    shift
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '%s\n' "::group::$check_stage_name" >&2
    else
        printf 'Stage started: %s\n' "$check_stage_name" >&2
    fi
    check_stage_started=$(date +%s)
    check_stage_status=0
    "$@" || check_stage_status=$?
    check_stage_elapsed=$(($(date +%s) - check_stage_started))
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '%s\n' '::endgroup::' >&2
    fi
    printf 'Stage timing: %s: %ss (exit %s)\n' "$check_stage_name" "$check_stage_elapsed" "$check_stage_status" >&2
    return "$check_stage_status"
}

run_stage 'Repository Python tests' python3 -m unittest discover -s tests -p 'test_*.py'
run_stage 'PR watcher Python tests' python3 -m unittest discover -s .agents/skills/babysit-pr/scripts -p 'test_*.py'
if [ "$(uname -s)" = Darwin ]; then
    run_stage 'Swift build: experiments/macos' swift build --package-path experiments/macos --triple arm64-apple-macosx26.0
    run_stage 'Swift build: experiments/key-custody' swift build --package-path experiments/key-custody --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
    run_stage 'Swift test: experiments/system-keychain' swift test --package-path experiments/system-keychain --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
    run_stage run-native-approval-relay-experiment python3 scripts/run-native-approval-relay-experiment.py
    run_stage check-enclave-timeout python3 scripts/check-enclave-timeout.py
    run_stage run-transport-file-tls-experiment python3 scripts/run-transport-file-tls-experiment.py
    run_stage check-macos-packaging python3 scripts/check-macos-packaging.py
    run_stage check-service-lifecycle python3 scripts/check-service-lifecycle.py
    run_stage check-macos-app python3 scripts/check-macos-app.py
    run_stage run-native-bootstrap-file-experiment python3 scripts/run-native-bootstrap-file-experiment.py
    run_stage run-macos-release-signing-experiment python3 scripts/run-macos-release-signing-experiment.py
    run_stage 'Swift build: experiments/release-dependencies' swift build --package-path experiments/release-dependencies --disable-keychain --disable-netrc
    run_stage 'Swift build: experiments/release-copy' swift build --package-path experiments/release-copy --disable-keychain --disable-netrc
    run_stage 'Swift test: experiments/release-attributes' swift test --package-path experiments/release-attributes --triple arm64-apple-macosx26.0
    run_stage 'Swift build: experiments/sparkle-probe' swift build --package-path experiments/sparkle-probe --disable-keychain --disable-netrc
    run_stage run-sparkle-feed-experiment python3 scripts/run-sparkle-feed-experiment.py
    run_stage 'Swift build: experiments/sparkle-boundary' swift build --package-path experiments/sparkle-boundary --disable-keychain --disable-netrc
    run_stage check-sparkle-boundary-guards python3 scripts/check-sparkle-boundary-guards.py
    run_stage run-release-activity-experiment python3 scripts/run-release-activity-experiment.py
    run_stage build-approval-flow python3 scripts/build-approval-flow.py
    run_stage run-macos-execution-experiment python3 scripts/run-macos-execution-experiment.py
    run_stage run-macos-self-code-experiment python3 scripts/run-macos-self-code-experiment.py
    run_stage run-macos-command-caller-experiment python3 scripts/run-macos-command-caller-experiment.py
    run_stage run-command-groups-experiment python3 scripts/run-command-groups-experiment.py
    run_stage run-production-child-experiment python3 scripts/run-production-child-experiment.py
    run_stage run-macos-frontend-composition python3 scripts/run-macos-frontend-composition.py
    run_stage run-macos-live-frontend python3 scripts/run-macos-live-frontend.py
    run_stage run-macos-command-fileport-experiment python3 scripts/run-macos-command-fileport-experiment.py
    run_stage run-macos-journal-experiment python3 scripts/run-macos-journal-experiment.py
    run_stage run-installation-inventory-experiment python3 scripts/run-installation-inventory-experiment.py
    run_stage 'Swift test: protocol/swift' swift test --package-path protocol/swift --triple arm64-apple-macosx26.0 --force-resolved-versions
    run_stage 'Swift test: host/shared-core' swift test --package-path host/shared-core --triple arm64-apple-macosx26.0 --force-resolved-versions --jobs 4
    run_stage 'Swift test: macos/core' swift test --package-path macos/core --triple arm64-apple-macosx26.0
    run_stage run-macos-job-control-experiment python3 scripts/run-macos-job-control-experiment.py
    run_stage run-macos-nested-shell-experiment python3 scripts/run-macos-nested-shell-experiment.py
    run_stage check-command-transfer python3 scripts/check-command-transfer.py
fi
run_stage 'Working-tree whitespace' git diff --check
