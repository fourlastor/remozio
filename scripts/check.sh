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

# CI splits the Mac stages between two jobs. The app part builds the app and macos/core and runs everything that
# inspects either; the experiments part runs the rest. Local runs and other hosts run every stage.
mac_part=${REMOZIO_CHECK_MAC_PART:-all}
case "$mac_part" in
    all|app|experiments) ;;
    *) printf 'Unknown REMOZIO_CHECK_MAC_PART: %s\n' "$mac_part" >&2; exit 2 ;;
esac
mac_stage() {
    mac_stage_part=$1
    shift
    if [ "$mac_part" = all ] || [ "$mac_part" = "$mac_stage_part" ]; then
        run_stage "$@"
    fi
}

if [ "$(uname -s)" != Darwin ] || [ "$mac_part" != app ]; then
    run_stage 'Repository Python tests' python3 -m unittest discover -s tests -p 'test_*.py'
    run_stage 'PR watcher Python tests' python3 -m unittest discover -s .agents/skills/babysit-pr/scripts -p 'test_*.py'
fi
if [ "$(uname -s)" = Darwin ]; then
    mac_stage experiments 'Swift build: experiments/macos' swift build --package-path experiments/macos --triple arm64-apple-macosx26.0
    mac_stage experiments 'Swift build: experiments/key-custody' swift build --package-path experiments/key-custody --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
    mac_stage experiments 'Swift test: experiments/system-keychain' swift test --package-path experiments/system-keychain --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
    mac_stage experiments run-native-approval-relay-experiment python3 scripts/run-native-approval-relay-experiment.py
    mac_stage experiments check-enclave-timeout python3 scripts/check-enclave-timeout.py
    mac_stage experiments run-transport-file-tls-experiment python3 scripts/run-transport-file-tls-experiment.py
    mac_stage experiments check-macos-packaging python3 scripts/check-macos-packaging.py
    mac_stage experiments check-service-lifecycle python3 scripts/check-service-lifecycle.py
    mac_stage app check-macos-app python3 scripts/check-macos-app.py
    mac_stage experiments run-native-bootstrap-file-experiment python3 scripts/run-native-bootstrap-file-experiment.py
    mac_stage app run-macos-release-signing-experiment python3 scripts/run-macos-release-signing-experiment.py
    mac_stage experiments 'Swift build: experiments/release-dependencies' swift build --package-path experiments/release-dependencies --disable-keychain --disable-netrc
    mac_stage experiments 'Swift build: experiments/release-copy' swift build --package-path experiments/release-copy --disable-keychain --disable-netrc
    mac_stage experiments 'Swift test: experiments/release-attributes' swift test --package-path experiments/release-attributes --triple arm64-apple-macosx26.0
    mac_stage experiments 'Swift build: experiments/sparkle-probe' swift build --package-path experiments/sparkle-probe --disable-keychain --disable-netrc
    mac_stage experiments run-sparkle-feed-experiment python3 scripts/run-sparkle-feed-experiment.py
    mac_stage experiments 'Swift build: experiments/sparkle-boundary' swift build --package-path experiments/sparkle-boundary --disable-keychain --disable-netrc
    mac_stage experiments check-sparkle-boundary-guards python3 scripts/check-sparkle-boundary-guards.py
    mac_stage experiments run-release-activity-experiment python3 scripts/run-release-activity-experiment.py
    mac_stage experiments build-approval-flow python3 scripts/build-approval-flow.py
    mac_stage experiments run-macos-execution-experiment python3 scripts/run-macos-execution-experiment.py
    mac_stage experiments run-macos-self-code-experiment python3 scripts/run-macos-self-code-experiment.py
    mac_stage experiments run-macos-command-caller-experiment python3 scripts/run-macos-command-caller-experiment.py
    mac_stage experiments run-command-groups-experiment python3 scripts/run-command-groups-experiment.py
    mac_stage experiments run-production-child-experiment python3 scripts/run-production-child-experiment.py
    mac_stage experiments run-macos-frontend-composition python3 scripts/run-macos-frontend-composition.py
    mac_stage experiments run-macos-live-frontend python3 scripts/run-macos-live-frontend.py
    mac_stage experiments run-macos-command-fileport-experiment python3 scripts/run-macos-command-fileport-experiment.py
    mac_stage experiments run-macos-journal-experiment python3 scripts/run-macos-journal-experiment.py
    mac_stage experiments run-installation-inventory-experiment python3 scripts/run-installation-inventory-experiment.py
    mac_stage experiments 'Swift test: protocol/swift' swift test --package-path protocol/swift --triple arm64-apple-macosx26.0 --force-resolved-versions
    mac_stage experiments 'Swift test: host/shared-core' swift test --package-path host/shared-core --triple arm64-apple-macosx26.0 --force-resolved-versions --jobs 4
    # CI spends most of this stage in CPU-bound validation. Optimizing halves it; local runs keep faster rebuilds.
    # In CI the Mac core tests job runs the other classes in shards. This job built the app these classes inspect,
    # so none of them may skip here.
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        mac_stage app 'Swift test: macos/core app-dependent classes' python3 scripts/run-xctest-shards.py \
            --package-path macos/core --shards 1 --index 0 --app-dependent only --forbid-skips \
            -- --triple arm64-apple-macosx26.0 -Xswiftc -O
    else
        mac_stage app 'Swift test: macos/core' swift test --package-path macos/core --triple arm64-apple-macosx26.0
    fi
    mac_stage experiments 'Swift test: macos/ui-adapters' swift test --package-path macos/ui-adapters --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
    mac_stage experiments run-macos-job-control-experiment python3 scripts/run-macos-job-control-experiment.py
    mac_stage experiments run-macos-nested-shell-experiment python3 scripts/run-macos-nested-shell-experiment.py
    mac_stage app check-command-transfer python3 scripts/check-command-transfer.py
fi
run_stage 'Working-tree whitespace' git diff --check
