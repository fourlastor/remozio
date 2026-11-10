#!/bin/sh
# Run the automated local gate for this host; CI also validates the other host.
set -eu
cd "$(dirname "$0")/.."

host=$(uname -s)
case "$host" in
    Linux|Darwin) ;;
    *) echo "Local checks require Linux or macOS (found $host)." >&2; exit 1 ;;
esac

./scripts/check.sh
set -- :protocol-kotlin:jvmTest :phone-pairing:jvmTest :phone-enrollment:jvmTest :phone-core:test :phone-ui:jvmTest :dev-invitation:test
if [ "$host" = Darwin ]; then
    # check.sh builds the native Mac peers required by this integration task.
    set -- "$@" :phone-core:approvalFlowTest :protocol-kotlin:iosSimulatorArm64Test :phone-pairing:iosSimulatorArm64Test :phone-enrollment:iosSimulatorArm64Test :phone-ui:iosSimulatorArm64Test
else
    ./scripts/check-linux-protocol.sh
    ./scripts/check-linux-host.sh
    ./scripts/check-linux-pairing-peer.sh
    # check-linux-pairing-peer.sh built this software-key pairing tool for the JVM loopback test.
    REMOZIO_LINUX_PAIR_TOOL="${REMOZIO_SWIFT_WORK_DIR:-$PWD/.build/linux-swift}/pairing-peer/build/debug/remozio-linux-pair"
    export REMOZIO_LINUX_PAIR_TOOL
    set -- "$@" :phone-core:linuxPairToolTest
fi
./gradlew "$@" :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
if [ "$host" = Darwin ]; then
    ./scripts/build-ios-app.sh
    ./scripts/test-ios-app.sh
fi
