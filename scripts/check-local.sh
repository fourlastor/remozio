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
set -- :protocol-kotlin:test :phone-core:test
if [ "$host" = Darwin ]; then
    # check.sh builds the native Mac peers required by this integration task.
    set -- "$@" :phone-core:approvalFlowTest
else
    ./scripts/check-linux-protocol.sh
    ./scripts/check-linux-host.sh
fi
./gradlew "$@" :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
