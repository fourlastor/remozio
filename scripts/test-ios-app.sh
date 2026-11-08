#!/bin/sh
# Run the native iOS unit tests (RemozioTests) on the first available iPhone simulator.
set -eu
cd "$(dirname "$0")/../ios"
device=$(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
rows = [d for runtime, found in sorted(devices.items(), reverse=True) if "iOS" in runtime
        for d in found if "iPhone" in d["name"]]
# A booted simulator first, so a local run reuses it.
rows.sort(key=lambda d: d["state"] != "Booted")
print(rows[0]["udid"] if rows else "")')
if [ -z "$device" ]; then
    echo "No available iPhone simulator." >&2
    exit 1
fi
exec xcodebuild -project Remozio.xcodeproj -scheme Remozio -configuration Debug \
    -destination "id=$device" -derivedDataPath "${REMOZIO_IOS_DERIVED_DATA:-../.build/ios-app}" \
    CODE_SIGNING_ALLOWED=NO test
