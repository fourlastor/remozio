#!/bin/sh
# Build the unsigned iOS app for the simulator; the Xcode build phase also builds the Kotlin framework.
set -eu
cd "$(dirname "$0")/../ios"
exec xcodebuild -project Remozio.xcodeproj -scheme Remozio -configuration Debug \
    -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "${REMOZIO_IOS_DERIVED_DATA:-../.build/ios-app}" CODE_SIGNING_ALLOWED=NO build
