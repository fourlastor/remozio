#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
    echo "This protocol check requires Linux." >&2
    exit 1
fi

cd "$(dirname "$0")/.."
work_dir="${REMOZIO_SWIFT_WORK_DIR:-$PWD/.build/linux-swift-protocol}"
jobs="${REMOZIO_SWIFT_JOBS:-4}"
case "$work_dir" in
    /*) ;;
    *) echo "REMOZIO_SWIFT_WORK_DIR must be an absolute path." >&2; exit 1 ;;
esac
case "$jobs" in
    1|2|3|4) ;;
    *) echo "REMOZIO_SWIFT_JOBS must be between 1 and 4." >&2; exit 1 ;;
esac

mkdir -p "$work_dir/module-cache"
export CLANG_MODULE_CACHE_PATH="$work_dir/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$work_dir/module-cache"
swift --version
swift test --package-path protocol/swift \
    --cache-path "$work_dir/cache" \
    --config-path "$work_dir/config" \
    --security-path "$work_dir/security" \
    --scratch-path "$work_dir/build" \
    --disable-keychain --disable-netrc --force-resolved-versions \
    --jobs "$jobs"
