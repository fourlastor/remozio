#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
    echo "This pairing-peer check requires Linux." >&2
    exit 1
fi

cd "$(dirname "$0")/.."
work_root="${REMOZIO_SWIFT_WORK_DIR:-$PWD/.build/linux-swift}"
case "$work_root" in
    /*) ;;
    *) echo "REMOZIO_SWIFT_WORK_DIR must be an absolute path." >&2; exit 1 ;;
esac
work_dir="$work_root/pairing-peer"

mkdir -p "$work_dir/module-cache"
export CLANG_MODULE_CACHE_PATH="$work_dir/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$work_dir/module-cache"
swift test --package-path experiments/linux-pairing-peer \
    --cache-path "$work_dir/cache" \
    --config-path "$work_dir/config" \
    --security-path "$work_dir/security" \
    --scratch-path "$work_dir/build" \
    --disable-keychain --disable-netrc --force-resolved-versions
