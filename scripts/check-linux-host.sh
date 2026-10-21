#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ]; then
    echo "This shared-host check requires Linux." >&2
    exit 1
fi

cd "$(dirname "$0")/.."
work_root="${REMOZIO_SWIFT_WORK_DIR:-$PWD/.build/linux-swift}"
jobs="${REMOZIO_SWIFT_JOBS:-4}"
case "$work_root" in
    /*) ;;
    *) echo "REMOZIO_SWIFT_WORK_DIR must be an absolute path." >&2; exit 1 ;;
esac
case "$jobs" in
    1|2|3|4) ;;
    *) echo "REMOZIO_SWIFT_JOBS must be between 1 and 4." >&2; exit 1 ;;
esac
work_dir="$work_root/host-core"

mkdir -p "$work_dir/module-cache"
export CLANG_MODULE_CACHE_PATH="$work_dir/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$work_dir/module-cache"
swift --version
swift test --package-path host/shared-core \
    --cache-path "$work_dir/cache" \
    --config-path "$work_dir/config" \
    --security-path "$work_dir/security" \
    --scratch-path "$work_dir/build" \
    --disable-keychain --disable-netrc --force-resolved-versions \
    --jobs "$jobs"

python3 scripts/run-linux-approval-command-experiment.py \
    --work-dir "$work_root/approval-command"

python3 scripts/run-linux-storage-lease-experiment.py
