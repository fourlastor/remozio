"""Shared checks for local, ad-hoc signed Mac build artifacts."""
import os
import plistlib
import re
import subprocess
import sys
import time


def run(*args, check=True):
    started = time.monotonic()
    result = subprocess.run(args, text=True, capture_output=True)
    tool = os.path.basename(os.fspath(args[0]))
    if tool in {"swift", "xcodebuild"}:
        operation = "path query" if "--show-bin-path" in args else "build" if "build" in args else "command"
        print(f"Command timing: {tool} {operation}: {time.monotonic() - started:.3f}s (exit {result.returncode})",
              file=sys.stderr, flush=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr.strip()}")
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_executable(path, identity, *, expected_entitlements=None):
    require(run('lipo', '-archs', str(path)).stdout.strip() == 'arm64', f'{path.name}: unexpected architecture')
    load_commands = run('xcrun', 'vtool', '-show-build', str(path)).stdout
    require(re.search(r'\bminos\s+26\.0(?:\.0)?\s', load_commands), f'{path.name}: deployment target is not macOS 26')
    run('codesign', '--verify', '--strict', '-R', f'=identifier "{identity}"', str(path))
    details = run('codesign', '--display', '--verbose=4', str(path)).stderr
    require('runtime)' in details, f'{path.name}: hardened runtime is absent')
    entitlements = run('codesign', '--display', '--entitlements', '-', '--xml', str(path)).stdout
    values = plistlib.loads(entitlements.encode()) if entitlements.strip() else {}
    if expected_entitlements is None:
        require(values in ({}, {'com.apple.application-identifier': identity}), f'{path.name}: unexpected entitlements')
    else:
        require(values == expected_entitlements and all(type(values[k]) is type(v) for k, v in expected_entitlements.items()),
                f'{path.name}: entitlements differ from the exact expected set')


