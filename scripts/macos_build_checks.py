"""Shared checks for local, ad-hoc signed Mac build artifacts."""
import plistlib
import re
import subprocess


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
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


