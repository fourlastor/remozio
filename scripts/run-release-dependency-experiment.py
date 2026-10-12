#!/usr/bin/env python3
"""Inspect owned Developer ID SDK fixtures without starting an updater or installer."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import uuid

from sparkle_sdk_fixture import SDKFixtureSigner, SigningConfig

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent / 'experiments/release-dependencies'


def load_boundary():
    spec = importlib.util.spec_from_file_location('release_dependency_boundary', HERE / 'run-sparkle-boundary-experiment.py')
    boundary = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = boundary
    spec.loader.exec_module(boundary)
    return boundary


def inspect(probe, app, team, identity):
    return subprocess.run([str(probe), 'inspect', str(app), team, identity], capture_output=True, timeout=10)


def reject(probe, app, team, identity, control, expected):
    result = inspect(probe, app, team, identity)
    failure = result.stderr.decode().strip()
    if result.returncode != 65 or not failure.startswith('fixture inspection failed: '):
        raise RuntimeError(f'{control}: the native reader did not reject the fixture')
    if expected not in failure:
        raise RuntimeError(f'{control}: the rejection did not match the expected validation stage')
    print(json.dumps({'control': control, 'rejected': True, 'failure': failure}), flush=True)


def resign(boundary, config, app, identity, declaration):
    boundary.command('/usr/bin/codesign', '--force', '--sign', config.identity, '--options', 'runtime',
                     '--timestamp=none', '--identifier', identity, '--entitlements', declaration, app)
    boundary.command('/usr/bin/codesign', '--verify', '--deep', '--strict', app)


def controls(boundary, config, products, probe):
    with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
        root = Path(temporary).resolve()
        identity = boundary.PREFIX + uuid.uuid4().hex
        app = SDKFixtureSigner(boundary, config).bundle(root, 'Host', products, identity, 1,
                                                       base64.b64encode(bytes(32)).decode(), 1)
        declaration = root / 'empty.plist'
        declaration.write_bytes(plistlib.dumps({}))
        boundary.command(probe, 'prepare', app, config.team, identity)
        resign(boundary, config, app, identity, declaration)
        result = inspect(probe, app, config.team, identity)
        if result.returncode:
            raise RuntimeError(result.stderr.decode().strip())
        value = json.loads(result.stdout)
        expected = {'schema': 2, 'roles': 1, 'dependencies': 5, 'dependencyHashes': 5,
                    'aliases': 10, 'preflight': True, 'activation': False}
        if value != expected:
            raise RuntimeError('Unexpected valid SDK inspection evidence')
        print(json.dumps({'control': 'valid-signed-sdk', 'result': value}), flush=True)
        info = app / 'Contents/Info.plist'
        saved_info = info.read_bytes()
        extra = app / 'Contents/Frameworks/unlisted-tool'
        shutil.copy2(app / 'Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate', extra)
        resign(boundary, config, app, identity, declaration)
        reject(probe, app, config.team, identity, 'validly-signed-extra-tool', 'identityMismatch')
        extra.unlink()
        resign(boundary, config, app, identity, declaration)
        reject(probe, app, 'ZZZZZZZZZZ', identity, 'wrong-trusted-team', 'security(')
        if info.read_bytes() != saved_info:
            raise RuntimeError('Inspection changed the signed manifest')
        for operation, failure in [('bad-hash', 'identityMismatch'), ('bad-alias', 'unsafePath'),
                                   ('bad-kind', 'identityMismatch'), ('bad-build', 'identityMismatch'),
                                   ('bad-identifier', 'security('), ('bad-team', 'identityMismatch')]:
            info.write_bytes(saved_info)
            boundary.command(probe, operation, app, config.team, identity)
            resign(boundary, config, app, identity, declaration)
            reject(probe, app, config.team, identity, operation, failure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', required=True, help='Public Developer ID certificate SHA-1; no implicit selection')
    parser.add_argument('--team', required=True, help='Expected trusted Developer ID Team')
    args = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Only an ordinary account can run these controls')
    config = SigningConfig(args.identity, args.team)
    boundary = load_boundary()
    for package in [boundary.PACKAGE, PACKAGE]:
        boundary.command('/usr/bin/swift', 'build', '--package-path', package, '--disable-keychain', '--disable-netrc')
    products = Path(boundary.command('/usr/bin/swift', 'build', '--package-path', boundary.PACKAGE, '--show-bin-path').decode().strip())
    probe_products = Path(boundary.command('/usr/bin/swift', 'build', '--package-path', PACKAGE, '--show-bin-path').decode().strip())
    original = boundary.digest((products / 'Sparkle.framework').resolve())
    try:
        controls(boundary, config, products, probe_products / 'DependencyProbe')
    finally:
        if boundary.digest((products / 'Sparkle.framework').resolve()) != original:
            raise RuntimeError('The original SDK changed')
    print(json.dumps({'event': 'owned-fixtures-removed', 'originalSDKPreserved': True, 'installerStarted': False}), flush=True)


if __name__ == '__main__':
    main()
