#!/usr/bin/env python3
"""Inspect disposable release copies through the production signature reader."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP_IDENTIFIER = 'dev.remozio.mac'
DEFAULT_TEAM = 'AAAAAAAAAA'
APP = Path('.build/macos-app/DerivedData/Build/Products/Release/Remozio.app')


def run(arguments, *, timeout=30, check=True):
    """Bound commands and keep candidate paths and tool diagnostics out of evidence."""
    try:
        result = subprocess.run([str(x) for x in arguments], capture_output=True,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'{Path(arguments[0]).name} timed out; result unknown') from None
    if check and result.returncode:
        raise RuntimeError(f'{Path(arguments[0]).name} failed with status {result.returncode}')
    return result


def fingerprint(bundle):
    """Reject aliases and special files before copying or signing the known build output."""
    if not stat.S_ISDIR(bundle.lstat().st_mode):
        raise ValueError('The built app must be a directory without an alias')
    digest = hashlib.sha256()
    count = 0
    def unreadable(_):
        raise ValueError("The built app inventory could not be read")
    for directory, folders, files in os.walk(bundle, followlinks=False, onerror=unreadable):
        for name in sorted(folders + files):
            path = Path(directory) / name
            relative = path.relative_to(bundle).as_posix()
            metadata = path.lstat()
            mode = metadata.st_mode
            count += 1
            if count > 8192 or len(relative.split('/')) > 16:
                raise ValueError('The built app exceeds fixture inventory limits')
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError('The signing fixture rejects aliases and special files')
            digest.update(relative.encode('utf-8') + b'\0' + str(mode).encode('ascii') + b'\0' + str(metadata.st_size if stat.S_ISREG(mode) else 0).encode('ascii') + b'\0')
            if stat.S_ISREG(mode):
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(65536), b''):
                        digest.update(block)
        folders.sort()
    return digest.hexdigest()


def inspect(probe, bundle, team, expected, identifier=APP_IDENTIFIER):
    result = run([probe, bundle, team, identifier], check=False)
    if not expected:
        if result.returncode != 1 or result.stdout.strip() != 'rejected' or result.stderr:
            raise RuntimeError('The production reader did not confirm rejection')
        return {'result': 'rejected'}
    if result.returncode or result.stderr:
        raise RuntimeError('The production reader did not confirm acceptance')
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise RuntimeError('The production reader returned invalid evidence') from None
    expected_roles = sorted(role for role, *_ in load_manifest().COMPONENTS)
    if not isinstance(value, dict) or value.get('result') != 'accepted' or \
       value.get('components') != len(expected_roles) or value.get('hashes') != len(expected_roles) or \
       value.get('roles') != expected_roles:
        raise RuntimeError('The production reader returned incomplete evidence')
    absent = value.get('absentRoles')
    if not isinstance(absent, list) or any(type(role) is not int or role <= 0 for role in absent) or \
       len(set(absent)) != len(absent) or set(absent).intersection(expected_roles):
        raise RuntimeError('The production reader returned conflicting absence evidence')
    return value


def load_manifest():
    spec = importlib.util.spec_from_file_location('signing_manifest', ROOT / 'scripts/generate-macos-release-manifest.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signing_options(identity, team):
    if (identity is None) != (team is None):
        raise ValueError('Supply both the signing certificate fingerprint and trusted Team ID')
    if identity is not None:
        if not re.fullmatch(r'[0-9A-Fa-f]{40}', identity):
            raise ValueError('Use the explicit 40-character certificate fingerprint')
        if not re.fullmatch(r'[A-Z0-9]{10}', team):
            raise ValueError('Use the independently trusted 10-character Team ID')
    return identity.upper() if identity else None, team


def measure(probe, *, identity=None, team=None):
    identity, team = signing_options(identity, team)
    original = ROOT / APP
    initial = fingerprint(original)
    public = run(['/usr/bin/codesign', '--display', '--verbose=4', original])
    if 'Signature=adhoc' not in public.stderr or 'TeamIdentifier=not set' not in public.stderr:
        raise RuntimeError('Build the ad-hoc Release app before running this experiment')
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', original])
    cases = {}
    try:
        cases['adHocRelease'] = inspect(probe, original, team or DEFAULT_TEAM, False)
        if identity:
            manifest = load_manifest()
            with tempfile.TemporaryDirectory(prefix='remozio-release-signing-') as temporary:
                directory = Path(temporary).resolve()
                app = directory / 'Remozio.app'
                shutil.copytree(original, app, symlinks=True)
                if fingerprint(app) != initial:
                    raise RuntimeError('The disposable copy does not match the built app')
                products = directory / 'products'
                products.mkdir()
                for _, name, relative, product, _ in manifest.COMPONENTS:
                    if not product:
                        continue
                    executable = app / relative
                    run(['/usr/bin/codesign', '--force', '--sign', identity, '--timestamp=none',
                         '--options', 'runtime', '--identifier', 'dev.remozio.' + name, executable])
                    shutil.copy2(executable, products / product)
                info_path = app / 'Contents/Info.plist'
                info = plistlib.loads(info_path.read_bytes())
                info.update(manifest.generate({'SRCROOT': str(ROOT / 'macos/app'),
                    'BUILT_PRODUCTS_DIR': str(products), 'CONFIGURATION': 'Release',
                    'PRODUCT_BUNDLE_IDENTIFIER': APP_IDENTIFIER, 'MACOSX_DEPLOYMENT_TARGET': '26.0',
                    'MARKETING_VERSION': info['CFBundleShortVersionString'],
                    'CURRENT_PROJECT_VERSION': info['CFBundleVersion']}))
                info_path.write_bytes(plistlib.dumps(info))
                entitlements = directory / 'identity.plist'
                def sign_app(bundle, entitlement_identifier=APP_IDENTIFIER):
                    fingerprint(bundle)
                    entitlements.write_bytes(plistlib.dumps({
                        'com.apple.application-identifier': team + '.' + entitlement_identifier,
                        'com.apple.developer.team-identifier': team}))
                    run(['/usr/bin/codesign', '--force', '--sign', identity, '--timestamp=none',
                         '--options', 'runtime', '--identifier', APP_IDENTIFIER,
                         '--entitlements', entitlements, bundle])
                    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', bundle])
                sign_app(app)
                cases['developerIDCompleteBundle'] = inspect(probe, app, team, True)
                wrong_team = 'BBBBBBBBBB' if team == DEFAULT_TEAM else DEFAULT_TEAM
                cases['wrongTrustedTeam'] = inspect(probe, app, wrong_team, False)
                cases['wrongAppIdentifier'] = inspect(probe, app, team, False, 'dev.remozio.other')
                extra = directory / 'Extra.app'
                shutil.copytree(app, extra, symlinks=True)
                shutil.copy2(extra / 'Contents/Helpers/RemozioCommandChild', extra / 'Contents/Helpers/UnlistedHelper')
                sign_app(extra)
                cases['signedUndeclaredHelper'] = inspect(probe, extra, team, False)
                wrong = directory / 'WrongEntitlement.app'
                shutil.copytree(app, wrong, symlinks=True)
                sign_app(wrong, 'dev.remozio.other')
                cases['foreignApplicationIdentifierEntitlement'] = inspect(probe, wrong, team, False)
    finally:
        if fingerprint(original) != initial:
            raise RuntimeError('The original built app changed during this experiment')
    return {'experiment': 'complete-release-signature-inspection', 'schemaVersion': 1,
        'mode': 'developer-id' if identity else 'ad-hoc-rejection', 'cases': cases,
        'trustedTeamID': team, 'identityFingerprint': identity, 'originalBundleUnchanged': True,
        'temporarySignedCopiesRemoved': True, 'signingTimestampUsed': False,
        'notarizationTested': False, 'appLaunched': False, 'servicesInstalled': False,
        'limits': ['Candidate signature evidence only; no protected installation or activation',
                   'No password retrieval or authentication UI automation',
                   'No notarization, secure timestamp, revocation or macOS 26 runtime proof']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--signing-identity', help='Explicit certificate SHA-1 fingerprint; no automatic selection')
    parser.add_argument('--trusted-team', help='Expected Team ID from trusted policy, independent of the candidate')
    arguments = parser.parse_args()
    try:
        identity, team = signing_options(arguments.signing_identity, arguments.trusted_team)
    except ValueError as error:
        parser.error(str(error))
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or os.geteuid() == 0:
        parser.error('Run without elevation on an Apple Silicon Mac')
    package = ROOT / 'experiments/release-signing'
    build_arguments = ['swift', 'build', '--package-path', package, '--scratch-path',
        ROOT / '.build/release-signing', '--triple', 'arm64-apple-macosx26.0', '--disable-keychain', '--disable-netrc']
    run(build_arguments, timeout=300)
    binary_path = Path(run([*build_arguments, '--show-bin-path']).stdout.strip())
    probe = binary_path / 'ReleaseSigningProbe'
    evidence = measure(probe, identity=identity, team=team)
    evidence['recordedAtUTC'] = datetime.now(timezone.utc).isoformat()
    evidence['probeSHA256'] = hashlib.sha256(probe.read_bytes()).hexdigest()
    evidence['host'] = {'os': run(['sw_vers', '-productVersion']).stdout.strip(),
        'build': run(['sw_vers', '-buildVersion']).stdout.strip(),
        'sdk': run(['xcrun', '--show-sdk-version']).stdout.strip(),
        'architecture': platform.machine(), 'deploymentTarget': '26.0'}
    evidence['sources'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [ROOT / 'scripts/run-macos-release-signing-experiment.py',
                  package / 'Package.swift', package / 'Sources/ReleaseSigningProbe/main.swift',
                  ROOT / 'scripts/generate-macos-release-manifest.py',
                  ROOT / 'macos/core/Sources/RemozioCore/SignedReleaseInspection.swift']}
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
