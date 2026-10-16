#!/usr/bin/env python3
"""Install one pinned developer package only on an explicitly dispatched hosted Mac."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'rock3r/remozio'
ASSET_NAME = 'Remozio-native-installer.pkg'
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
BUNDLE = Path('/Library/Application Support/Remozio/Applications/Remozio.app')
SHARED = BUNDLE.parent.parent
ENTRY = Path('/Applications/Remozio.app')
SETUP = BUNDLE / 'Contents/Library/LaunchServices/RemozioSetup'
STATE_FILES = ('setup.cbor', 'bootstrap-intent.cbor', 'bootstrap-complete.cbor', 'Machine/installation.sqlite')


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = load('native_package_builder', 'build-macos-package.py')
EVIDENCE = load('native_package_evidence', 'collect-production-child-ci-evidence.py')


def context():
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    value = EVIDENCE.workflow_context(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0],
                                      os.getuid(), os.geteuid(), head)
    # This is an accidental-use guard, not attestation against a malicious local administrator.
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT):
        raise ValueError('The experiment requires an unchanged reviewed checkout')
    return value


def positive_id(value):
    if type(value) is not str or not re.fullmatch(r'[1-9][0-9]{0,19}', value):
        raise ValueError('Invalid provider identifier')
    return int(value)


def pins(digest, team):
    if not re.fullmatch(r'[0-9a-f]{64}', digest) or not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('An operator-pinned package hash and publisher Team ID are required')


def provider_failure(stage, result):
    # Keep provider text private. A unique bounded CLI status is diagnostic data only.
    matches = set(re.findall(rb'\(HTTP ([1-5][0-9]{2})\)\r?$',
        (result.stderr or b'')[-8192:], re.MULTILINE))
    status = next(iter(matches)).decode('ascii') if len(matches) == 1 else 'unknown'
    return f'{stage} failed with status {result.returncode}; reported HTTP status {status}'


def command(arguments, *, root=False, timeout=120, accepted=(0,)):
    executable = Path(str(arguments[0])).name
    if root:
        arguments = ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i',
                     'PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'HOME=/var/root', 'LC_ALL=C', *arguments]
    result = subprocess.run([str(a) for a in arguments], capture_output=True, timeout=timeout)
    if result.returncode not in accepted:
        if not root and arguments[:4] == ['gh', 'api', '--method', 'GET']:
            raise RuntimeError(provider_failure('GitHub metadata request', result))
        raise RuntimeError(f'{executable} failed with status {result.returncode}')
    return result


def api(endpoint):
    raw = command(['gh', 'api', '--method', 'GET', endpoint]).stdout
    if len(raw) > 1024 * 1024:
        raise ValueError('Provider metadata exceeds its bound')
    return json.loads(raw, object_pairs_hook=EVIDENCE.unique_object)


def validate_asset(release, asset, release_id, asset_id):
    expected_release = positive_id(release_id)
    expected_asset = positive_id(asset_id)
    if type(release) is not dict or type(release.get('id')) is not int or release['id'] != expected_release or \
            release.get('draft') is not True or release.get('published_at') is not None or \
            not re.fullmatch(r'native-installer-experiment-[0-9a-f]{12}', release.get('tag_name', '')):
        raise ValueError('Requires the exact unpublished experiment draft')
    if type(asset) is not dict or type(asset.get('id')) is not int or asset['id'] != expected_asset or \
            asset.get('name') != ASSET_NAME or asset.get('state') != 'uploaded' or \
            type(asset.get('size')) is not int or not 0 < asset['size'] <= MAX_PACKAGE_BYTES:
        raise ValueError('Invalid pinned package asset')
    rows = release.get('assets')
    if type(rows) is not list or sum(type(row) is dict and row.get('id') == expected_asset for row in rows) != 1 or \
            next(row for row in rows if type(row) is dict and row.get('id') == expected_asset) != asset:
        raise ValueError('The asset is not part of the pinned draft')
    return asset['size']


def verify_package(path, digest, size):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size or not 0 < size <= MAX_PACKAGE_BYTES:
        raise ValueError('Invalid package transfer')
    with path.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != digest:
            raise ValueError('The package differs from the operator pin')


def fetch(args):
    context()  # Refuse local use before reading credentials or contacting GitHub.
    pins(args.package_sha256, args.trusted_team)
    positive_id(args.release_id); positive_id(args.asset_id)
    endpoint = f'repos/{REPOSITORY}/releases'
    release = api(endpoint + '/' + args.release_id)
    asset = api(endpoint + '/assets/' + args.asset_id)
    size = validate_asset(release, asset, args.release_id, args.asset_id)
    with args.package.open('xb') as output:
        result = subprocess.run(['gh', 'api', '--method', 'GET', endpoint + '/assets/' + args.asset_id,
                                 '-H', 'Accept: application/octet-stream'], stdout=output, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise RuntimeError(provider_failure('Package asset download', result))
    verify_package(args.package, args.package_sha256, size)
    # Recheck draft status after transfer. This script never publishes a release.
    validate_asset(api(endpoint + '/' + args.release_id), api(endpoint + '/assets/' + args.asset_id),
                   args.release_id, args.asset_id)
    print('Pinned unpublished package downloaded. No installation performed.')


def read_profile(expanded, team):
    scripts = expanded / 'payload.pkg/Scripts'
    source = (scripts / 'preinstall').read_text()
    match = re.search(r'--prepare-package ([A-Z0-9]{10}:[0-9a-f]{40}:[0-9a-f]{64})\n\Z', source)
    if not match:
        raise ValueError('Missing fixed package profile')
    profile = BUILDER.profile(match.group(1), team)
    for role in BUILDER.IDENTIFIERS:
        directory = expanded / (role + '.pkg/Scripts')
        name = 'preinstall' if role == 'payload' else 'postinstall'
        expected = {name, 'RemozioSetup'}
        entries = {p.name for p in directory.iterdir()}
        if not expected <= entries or not entries <= expected | { '._' + item for item in expected }:
            raise ValueError('Package scripts differ from the production builder')
        for entry in entries:
            path = directory / entry
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('Unsupported package script entry')
            if entry.startswith('._'):
                BUILDER.validate_metadata(EVIDENCE.read_bytes(path, 8192))
        if (directory / name).read_text() != BUILDER.package_script(role, profile) or \
                (directory / 'RemozioSetup').read_bytes() != (scripts / 'RemozioSetup').read_bytes():
            raise ValueError('Package scripts differ from the production builder')
    return profile


def app_snapshot():
    result = {}
    for directory, folders, files in os.walk(BUNDLE, followlinks=False):
        for name in folders + files:
            path = Path(directory) / name
            info = path.lstat()
            if len(result) >= 8192 or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7022 or \
                    stat.S_IFMT(info.st_mode) not in (stat.S_IFREG, stat.S_IFDIR):
                raise ValueError('Unsafe installed app metadata')
            digest = None
            if stat.S_ISREG(info.st_mode):
                with path.open('rb') as source:
                    digest = hashlib.file_digest(source, 'sha256').hexdigest()
            result[str(path.relative_to(BUNDLE))] = (info.st_dev, info.st_ino, info.st_mode, info.st_size, digest)
    info = BUNDLE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7022 or not result:
        raise ValueError('Missing protected app')
    result['.'] = (info.st_dev, info.st_ino, info.st_mode)
    return result


def state_snapshot():
    result = {}
    for name in STATE_FILES:
        path = SHARED / name
        metadata = command(['/usr/bin/stat', '-f', '%d:%i:%u:%g:%p:%l:%z', path], root=True).stdout
        digest = command(['/usr/bin/shasum', '-a', '256', path], root=True).stdout
        # Native inspect validates metadata. These private values stay in process memory only.
        result[name] = (metadata, digest)
    return result


def entry_snapshot():
    info = ENTRY.lstat()
    if not stat.S_ISLNK(info.st_mode) or os.readlink(ENTRY) != str(BUNDLE):
        raise ValueError('The Applications entry does not point to the protected app')
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, os.readlink(ENTRY)


def require_retained(profile):
    value = command([SETUP, '--inspect-package', profile], root=True).stdout
    if value != b'retained\n':
        raise ValueError('Native installed state did not validate as retained')


def retained_snapshot(profile):
    require_retained(profile)
    return app_snapshot(), state_snapshot(), entry_snapshot()


def success(context, digest, profile):
    return {'schemaVersion': 1, 'kind': 'macos-native-package-hosted', **context,
            'packageSHA256': digest, 'trustedTeamID': profile[:10],
            'freshNativeInstallPassed': True, 'installedReleaseValidated': True,
            'sameBuildRepeatPassed': True, 'appBytesAndInodesRetained': True,
            'bootstrapFilesBytesAndInodesRetained': True, 'bootstrapFileCount': len(STATE_FILES), 'applicationsShortcutRetained': True,
            'payloadComponentRefused': True, 'refusalStateUnchanged': True,
            'servicesActivated': False, 'physicalPixelTested': False,
            'interactiveInstallerTested': False, 'interruptedInstallRecoveryTested': False,
            'differentReleaseUpdateTested': False, 'installationRetainedUntilVMDisposal': True}


def run(args):
    provider = context()  # No local elevation switch exists.
    pins(args.package_sha256, args.trusted_team)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Use a new evidence output path')
    verify_package(args.package, args.package_sha256, args.package.stat().st_size)
    if SHARED.exists() or SHARED.is_symlink() or ENTRY.exists() or ENTRY.is_symlink():
        raise ValueError('The disposable VM must have no previous Remozio installation')
    work = command(['/usr/bin/mktemp', '-d', '/private/var/tmp/remozio-package-ci.XXXXXXXX'], root=True).stdout.decode().strip()
    if not re.fullmatch(r'/private/var/tmp/remozio-package-ci\.[A-Za-z0-9]{8}', work):
        raise ValueError('Unexpected protected transfer directory')
    directory = Path(work)
    package = directory / ASSET_NAME
    command(['/bin/cp', args.package, package], root=True)
    command(['/usr/sbin/chown', '0:0', package], root=True)
    command(['/bin/chmod', '0444', package], root=True)
    frozen = command(['/usr/bin/shasum', '-a', '256', package], root=True).stdout.decode()
    if frozen != f'{args.package_sha256}  {package}\n':
        raise ValueError('Protected package copy differs from the operator pin')
    # The transfer directory remains private to Root. Inspect a separate ordinary copy before installation.
    with tempfile.TemporaryDirectory(prefix='remozio-package-inspect-') as temporary:
        expanded = Path(temporary) / 'expanded'
        command(['/usr/sbin/pkgutil', '--expand', args.package, expanded])
        profile = read_profile(expanded, args.trusted_team)
        # Verify the original again after inspection; Root installs only its independently hashed copy.
        verify_package(args.package, args.package_sha256, args.package.stat().st_size)
        print('Native package stage: fresh installation', flush=True)
        command(['/usr/sbin/installer', '-pkg', package, '-target', '/'], root=True, timeout=180)
        BUILDER.verify_payload(expanded / 'payload.pkg/Payload', BUNDLE)
        before = retained_snapshot(profile)
        print('Native package stage: same-build retention', flush=True)
        command(['/usr/sbin/installer', '-pkg', package, '-target', '/'], root=True, timeout=180)
        if retained_snapshot(profile) != before:
            raise ValueError('Same-build installation replaced established code or identity')
        # Exercise the actual payload package directly, bypassing distribution choice convenience.
        print('Native package stage: payload component refusal', flush=True)
        protected_expanded = directory / 'expanded'
        payload = directory / 'forced-payload.pkg'
        command(['/usr/sbin/pkgutil', '--expand', package, protected_expanded], root=True)
        command(['/usr/sbin/pkgutil', '--flatten', protected_expanded / 'payload.pkg', payload], root=True)
        refusal = command([SETUP, '--prepare-package', profile], root=True, accepted=(78,))
        if b'Package preparation refused or failed.' not in refusal.stderr:
            raise ValueError('The native payload guard did not report the expected refusal')
        forced = command(['/usr/sbin/installer', '-dumplog', '-pkg', payload, '-target', '/'],
                         root=True, timeout=180, accepted=(1,))
        if b'Package preparation refused or failed.' not in forced.stdout + forced.stderr:
            raise ValueError('Payload failure did not establish native preinstall refusal')
        if retained_snapshot(profile) != before:
            raise ValueError('Refused payload installation changed established state')
    # No app launch, service registration, account enrollment, reset or installation deletion follows.
    with args.output.open('x') as output:
        output.write(json.dumps(success(provider, args.package_sha256, profile), indent=2, sort_keys=True) + '\n')
    print('Fresh installation, same-build retention and native payload refusal passed. VM disposal remains required.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['fetch', 'run'])
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--trusted-team', required=True)
    parser.add_argument('--release-id')
    parser.add_argument('--asset-id')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.mode == 'fetch':
        fetch(args)
    else:
        if args.output is None:
            parser.error('--output is required for run')
        run(args)


if __name__ == '__main__':
    main()
