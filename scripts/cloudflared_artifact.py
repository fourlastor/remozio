"""Prepare one pinned arm64 connector for the app build. Never install or start a tunnel."""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PIN_DIRECTORY = ROOT / 'third-party/cloudflared'
PRODUCT = 'RemozioCloudflared'
RELATIVE_PATH = 'Contents/Helpers/' + PRODUCT


def pin():
    value = json.loads((PIN_DIRECTORY / 'pin.json').read_text())
    if (set(value) != {'version', 'archiveSHA256', 'archiveSize', 'binarySHA256', 'binarySize', 'licenseSHA256'}
            or not isinstance(value['version'], str) or not re.fullmatch(r'20[0-9]{2}\.[1-9][0-9]?\.[0-9]+', value['version'])
            or any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                   for k in ('archiveSHA256', 'binarySHA256', 'licenseSHA256'))
            or type(value['archiveSize']) is not int or not 1 <= value['archiveSize'] <= 30_000_000
            or type(value['binarySize']) is not int or not 32 <= value['binarySize'] <= 100_000_000):
        raise ValueError('Invalid pinned connector declaration')
    if hashlib.sha256((PIN_DIRECTORY / 'LICENSE').read_bytes()).hexdigest() != value['licenseSHA256']:
        raise ValueError('Pinned connector license changed')
    return value


def archive_url(value):
    return 'https://github.com/cloudflare/cloudflared/releases/download/' + value['version'] + '/cloudflared-darwin-arm64.tgz'


def verify_archive(data, value):
    if len(data) != value['archiveSize'] or hashlib.sha256(data).hexdigest() != value['archiveSHA256']:
        raise ValueError('Connector archive does not match its pin')


def binary_from_archive(data, value):
    verify_archive(data, value)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        if (len(members) != 1 or members[0].name != 'cloudflared' or not members[0].isfile()
                or members[0].linkname or members[0].mode != 0o755 or members[0].size != value['binarySize']):
            raise ValueError('Unexpected connector archive contents')
        with archive.extractfile(members[0]) as stream:
            binary = stream.read(value['binarySize'] + 1)
    if len(binary) != value['binarySize'] or hashlib.sha256(binary).hexdigest() != value['binarySHA256']:
        raise ValueError('Connector executable does not match its pin')
    if len(binary) < 32 or struct.unpack_from('<III', binary)[:2] != (0xFEEDFACF, 0x0100000C) or struct.unpack_from('<I', binary, 12)[0] != 2:
        raise ValueError('The connector must be a thin arm64 Mach-O executable')
    return binary


def download(value):
    request = urllib.request.Request(archive_url(value), headers={'User-Agent': 'Remozio-pinned-build-input'})
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.url.startswith('https://'):
            raise ValueError('Connector download requires HTTPS')
        data = response.read(value['archiveSize'] + 1)
    verify_archive(data, value)
    return data


def regular_owned(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
        raise ValueError('Use an owned regular connector build input')


def cached_archive(cache, value, fetch=download):
    cache.mkdir(parents=True, exist_ok=True)
    if cache.resolve() != cache.absolute() or cache.lstat().st_uid != os.getuid():
        raise ValueError('Use an owned canonical connector cache')
    descriptor = os.open(cache / 'input.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'a+b') as lock:
        regular_owned(cache / 'input.lock'); fcntl.flock(lock, fcntl.LOCK_EX)
        archive = cache / 'cloudflared-darwin-arm64.tgz'
        if archive.exists() or archive.is_symlink():
            regular_owned(archive)
            if archive.stat().st_size != value['archiveSize']:
                raise ValueError('Cached connector archive has an unexpected size')
            data = archive.read_bytes(); verify_archive(data, value); return data
        data = fetch(value); verify_archive(data, value)
        with tempfile.NamedTemporaryFile(dir=cache, prefix='.cloudflared-', delete=False) as staging:
            temporary = Path(staging.name)
            try:
                staging.write(data); staging.flush(); os.fsync(staging.fileno())
                os.link(temporary, archive)
            finally:
                temporary.unlink()
        return data


def command(arguments):
    result = subprocess.run([str(a) for a in arguments], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'Connector build tool {Path(arguments[0]).name} failed with status {result.returncode}')
    return result


def signed_tool_identity(path, identifier):
    command(['/usr/bin/codesign', '--verify', '--strict', '-R', '=identifier "' + identifier + '"', path])
    result = command(['/usr/bin/codesign', '--display', '--verbose=4', path])
    fields = dict(line.split('=', 1) for line in result.stderr.splitlines() if '=' in line)
    digest = fields.get('CDHash', '')
    if fields.get('Identifier') != identifier or not re.fullmatch(r'[0-9a-fA-F]{40}', digest) or 'runtime)' not in result.stderr:
        raise ValueError('Unexpected connector signing identity or runtime')
    team = fields.get('TeamIdentifier')
    if team == 'not set': team = None
    elif not team or not re.fullmatch(r'[A-Z0-9]{10}', team): raise ValueError('Unexpected connector signing team')
    return bytes.fromhex(digest), team


def prepare(environment, fetch=download):
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Prepare connector inputs as an ordinary build user')
    value = pin()
    configuration = environment['CONFIGURATION']
    suffix = '.debug' if configuration == 'Debug' else ''
    if configuration not in ('Debug', 'Release') or environment['PRODUCT_BUNDLE_IDENTIFIER'] != 'dev.remozio.mac' + suffix:
        raise ValueError('Unexpected app build identity')
    identity = environment.get('EXPANDED_CODE_SIGN_IDENTITY') or environment.get('CODE_SIGN_IDENTITY') or '-'
    if identity != '-' and not re.fullmatch(r'[0-9a-fA-F]{40}', identity):
        raise ValueError('Use an explicit signing fingerprint or the ad-hoc build identity')
    data = cached_archive(ROOT / '.build/vendor/cloudflared' / value['version'] / value['archiveSHA256'], value, fetch)
    binary = binary_from_archive(data, value)
    products = Path(environment['BUILT_PRODUCTS_DIR']); products.mkdir(parents=True, exist_ok=True)
    target = products / PRODUCT
    if target.exists() or target.is_symlink(): regular_owned(target)
    with tempfile.TemporaryDirectory(prefix='.remozio-cloudflared-', dir=products) as temporary:
        candidate = Path(temporary) / PRODUCT; candidate.write_bytes(binary); candidate.chmod(0o755)
        entitlements = Path(temporary) / 'empty-entitlements.plist'; entitlements.write_bytes(plistlib.dumps({}))
        identifier = 'dev.remozio.cloudflared' + suffix
        command(['/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--identifier', identifier,
                 '--entitlements', entitlements, '--timestamp=none' if identity == '-' else '--timestamp', candidate])
        digest, team = signed_tool_identity(candidate, identifier)
        os.replace(candidate, target)
    regular_owned(target)
    return {'version': value['version'], 'archiveSHA256': value['archiveSHA256'], 'binarySHA256': value['binarySHA256'],
            'codeDirectoryHash': digest.hex(), 'teamID': team, 'identifier': identifier, 'relativePath': RELATIVE_PATH,
            'tunnelStarted': False}


if __name__ == '__main__':
    print(json.dumps(prepare(os.environ), sort_keys=True))
