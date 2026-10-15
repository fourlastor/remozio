#!/usr/bin/env python3
"""Build an initial-install package without installing or activating it."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = '/Library/Application Support/Remozio/Applications/Remozio.app'
PARENT = str(Path(BUNDLE).parent)
IDENTIFIERS = {'payload': 'dev.remozio.pkg.application', 'bootstrap': 'dev.remozio.pkg.bootstrap'}


def signing_reader():
    spec = importlib.util.spec_from_file_location('package_signing_reader', ROOT / 'scripts/run-macos-release-signing-experiment.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(arguments, timeout=120):
    result = subprocess.run([str(a) for a in arguments], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{Path(arguments[0]).name} failed with status {result.returncode}')
    return result


def profile(value, team):
    if not re.fullmatch(r'[A-Z0-9]{10}:[0-9a-f]{40}:[0-9a-f]{64}', value or '') or value[:10] != team:
        raise ValueError('The verified release did not supply a matching package profile')
    return value


def package_script(mode, pins):
    """Native script arguments include the target volume as $3. Refuse other volumes."""
    profile(pins, pins[:10])
    header = '''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "${3:-}" = / ] || { echo 'Remozio requires the current startup volume.' >&2; exit 64; }
[ "$(/usr/bin/id -ru)" = 0 ] && [ "$(/usr/bin/id -u)" = 0 ] || exit 77
script_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
helper="$script_dir/RemozioSetup"
'''
    if mode == 'payload':
        return header + 'exec "$helper" --prepare-package ' + shlex.quote(pins) + '\n'
    if mode != 'bootstrap':
        raise ValueError('Unknown package script mode')
    return header + 'plan=$("$helper" --inspect-package ' + shlex.quote(pins) + ''')
case "$plan" in
    bootstrap) ''' + shlex.quote(BUNDLE + '/Contents/Library/LaunchServices/RemozioSetup') + ' --bootstrap-installation ' + shlex.quote(pins[:10]) + ''' ;;
    retained) ;;
    *) exit 78 ;;
esac
exec "$helper" --ensure-app-entry ''' + shlex.quote(pins) + '\n'


def distribution(version):
    xml = ET.Element('installer-gui-script', {'minSpecVersion': '2'})
    ET.SubElement(xml, 'title').text = 'Remozio developer preview'
    ET.SubElement(xml, 'welcome', {'file': 'welcome.txt', 'mime-type': 'text/plain'})
    ET.SubElement(xml, 'conclusion', {'file': 'conclusion.txt', 'mime-type': 'text/plain'})
    ET.SubElement(xml, 'options', {'customize': 'never', 'require-scripts': 'false',
        'allow-external-scripts': 'no', 'hostArchitectures': 'arm64'})
    ET.SubElement(xml, 'domains', {'enable_anywhere': 'false', 'enable_currentUserHome': 'false', 'enable_localSystem': 'true'})
    check = ET.SubElement(xml, 'volume-check', {'script': 'startupVolume()'})
    versions = ET.SubElement(check, 'allowed-os-versions')
    ET.SubElement(versions, 'os-version', {'min': '26.0'})
    ET.SubElement(xml, 'script').text = '''function startupVolume() {
    if (my.target.mountpoint == "/") return true;
    my.result.type = "Fatal";
    my.result.message = "Remozio requires the current startup volume.";
    return false;
}
function needsPayload() { return !system.files.fileExistsAtPath(''' + json.dumps(BUNDLE) + '''); }
'''
    outline = ET.SubElement(xml, 'choices-outline')
    for role, identity in IDENTIFIERS.items():
        ET.SubElement(outline, 'line', {'choice': role})
        choice = ET.SubElement(xml, 'choice', {'id': role, 'title': 'Remozio', 'visible': 'false', 'enabled': 'false',
            'selected': 'needsPayload()' if role == 'payload' else 'true'})
        ET.SubElement(choice, 'pkg-ref', {'id': identity})
        ET.SubElement(xml, 'pkg-ref', {'id': identity, 'version': version, 'auth': 'Root'}).text = role + '.pkg'
    return ET.tostring(xml, encoding='utf-8', xml_declaration=True)


def validate_metadata(data):
    """Allow only empty Finder data and Apple's non-authoritative provenance attribute."""
    if len(data) < 152 or len(data) > 8192:
        raise RuntimeError('Unsupported package metadata')
    magic, version = struct.unpack_from('>II', data)
    count = struct.unpack_from('>H', data, 24)[0]
    finder, start, length, fork, fork_start, fork_length = struct.unpack_from('>6I', data, 26)
    if (magic, version, count, finder, start, fork, fork_start, fork_length) != (0x51607, 0x20000, 2, 9, 50, 2, len(data), 0) or length != len(data) - start:
        raise RuntimeError('Unsupported package metadata entries')
    if data[50:84] != bytes(34):
        raise RuntimeError('Package Finder metadata is not empty')
    header = struct.unpack_from('>8I2H', data, 84)
    if header[0] != 0x41545452 or header[1] != 0 or header[2] != len(data) or any(header[5:9]) or header[9] != 1:
        raise RuntimeError('Unsupported package attributes')
    offset, size, flags, name_length = struct.unpack_from('>IIHB', data, 120)
    name = data[131:131 + name_length]
    if name != b'com.apple.provenance\0' or flags != 0 or offset < 131 + name_length or offset + size != len(data) or not 1 <= size <= 64:
        raise RuntimeError('Unsupported package attribute')
    if header[3:5] != (offset, size) or any(data[131 + name_length:offset]):
        raise RuntimeError('Malformed package attributes')


def archive_inventory(payload):
    """Read the legacy odc cpio stream. Expanded files do not retain archive ownership."""
    records = {}
    with gzip.open(payload, 'rb') as stream:
        def read(count):
            data = stream.read(count)
            if len(data) != count:
                raise RuntimeError('Truncated package payload')
            return data
        while True:
            header = read(76)
            if header[:6] != b'070707':
                raise RuntimeError('Unsupported package payload format')
            fields = [int(header[a:b], 8) for a, b in [(6, 12), (12, 18), (18, 24), (24, 30),
                (30, 36), (36, 42), (42, 48), (48, 59), (59, 65), (65, 76)]]
            _, _, mode, uid, gid, links, _, _, size_name, size = fields
            if size_name < 1 or size_name > 4096 or size > 512 * 1024 * 1024 or len(records) > 8192:
                raise RuntimeError('The package payload exceeds inventory limits')
            name_bytes = read(size_name)
            if name_bytes[-1:] != b'\0':
                raise RuntimeError('Invalid package payload name')
            name = name_bytes[:-1].decode('utf-8')
            if name == 'TRAILER!!!':
                break
            path = Path(name)
            if path.is_absolute() or '..' in path.parts or path.as_posix() in records:
                raise RuntimeError('Unsafe package payload path')
            metadata = path.name.startswith('._')
            if metadata and size > 8192:
                raise RuntimeError('The package metadata exceeds limits')
            metadata_bytes = bytearray()
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                block = read(min(remaining, 65536)); digest.update(block); remaining -= len(block)
                if metadata: metadata_bytes.extend(block)
            if uid != 0 or gid != 0 or mode & 0o7022 or stat.S_IFMT(mode) not in (stat.S_IFDIR, stat.S_IFREG):
                raise RuntimeError('The package payload has unsafe ownership, permissions or file types')
            if metadata:
                if mode != stat.S_IFREG | 0o644:
                    raise RuntimeError('Unsupported package metadata mode')
                validate_metadata(bytes(metadata_bytes))
            elif stat.S_ISREG(mode) and links != 1:
                raise RuntimeError('The package payload contains a hard link')
            records[path.as_posix()] = {'mode': mode & 0o777, 'sha256': digest.hexdigest(), 'size': size, 'metadata': metadata, 'type': stat.S_IFMT(mode)}
    return records


def verify_payload(payload, app):
    records = archive_inventory(payload)
    expected = {'.', 'Remozio.app'}
    for directory, folders, files in os.walk(app):
        for name in folders + files:
            file = Path(directory) / name
            relative = 'Remozio.app/' + file.relative_to(app).as_posix()
            expected.add(relative)
            row = records.get(relative)
            metadata = file.lstat()
            if row is None or row['mode'] != stat.S_IMODE(metadata.st_mode) or row['type'] != stat.S_IFMT(metadata.st_mode):
                raise RuntimeError('The archived app does not match the verified source')
            if file.is_file() and (row['sha256'] != hashlib.sha256(file.read_bytes()).hexdigest() or row['size'] != metadata.st_size):
                raise RuntimeError('The archived app bytes changed')
    for name, row in records.items():
        if row['metadata'] and str(Path(name).with_name(Path(name).name[2:])) not in expected:
            raise RuntimeError('Orphan package metadata')
    if {name for name, row in records.items() if not row['metadata']} != expected or records['Remozio.app']['mode'] != stat.S_IMODE(app.lstat().st_mode) or any(records[name]['type'] != stat.S_IFDIR for name in ('.', 'Remozio.app')):
        raise RuntimeError('The package contains an unexpected payload')
    return len(records)


def publish_package(candidate, output):
    """Publish complete bytes exclusively. Failed copies leave no final artifact."""
    with tempfile.NamedTemporaryFile(prefix='.remozio-package-', dir=output.parent) as temporary:
        with candidate.open('rb') as source:
            shutil.copyfileobj(source, temporary)
        temporary.flush()
        os.fsync(temporary.fileno())
        os.link(temporary.name, output)


def build(app, output, team, *, installer_identity=None, unsigned_developer=False):
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('An independently trusted Team ID is required')
    if bool(installer_identity) == bool(unsigned_developer):
        raise ValueError('Choose an explicit installer identity or unsigned developer mode')
    output = output.absolute()
    if output.suffix != '.pkg' or output.exists() or output.is_symlink():
        raise ValueError('Use a new .pkg output path')
    reader = signing_reader()
    original = reader.fingerprint(app)
    probe_arguments = ['swift', 'build', '--package-path', ROOT / 'experiments/release-signing',
        '--scratch-path', ROOT / '.build/release-signing', '--triple', 'arm64-apple-macosx26.0', '--disable-keychain', '--disable-netrc']
    run(probe_arguments, timeout=300)
    probe = Path(run([*probe_arguments, '--show-bin-path']).stdout.strip()) / 'ReleaseSigningProbe'
    with tempfile.TemporaryDirectory(prefix='remozio-package-') as temporary:
        staging = Path(temporary).resolve()
        payload = staging / 'payload'; payload.mkdir()
        copy = payload / 'Remozio.app'; shutil.copytree(app, copy, symlinks=True)
        if reader.fingerprint(copy) != original:
            raise RuntimeError('The app changed while copying')
        value = reader.inspect(probe, copy, team, True)
        pins = profile(value.get('packageProfile'), team)
        info = plistlib.loads((copy / 'Contents/Info.plist').read_bytes())
        version = info['CFBundleVersion']
        if not isinstance(version, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', version):
            raise ValueError('The app build version is not a supported package version')
        components = staging / 'components.plist'
        components.write_bytes(plistlib.dumps([{'RootRelativeBundlePath': 'Remozio.app',
            'BundleIsRelocatable': False, 'BundleIsVersionChecked': False, 'BundleHasStrictIdentifier': True,
            'BundleOverwriteAction': 'upgrade'}]))
        for role, identity in IDENTIFIERS.items():
            scripts = staging / (role + '-scripts'); scripts.mkdir()
            shutil.copy2(copy / 'Contents/Library/LaunchServices/RemozioSetup', scripts / 'RemozioSetup')
            script = scripts / ('preinstall' if role == 'payload' else 'postinstall')
            script.write_text(package_script(role, pins)); script.chmod(0o755)
            arguments = ['/usr/bin/pkgbuild', '--identifier', identity, '--version', version, '--scripts', scripts]
            if role == 'payload':
                arguments += ['--root', payload, '--install-location', PARENT, '--ownership', 'recommended',
                    '--compression', 'legacy', '--component-plist', components]
            else:
                arguments += ['--nopayload']
            run([*arguments, staging / (role + '.pkg')])
        resources = staging / 'resources'; resources.mkdir()
        (resources / 'welcome.txt').write_text('This developer preview installs Remozio and prepares its machine files.\nIt does not enable command approvals or register services.\nAn existing installation must match this exact build.\n')
        (resources / 'conclusion.txt').write_text('File preparation has completed.\nThe Remozio app is available in Applications.\nAccount enrollment and service activation remain separate.\n')
        definition = staging / 'Distribution.xml'; definition.write_bytes(distribution(version))
        candidate = staging / 'Remozio.pkg'
        arguments = ['/usr/bin/productbuild', '--distribution', definition, '--package-path', staging, '--resources', resources]
        if installer_identity:
            arguments += ['--sign', installer_identity, '--timestamp']
        run([*arguments, candidate])
        expanded = staging / 'expanded'
        run(['/usr/sbin/pkgutil', '--expand', candidate, expanded])
        count = verify_payload(expanded / 'payload.pkg/Payload', copy)
        # Both package scripts must contain the exact verified setup helper.
        helper_digest = hashlib.sha256((copy / 'Contents/Library/LaunchServices/RemozioSetup').read_bytes()).hexdigest()
        for role in IDENTIFIERS:
            scripts = expanded / (role + '.pkg/Scripts')
            name = 'preinstall' if role == 'payload' else 'postinstall'
            if (scripts / name).read_bytes() != package_script(role, pins).encode():
                raise RuntimeError('The archived package script changed')
            if hashlib.sha256((scripts / 'RemozioSetup').read_bytes()).hexdigest() != helper_digest:
                raise RuntimeError('The archived package helper changed')
        if reader.fingerprint(app) != original or reader.fingerprint(copy) != original:
            raise RuntimeError('The verified app changed during packaging')
        publish_package(candidate, output)
        return {'schemaVersion': 1, 'packageSHA256': hashlib.sha256(output.read_bytes()).hexdigest(),
            'appFingerprint': original, 'trustedTeamID': team, 'packageProfile': pins, 'payloadEntries': count,
            'packageSigned': bool(installer_identity), 'unsignedDeveloperPackage': unsigned_developer,
            'notarizationTested': False, 'installed': False, 'rootExecutionTested': False,
            'originalAppUnchanged': True, 'servicesRegistered': False,
            'limits': ['Archive validation only. Native script ordering, recovery and visible app entry need interactive testing.',
                'Initial installation and same-build resume only. Updates require the coordinated update path.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True, help='Complete Developer ID signed app')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trusted-team', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--installer-identity', help='Explicit Developer ID Installer identity')
    group.add_argument('--unsigned-developer', action='store_true', help='Local archive experiment only; not a trusted distribution')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or os.geteuid() == 0:
        parser.error('Run without elevation on an Apple Silicon Mac')
    print(json.dumps(build(args.app.absolute(), args.output, args.trusted_team,
        installer_identity=args.installer_identity, unsigned_developer=args.unsigned_developer), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
