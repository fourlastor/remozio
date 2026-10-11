"""Sign only disposable, owned Sparkle fixtures with an explicit identity."""
import base64
from dataclasses import dataclass
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import shutil
import tempfile
import json


@dataclass(frozen=True)
class SigningConfig:
    identity: str
    team: str

    def __post_init__(self):
        if not re.fullmatch(r'[0-9A-F]{40}', self.identity):
            raise ValueError('Use an explicit certificate fingerprint')
        if not re.fullmatch(r'[A-Z0-9]{10}', self.team):
            raise ValueError('Use an explicit trusted Team ID')


def owned_root(root):
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Only an ordinary account can run this fixture')
    root = Path(root)
    metadata = root.lstat()
    if (root != root.resolve(strict=True) or not root.name.startswith('remozio-sparkle-boundary-')
            or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError('Use an owned canonical fixture directory')
    return root


def owned_file(root, path):
    root = owned_root(root)
    path = Path(path)
    metadata = path.lstat()
    if (path != path.resolve(strict=True) or not path.is_relative_to(root)
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1):
        raise ValueError('Use a regular owned fixture file')
    return path


def thin_file(boundary, root, path):
    path = owned_file(root, path)
    architectures = boundary.command('/usr/bin/lipo', '-archs', path).decode().split()
    if architectures == ['arm64']:
        return
    if set(architectures) != {'x86_64', 'arm64'} or len(architectures) != 2:
        raise ValueError('Unexpected fixture architecture')
    output = path.with_name(path.name + '.probe-thin')
    if output.exists() or output.is_symlink():
        raise ValueError('Thinning must not overwrite an existing file')
    try:
        boundary.command('/usr/bin/lipo', path, '-thin', 'arm64', '-output', output)
        owned_file(root, output)
        output.replace(path)
    finally:
        if output.exists() or output.is_symlink():
            output.unlink()
    if boundary.command('/usr/bin/lipo', '-archs', path).decode().strip() != 'arm64':
        raise ValueError('Fixture thinning did not produce arm64 code')


def signature(boundary, path, identifier, config, expected_entitlements):
    expression = ('identifier "' + identifier + '" and anchor apple generic '
                  'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                  'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                  'and certificate leaf[subject.OU] = "' + config.team + '"')
    check = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + expression, str(path)], capture_output=True, text=True, timeout=10)
    if check.returncode:
        detail = check.stderr.replace(str(path), '<owned fixture>')[:1024]
        raise ValueError(f'Explicit fixture requirement failed for {identifier}: {detail}')
    result = subprocess.run(['/usr/bin/codesign', '-d', '--verbose=4', '--entitlements', ':-', str(path)],
                            capture_output=True, timeout=10)
    metadata = result.stderr.decode(errors='replace').splitlines()
    values = dict(line.split('=', 1) for line in metadata if '=' in line)
    flags = next((re.search(r'flags=(0x[0-9a-fA-F]+)', line) for line in metadata
                  if line.startswith('CodeDirectory ')), None)
    entitlements = plistlib.loads(result.stdout) if result.stdout else {}
    if (result.returncode or values.get('TeamIdentifier') != config.team
            or values.get('Identifier') != identifier or flags is None
            or int(flags.group(1), 16) & 0x10000 == 0
            or entitlements != expected_entitlements):
        raise ValueError('Fixture signature or entitlement mismatch')


class SDKFixtureSigner:
    def __init__(self, boundary, config):
        self.boundary = boundary
        self.base_bundle = boundary.bundle
        self.config = config

    def bundle(self, root, directory, products, identity, version, public_key, port):
        root = owned_root(root)
        if (directory not in ['Signer', 'Host', 'Candidate'] or version not in [1, 2]
                or not re.fullmatch(r'dev\.remozio\.experiment\.sparkleboundary\.[0-9a-f]{32}', identity)
                or not isinstance(port, int) or not 1 <= port <= 65535):
            raise ValueError('Invalid disposable fixture declaration')
        if len(base64.b64decode(public_key, validate=True)) != 32:
            raise ValueError('Invalid disposable signing public key')
        boundary = self.boundary
        app = self.base_bundle(root, directory, products, identity, version, public_key, port)
        boundary.validate_tree(root, app)
        framework = app / 'Contents/Frameworks/Sparkle.framework'
        base = framework / 'Versions/B'
        info = plistlib.loads((base / 'Resources/Info.plist').read_bytes())
        if info.get('CFBundleIdentifier') != 'org.sparkle-project.Sparkle' or info.get('CFBundleShortVersionString') != '2.10.0':
            raise ValueError('The fixture requires pinned Sparkle 2.10.0')
        declarations = [
            ('XPCServices/Downloader.xpc', 'XPCServices/Downloader.xpc/Contents/MacOS/Downloader', 'org.sparkle-project.DownloaderService'),
            ('XPCServices/Installer.xpc', 'XPCServices/Installer.xpc/Contents/MacOS/Installer', 'org.sparkle-project.InstallerLauncher'),
            ('Updater.app', 'Updater.app/Contents/MacOS/Updater', 'org.sparkle-project.Sparkle.Updater'),
            ('Autoupdate', 'Autoupdate', 'org.sparkle-project.Sparkle.Autoupdate'),
        ]
        code = [(base / target, base / binary, identifier) for target, binary, identifier in declarations]
        code.append((framework, base / 'Sparkle', 'org.sparkle-project.Sparkle'))
        for _, binary, _ in code:
            thin_file(boundary, root, binary)
        for index, (target, _, identifier) in enumerate(code):
            entitlements = {'com.apple.application-identifier': self.config.team + '.' + identifier} if target == base / 'Autoupdate' else {}
            declaration = root / directory / f'fixture-entitlements-{index}.plist'
            declaration.write_bytes(plistlib.dumps(entitlements))
            boundary.command('/usr/bin/codesign', '--force', '--sign', self.config.identity,
                             '--options', 'runtime', '--timestamp=none', '--identifier', identifier,
                             '--entitlements', declaration, target)
            signature(boundary, target, identifier, self.config, entitlements)
        declaration = root / directory / 'fixture-app-entitlements.plist'
        declaration.write_bytes(plistlib.dumps({}))
        boundary.command('/usr/bin/codesign', '--force', '--sign', self.config.identity,
                         '--options', 'runtime', '--timestamp=none', '--identifier', identity,
                         '--entitlements', declaration, app)
        signature(boundary, app, identity, self.config, {})
        boundary.command('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
        boundary.validate_tree(root, app)
        if boundary.command('/usr/bin/lipo', '-archs', app / 'Contents/MacOS/SparkleBoundaryProbe').decode().strip() != 'arm64':
            raise ValueError('The fixture host must also contain only arm64 code')
        return app


def entitlement_controls(boundary, config, products):
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError('Only an ordinary account can run these controls')
    source = (products / 'Sparkle.framework').resolve() / 'Versions/B/Autoupdate'
    identifier = 'org.sparkle-project.Sparkle.Autoupdate'
    application = {'com.apple.application-identifier': config.team + '.' + identifier}
    team = {'com.apple.developer.team-identifier': config.team}
    variants = {'none': {}, 'teamOnly': team, 'applicationOnly': application, 'both': team | application}
    with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
        root = owned_root(Path(temporary).resolve())
        for name, entitlements in variants.items():
            directory = root / name
            directory.mkdir()
            code = directory / 'Autoupdate'
            shutil.copy2(source, code)
            boundary.validate_tree(root, directory)
            thin_file(boundary, root, code)
            declaration = directory / 'entitlements.plist'
            declaration.write_bytes(plistlib.dumps(entitlements))
            boundary.command('/usr/bin/codesign', '--force', '--sign', config.identity,
                             '--options', 'runtime', '--timestamp=none', '--identifier', identifier,
                             '--entitlements', declaration, code)
            signature(boundary, code, identifier, config, entitlements)
            # The pinned utility returns 1 before creating an installer when it has no arguments.
            result = subprocess.run([str(code)], capture_output=True, timeout=5)
            if result.returncode not in [1, -9] or result.stdout or result.stderr:
                raise ValueError('Unexpected fixture argument-guard outcome')
            print(json.dumps({'control': name, 'strictSignatureValid': True,
                              'developerIDTeamVerified': True, 'architecture': 'arm64',
                              'noArgumentExit': result.returncode,
                              'expectedArgumentGuardReached': result.returncode == 1,
                              'installerOrJobStarted': False, 'profileProvided': False}), flush=True)
