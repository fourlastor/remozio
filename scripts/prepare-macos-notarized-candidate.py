#!/usr/bin/env python3
"""Prepare, submit, reconcile and package one local notarized app candidate."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = ('scripts/prepare-macos-notarized-candidate.py',
    'scripts/run-macos-release-signing-experiment.py', 'scripts/build-macos-package.py',
    'scripts/generate-macos-release-manifest.py')


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native(arguments, *, timeout=120, umask=0o077):
    try:
        result = subprocess.run([str(a) for a in arguments], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout, umask=umask,
            env={**os.environ, 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'{Path(arguments[0]).name} timed out; outcome unknown') from None
    if result.returncode:
        raise RuntimeError(f'{Path(arguments[0]).name} failed with status {result.returncode}')
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise RuntimeError('The tool response exceeds the evidence limit')
    return result


def sha256(path):
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
        return digest.hexdigest()


def regular(path, *, private=False):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid() or value.st_nlink != 1 or \
       value.st_mode & 0o022 or (private and stat.S_IMODE(value.st_mode) != 0o600):
        raise ValueError('The workspace file has unsafe ownership, permissions or type')
    return value


def save(folder, value):
    value['recordedAtUTC'] = datetime.now(timezone.utc).isoformat()
    data = json.dumps(value, indent=2, sort_keys=True).encode() + b'\n'
    if len(data) > 32768:
        raise ValueError('The journal exceeds the evidence limit')
    with tempfile.NamedTemporaryFile(dir=folder, prefix='.journal-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, folder / 'journal.json')
        finally:
            temporary.unlink(missing_ok=True)
    descriptor = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


@contextmanager
def workspace(folder, *, create=False):
    if create:
        folder.mkdir(mode=0o700)
    value = folder.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise ValueError('Use a private owned workspace without an alias')
    descriptor = os.open(folder / 'writer.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        regular(folder / 'writer.lock', private=True)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def source_identity():
    native(['git', '-C', ROOT, 'ls-files', '--error-unmatch', *SOURCE_FILES])
    if native(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=no']).stdout.strip():
        raise ValueError('Commit the source before preparing a notarization candidate')
    return {'commit': native(['git', '-C', ROOT, 'rev-parse', 'HEAD']).stdout.strip(),
        'tree': native(['git', '-C', ROOT, 'rev-parse', 'HEAD^{tree}']).stdout.strip(),
        'scripts': {name: sha256(ROOT / name) for name in SOURCE_FILES}}


def probe():
    arguments = ['swift', 'build', '--package-path', ROOT / 'experiments/release-signing',
        '--scratch-path', ROOT / '.build/release-signing', '--triple', 'arm64-apple-macosx26.0',
        '--disable-keychain', '--disable-netrc']
    native(arguments, timeout=300)
    return Path(native([*arguments, '--show-bin-path']).stdout.strip()) / 'ReleaseSigningProbe'


def verify_signed_app(app, team):
    reader = load_script('run-macos-release-signing-experiment')
    before = reader.fingerprint(app)
    native(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
    for role, _, relative, *_ in reader.load_manifest().COMPONENTS:
        target = app if role == 1 else app / relative
        text = native(['/usr/bin/codesign', '--display', '--verbose=4', target]).stderr
        timestamp = re.search(r'^Timestamp=(\S.+)$', text, re.MULTILINE)
        if not timestamp or timestamp.group(1).lower() in ('none', 'not set') or \
           not re.search(r'^TeamIdentifier=' + re.escape(team) + r'$', text, re.MULTILINE) or \
           not re.search(r'^CodeDirectory .*flags=.*\bruntime\b', text, re.MULTILINE):
            raise ValueError('Every component needs the trusted publisher, hardened runtime and a secure timestamp')
    inspected = reader.inspect(probe(), app, team, True)
    if reader.fingerprint(app) != before:
        raise RuntimeError('The signed app changed during inspection')
    return before, inspected


def prepare(folder, app, team):
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('Supply the independently trusted Team ID')
    source = source_identity()
    reader = load_script('run-macos-release-signing-experiment')
    original = reader.fingerprint(app)
    with workspace(folder, create=True):
        value = {'schemaVersion': 1, 'phase': 'preparing', 'source': source, 'trustedTeamID': team,
            'archiveName': 'Remozio-' + str(uuid.uuid4()) + '.zip', 'installed': False,
            'servicesRegistered': False, 'packageSigned': False, 'appNotarizationVerified': False}
        save(folder, value)
        try:
            candidate = folder / 'Remozio.app'
            shutil.copytree(app, candidate, symlinks=True)
            fingerprint, inspected = verify_signed_app(candidate, team)
            if fingerprint != original or reader.fingerprint(app) != original:
                raise RuntimeError('The app changed while preparing the submission')
            archive = folder / value['archiveName']
            native(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', candidate, archive])
            regular(archive, private=True)
            if reader.fingerprint(candidate) != fingerprint:
                raise RuntimeError('The candidate changed while archiving')
            value.update(phase='prepared', appFingerprint=fingerprint, releaseInspection=inspected,
                archiveSHA256=sha256(archive))
            save(folder, value)
        except Exception:
            value['phase'] = 'preparation-failed'; save(folder, value)
            raise
    return value


def read_journal(folder):
    journal = folder / 'journal.json'
    if regular(journal, private=True).st_size > 32768:
        raise ValueError('The journal exceeds the evidence limit')
    value = json.loads(journal.read_text())
    if value.get('schemaVersion') != 1 or value['source'] != source_identity():
        raise ValueError('The workspace belongs to different source; preserve it for inspection')
    if value['phase'] in ('preparing', 'preparation-failed'):
        raise ValueError('Candidate preparation did not complete; preserve the workspace')
    name = value['archiveName']
    if not re.fullmatch(r'Remozio-[0-9a-f-]{36}\.zip', name):
        raise ValueError('The submission archive name is invalid')
    regular(folder / name, private=True)
    if sha256(folder / name) != value['archiveSHA256']:
        raise ValueError('The submission archive changed')
    return value


def response(result, *, require_status=True):
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, dict): raise ValueError()
        value['id'] = str(uuid.UUID(value['id']))
        if value.get('status') not in ('In Progress', 'Accepted', 'Invalid', 'Rejected'):
            if require_status: raise ValueError()
            value['status'] = 'Unknown'
        return value
    except (ValueError, KeyError, TypeError, AttributeError):
        raise RuntimeError('The notary service returned an invalid response') from None


def submit(folder, profile):
    with workspace(folder):
        value = read_journal(folder)
        if value['phase'] != 'prepared':
            raise ValueError('This candidate already has a submission attempt; reconcile its status instead')
        value['phase'] = 'submission-unknown'; save(folder, value)
        # Persist uncertainty before upload. A timeout or crash must never permit a second submission.
        result = response(native(['/usr/bin/xcrun', 'notarytool', 'submit', folder / value['archiveName'],
            '--keychain-profile', profile, '--output-format', 'json', '--no-wait']), require_status=False)
        value.update(phase='submitted', submissionID=result['id'], lastStatus=result['status'])
        save(folder, value)
    return value


def status(folder, profile, submission_id=None):
    with workspace(folder):
        value = read_journal(folder)
        if value['phase'] in ('preparing', 'preparation-failed', 'prepared'):
            raise ValueError('This candidate has no submission attempt to reconcile')
        recorded = value.get('submissionID')
        identity = str(uuid.UUID(submission_id)) if submission_id else recorded
        if not identity or (recorded and identity != recorded):
            raise ValueError('Use the recorded submission ID, or recover the unknown ID from authenticated notary history')
        result = response(native(['/usr/bin/xcrun', 'notarytool', 'info', identity,
            '--keychain-profile', profile, '--output-format', 'json']))
        if result['id'] != identity or result.get('name') != value['archiveName']:
            raise ValueError('The authenticated submission does not match this candidate')
        value.update(submissionID=identity, lastStatus=result['status'])
        if value['phase'] in ('submission-unknown', 'submitted', 'in-progress', 'accepted', 'rejected'):
            value['phase'] = {'Accepted': 'accepted', 'In Progress': 'in-progress'}.get(result['status'], 'rejected')
        save(folder, value)
    return value


def finish(folder):
    with workspace(folder):
        value = read_journal(folder)
        if value['phase'] != 'accepted' or value.get('lastStatus') != 'Accepted':
            raise ValueError('Reconcile an accepted submission before finishing this candidate')
        reader = load_script('run-macos-release-signing-experiment')
        original = folder / 'Remozio.app'
        if reader.fingerprint(original) != value['appFingerprint']:
            raise ValueError('The submitted app changed')
        value['phase'] = 'finishing-unknown'; save(folder, value)
        candidate = folder / 'Remozio-notarized.app'
        shutil.copytree(original, candidate, symlinks=True)
        if reader.fingerprint(candidate) != value['appFingerprint']:
            raise RuntimeError('The app changed while copying for stapling')
        # Stapler creates a public app resource. Keep the journal private and scope 022 to this child.
        value['finishStage'] = 'staple'; save(folder, value)
        native(['/usr/bin/xcrun', 'stapler', 'staple', candidate], umask=0o022)
        native(['/usr/bin/xcrun', 'stapler', 'validate', candidate])
        ticket = candidate / 'Contents/CodeResources'
        if not stat.S_ISREG(ticket.lstat().st_mode) or stat.S_IMODE(ticket.lstat().st_mode) != 0o644:
            raise ValueError('The stapled ticket must be an ordinary readable app resource')
        value['finishStage'] = 'inspect-stapled-app'; save(folder, value)
        fingerprint, inspected = verify_signed_app(candidate, value['trustedTeamID'])
        if inspected['packageProfile'] != value['releaseInspection']['packageProfile']:
            raise RuntimeError('Stapling changed the accepted release identity')
        native(['/usr/sbin/spctl', '--assess', '--type', 'execute', candidate])
        value['finishStage'] = 'build-package'; save(folder, value)
        package = folder / 'Remozio-developer.pkg'
        built = load_script('build-macos-package').build(candidate, package, value['trustedTeamID'], unsigned_developer=True)
        if built['appFingerprint'] != fingerprint or built['packageProfile'] != value['releaseInspection']['packageProfile']:
            raise RuntimeError('The packaged app differs from the accepted release')
        value['finishStage'] = 'verify-package-round-trip'; save(folder, value)
        expanded = folder / 'expanded-package'
        native(['/usr/sbin/pkgutil', '--expand-full', package, expanded])
        extracted = expanded / 'payload.pkg/Payload/Remozio.app'
        if reader.fingerprint(extracted) != fingerprint or reader.fingerprint(original) != value['appFingerprint']:
            raise RuntimeError('The package round trip changed the verified app')
        native(['/usr/bin/xcrun', 'stapler', 'validate', extracted])
        verify_signed_app(extracted, value['trustedTeamID'])
        native(['/usr/sbin/spctl', '--assess', '--type', 'execute', extracted])
        value.update(phase='complete', finishStage='complete', appNotarizationVerified=True, stapledAppFingerprint=fingerprint,
            packageSHA256=sha256(package), packageProfile=built['packageProfile'],
            packageRoundTripVerified=True, ticketMode='0644', strictSignaturesVerified=True,
            gatekeeperAccepted=True, packageNotarizationVerified=False)
        save(folder, value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'submit', 'status', 'finish'):
        command = commands.add_parser(name)
        command.add_argument('--workspace', type=Path, required=True)
        if name == 'prepare':
            command.add_argument('--app', type=Path, required=True)
            command.add_argument('--trusted-team', required=True)
        if name in ('submit', 'status'):
            command.add_argument('--keychain-profile', required=True)
        if name == 'status':
            command.add_argument('--submission-id', help='Only for a lost upload response; recover from authenticated history')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or os.geteuid() == 0:
        parser.error('Run without elevation on an Apple Silicon Mac')
    try:
        folder = args.workspace.absolute()
        if args.command == 'prepare': value = prepare(folder, args.app.absolute(), args.trusted_team)
        elif args.command == 'submit': value = submit(folder, args.keychain_profile)
        elif args.command == 'status': value = status(folder, args.keychain_profile, args.submission_id)
        else: value = finish(folder)
        print(json.dumps(value, indent=2, sort_keys=True))
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        # Raw tool output can contain account data. Retain the workspace and report a bounded outcome only.
        print('Candidate preparation stopped. Preserve the workspace; do not resubmit an unknown upload.', file=sys.stderr)
        if isinstance(error, (ValueError, RuntimeError)):
            print(str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
