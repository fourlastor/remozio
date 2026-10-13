#!/usr/bin/env python3
"""Build the disposable bootstrap app and run only modes that need no authorization."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

from macos_build_checks import require, run, verify_executable

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'experiments/protected-bootstrap'
BUILD = ROOT / '.build/protected-bootstrap'
IDENTITY = 'dev.remozio.experiments.bootstrap'
ENTITLEMENT = 'com.apple.developer.security.privileged-file-operations'


def check_report(report):
    require(report.get('schemaVersion') == 1, 'Unknown bootstrap evidence version')
    for field in ('administratorAuthorizationRequested', 'privilegedFileManagerTested', 'productionProtectedInstallationTested'):
        require(report.get(field) is False, 'Ordinary evidence must not claim privileged behavior')
    require(report.get('fixtureRootRemoved') is True, 'Ordinary fixture cleanup was not verified')
    rows = report.get('results')
    names = ['replace-existing-file', 'replace-missing-file', 'replace-existing-directory',
             'replace-missing-directory', 'replace-under-missing-parent']
    require(isinstance(rows, list) and [r.get('case') for r in rows] == names, 'Missing or reordered ordinary cases')
    for index, row in enumerate(rows[:4]):
        require(row.get('operationReturnedSuccess') is True and row.get('replacementBytesPresent') is True,
                'Replacement did not produce the fixture bytes')
        require(row.get('sourceRemains') is False and row.get('returnedDestination') is True, 'Replacement did not consume its source')
        after = row.get('after')
        require(isinstance(after, dict) and after.get('ownerUID') == os.getuid(), 'Ordinary probe changed ownership')
        require(after.get('directory') is (index >= 2), 'Replacement changed the expected object type')
        expected_mode = (0o600, 0o640, 0o700, 0o750)[index]
        require(after.get('mode') == expected_mode, 'Replacement permission behavior changed')
        if index in (0, 2):
            require(after.get('mode') == row.get('before', {}).get('mode'), 'Replacement discarded destination permissions')
        else:
            require(row.get('before') is None, 'Absent-target case had a pre-existing destination')
    missing = rows[-1]
    require(missing.get('operationReturnedSuccess') is False and missing.get('sourceRemains') is True
            and missing.get('after') is None and missing.get('replacementBytesPresent') is False,
            'Missing-parent refusal altered the fixture')


def profile_entitlements(profile, signing_identity, team_id, now=None):
    """Validate decoded profile fields only. Platform signing and execution must validate authorization separately."""
    require(len(signing_identity) == 40 and all(c in '0123456789abcdefABCDEF' for c in signing_identity), 'Use a certificate SHA-1 identity')
    require(len(team_id) == 10 and team_id.isascii() and team_id.isalnum() and team_id.upper() == team_id, 'Invalid Team ID')
    require(isinstance(profile, dict) and profile.get('TeamIdentifier') == [team_id], 'Profile belongs to another team')
    platforms = profile.get('Platform')
    require(isinstance(platforms, list) and 'OSX' in platforms, 'Profile does not target macOS')
    expiration = profile.get('ExpirationDate')
    require(isinstance(expiration, datetime), 'Profile has no expiration')
    expiration = expiration.replace(tzinfo=timezone.utc) if expiration.tzinfo is None else expiration
    require(expiration > (now or datetime.now(timezone.utc)), 'Profile expired')
    certs = profile.get('DeveloperCertificates')
    require(isinstance(certs, list) and any(isinstance(c, bytes) and hashlib.sha1(c).hexdigest().upper() == signing_identity.upper() for c in certs),
            'Profile does not authorize the selected certificate')
    values = profile.get('Entitlements')
    require(isinstance(values, dict) and values.get(ENTITLEMENT) is True, 'Profile lacks the approved privileged file operations entitlement')
    app = values.get('com.apple.application-identifier')
    suffix = '.' + IDENTITY
    require(isinstance(app, str) and app.endswith(suffix), 'Profile is not bound to this probe app')
    prefixes = profile.get('ApplicationIdentifierPrefix')
    require(isinstance(prefixes, list) and prefixes and all(isinstance(p, str) and p for p in prefixes),
            'Profile has no valid App ID prefixes')
    require(app[:-len(suffix)] in prefixes, 'Profile application identifier has an unapproved prefix')
    expected = plistlib.loads((PACKAGE / 'PrivilegedFiles.entitlements').read_bytes())
    require(expected == {ENTITLEMENT: True} and expected[ENTITLEMENT] is True, 'Unexpected probe entitlement declaration')
    expected['com.apple.application-identifier'] = app
    if 'com.apple.developer.team-identifier' in values:
        require(values['com.apple.developer.team-identifier'] == team_id, 'Profile entitlement team differs')
        expected['com.apple.developer.team-identifier'] = team_id
    return expected


def check(signing_identity=None, provisioning_profile=None, team_id=None):
    BUILD.mkdir(parents=True, exist_ok=True)
    args = ('swift', 'build', '--package-path', str(PACKAGE), '--triple', 'arm64-apple-macosx26.0', '--disable-keychain', '--disable-netrc')
    built = run(*args, check=False)
    (BUILD / 'build.log').write_text(built.stdout + built.stderr)
    require(built.returncode == 0, f'Bootstrap experiment build failed; see {BUILD / "build.log"}')
    directory = Path(run(*args, '--show-bin-path').stdout.strip().splitlines()[-1])
    interactive = signing_identity is not None
    expected = None
    if interactive:
        require(provisioning_profile is not None and team_id is not None, 'Interactive signing requires identity, profile and team')
        require(provisioning_profile.is_file() and provisioning_profile.stat().st_size <= 1_048_576, 'Missing or oversized profile')
        decoded = run('security', 'cms', '-D', '-i', str(provisioning_profile)).stdout
        expected = profile_entitlements(plistlib.loads(decoded.encode()), signing_identity, team_id)
    app = BUILD / ('RemozioBootstrapProbeInteractive.app' if interactive else 'RemozioBootstrapProbe.app')
    contents = app / 'Contents'
    (contents / 'MacOS').mkdir(parents=True, exist_ok=True)
    executable = contents / 'MacOS/remozio-bootstrap-probe'
    shutil.copy2(directory / 'remozio-bootstrap-probe', executable)
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': IDENTITY, 'CFBundleName': 'Remozio Bootstrap Experiment',
        'CFBundleExecutable': executable.name, 'CFBundlePackageType': 'APPL',
        'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1.0', 'LSMinimumSystemVersion': '26.0'}))
    if interactive:
        shutil.copy2(provisioning_profile, contents / 'embedded.provisionprofile')
        entitlement_path = BUILD / 'interactive.entitlements'
        entitlement_path.write_bytes(plistlib.dumps(expected))
        run('codesign', '--force', '--sign', signing_identity, '--options', 'runtime', '--timestamp',
            '--entitlements', str(entitlement_path), str(app))
        run('codesign', '--verify', '--strict', '-R', '=anchor apple generic and identifier "' + IDENTITY + '"', str(app))
    else:
        run('codesign', '--force', '--sign', '-', '--options', 'runtime', str(app))
    verify_executable(executable, IDENTITY, expected_entitlements=expected)
    run('codesign', '--verify', '--strict', str(app))
    describe = json.loads(subprocess.run([str(executable), '--describe'], check=True, capture_output=True, text=True, timeout=10).stdout)
    require(describe == {'schemaVersion': 1, 'capability': 'disposable-bootstrap-file-experiment',
                         'defaultPrompts': False, 'productionInstallation': False, 'interactiveSigningPresent': interactive}, 'Unexpected bootstrap capability')
    for arguments in ([], ['--authorize-file-operations'], ['--confirm-disposable-only'],
                      ['--authorize-file-operations', '--confirm-disposable-only', '/private/invalid-probe-target']):
        read_fd, write_fd = os.pipe()
        try:
            marker = b'unread bootstrap input\x00\xff'
            os.write(write_fd, marker); os.close(write_fd); write_fd = -1
            refused = subprocess.run([str(executable), *arguments], stdin=read_fd, capture_output=True, timeout=10)
            require(refused.returncode == 64 and not refused.stdout, 'Probe did not refuse incomplete interactive confirmation')
            require(os.read(read_fd, len(marker)) == marker, 'Refusal consumed stdin')
            require(b'/private/invalid-probe-target' not in refused.stderr, 'Refusal logged a supplied private argument')
        finally:
            os.close(read_fd)
            if write_fd >= 0: os.close(write_fd)
    if not interactive:
        refused = subprocess.run([str(executable), '--authorize-file-operations', '--confirm-disposable-only'],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        require(refused.returncode == 78 and not refused.stdout, 'Ordinary artifact did not refuse unapproved interactive signing')
    preflight = json.loads(subprocess.run([str(executable), '--preflight'], check=True, capture_output=True, text=True, timeout=10).stdout)
    require(preflight.get('schemaVersion') == 1 and preflight.get('authorizationRequested') is False,
            'Read-only preflight claimed authorization')
    require(type(preflight.get('protectedParentAccepted')) is bool, 'Preflight did not report its scope result')
    report = json.loads(subprocess.run([str(executable), '--ordinary'], check=True, capture_output=True, text=True, timeout=10).stdout)
    check_report(report)
    report.update(recordedAt=datetime.now(timezone.utc).isoformat(), signing='Apple-profile-provided' if interactive else 'ad-hoc', protectedParentPreflight=preflight,
                  interactiveModeRun=False, actualPromptCount=None,
                  sourceSHA256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((PACKAGE / 'Sources').rglob('*.swift'))})
    (BUILD / ('interactive-signing-evidence.json' if interactive else 'ordinary-evidence.json')).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('Bootstrap file experiment: five ordinary cases, read-only scope, signature and confirmation refusals passed. Interactive mode was not run.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interactive-signing-identity')
    parser.add_argument('--provisioning-profile', type=Path)
    parser.add_argument('--team-id')
    options = parser.parse_args()
    selected = [options.interactive_signing_identity, options.provisioning_profile, options.team_id]
    if any(v is not None for v in selected) and not all(v is not None for v in selected):
        parser.error('Interactive signing requires all three signing arguments')
    check(*selected)
