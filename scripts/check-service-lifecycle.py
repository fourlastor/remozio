#!/usr/bin/env python3
"""Build a disposable service harness. Never register or unregister services."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

from macos_build_checks import require, verify_executable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'experiments/service-lifecycle'
METADATA = ROOT / 'macos/core/Sources/RemozioCore/ProtectedStorageMetadata.swift'
APP_ID = 'dev.remozio.experiments.lifecycle'
ROLES = {'session': ('LaunchAgents', 'RemozioLifecycleSession'),
         'authority': ('LaunchDaemons', 'RemozioLifecycleAuthority')}


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} failed with {result.returncode}: {result.stderr[-2000:]}')
    return result


def manifest(role):
    folder, executable = ROLES[role]
    result = {'Label': f'{APP_ID}.{role}', 'BundleProgram': f'Contents/Helpers/{executable}',
              'ProgramArguments': [executable, '--service-probe'], 'RunAtLoad': True}
    if role == 'session':
        result['LimitLoadToSessionType'] = 'Aqua'
    else:
        result['UserName'] = 'root'
    return result


def sign(path, identity, identifier):
    args = ['codesign', '--force', '--options', 'runtime', '--sign', identity, '--identifier', identifier]
    if identity != '-':
        args.append('--timestamp')
    run(*args, str(path))


def build(app, identity):
    require(os.getuid() != 0 and os.getuid() == os.geteuid(), 'Run build checks as an ordinary account')
    require(not app.exists(), 'The output must not exist')
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/Helpers').mkdir()
    shared = [str(SOURCE / 'Preflight.swift'), str(METADATA)]
    common = ['xcrun', 'swiftc', '-swift-version', '6', '-target', 'arm64-apple-macosx26.0', '-parse-as-library']
    run(*common, str(SOURCE / 'Controller.swift'), *shared, '-o', str(app / 'Contents/MacOS/RemozioServiceLifecycle'))
    for role, (folder, executable) in ROLES.items():
        directory = app / 'Contents/Library' / folder
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f'{APP_ID}.{role}.plist').write_bytes(plistlib.dumps(manifest(role)))
        binary = app / 'Contents/Helpers' / executable
        run(*common, '-D', f'{role.upper()}_PROBE', str(SOURCE / 'Probe.swift'), *shared, '-o', str(binary))
        sign(binary, identity, f'{APP_ID}.{role}')
    info = {'CFBundleIdentifier': APP_ID, 'CFBundleName': 'Remozio service lifecycle experiment',
            'CFBundleExecutable': 'RemozioServiceLifecycle', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.0.1', 'LSMinimumSystemVersion': '26.0'}
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    sign(app, identity, APP_ID)
    run('codesign', '--verify', '--deep', '--strict', str(app))


def controls(app, identity):
    controller = app / 'Contents/MacOS/RemozioServiceLifecycle'
    verify_executable(controller, APP_ID)
    checks = []
    for role, (_, executable) in ROLES.items():
        binary = app / 'Contents/Helpers' / executable
        verify_executable(binary, f'{APP_ID}.{role}')
        require(json.loads(run(str(binary), '--describe').stdout) ==
                {'role': role, 'capability': 'service-lifecycle-only'}, 'Unexpected helper description')
        require(run(str(binary), check=False).returncode == 69, 'Default helper did not refuse')
        checks.append(f'{role}:description-and-default-refusal')
    authority = app / 'Contents/Helpers' / ROLES['authority'][1]
    require(run(str(authority), '--service-probe', check=False).returncode == 77, 'Authority accepted ordinary startup')
    checks.append('authority:ordinary-account-refusal')
    status = json.loads(run(str(controller), '--status').stdout)
    require(status['operationsAttempted'] is False, 'Status attempted a service operation')
    require(status['session'] in {'notRegistered', 'eligibleNotVerifiedRunning', 'requiresSystemApproval', 'notFound', 'unknown'}, 'Unknown status encoding')
    require(json.loads(run(str(controller), '--validate-manifests').stdout)['operationsAttempted'] is False,
            'Manifest inspection attempted a service operation')
    checks.extend(['read-only-status', 'exact-manifests'])
    # These confirmed register commands fail before reaching the framework because this app is user-owned.
    # Never invoke confirmed unregister: a valid signed copy could remove an existing experiment job.
    for args in [('--preflight',), ('--register', 'session'), ('--unregister', 'authority'),
                 ('--register', 'unknown', '--confirm-disposable-service-test'),
                 ('--register', 'session', '--confirm-disposable-service-test'),
                 ('--register', 'authority', '--confirm-disposable-service-test')]:
        result = run(str(controller), *args, check=False)
        require(result.returncode == 78 and not result.stdout, 'Unsafe experiment command did not refuse')
        require(str(app) not in result.stderr, 'Refusal disclosed the bundle path')
    checks.append('confirmation-account-and-protected-placement-refusals')
    if identity == '-':
        require(run(str(controller), '--validate-signing', check=False).returncode == 78, 'Ad-hoc code passed signing preflight')
        checks.append('ad-hoc-registration-signature-refusal')
    else:
        require(json.loads(run(str(controller), '--validate-publisher').stdout)['operationsAttempted'] is False,
                'Developer ID publisher validation attempted an operation')
        require(run(str(controller), '--validate-signing', check=False).returncode == 78,
                'A fresh unnotarized build passed notarization preflight')
        checks.extend(['developer-id-publisher-validation', 'unnotarized-registration-refusal'])
    for key, value in [('Label', 'dev.remozio.authority'), ('ProgramArguments', ['unexpected']),
                       ('UserName', 'nobody'), ('KeepAlive', True)]:
        with tempfile.TemporaryDirectory(prefix='remozio-service-mutation-') as temporary:
            copy = Path(temporary) / app.name
            shutil.copytree(app, copy)
            path = copy / f'Contents/Library/LaunchDaemons/{APP_ID}.authority.plist'
            changed = manifest('authority'); changed[key] = value
            path.write_bytes(plistlib.dumps(changed))
            sign(copy, '-', APP_ID)
            require(run(str(copy / 'Contents/MacOS/RemozioServiceLifecycle'), '--validate-manifests', check=False).returncode == 78,
                    f'Malformed manifest accepted: {key}')
    checks.append('altered-manifest-refusals')
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--developer-id', help='Explicitly sign the owned fixture; registration still requires notarization')
    parser.add_argument('--keep-output', type=Path, help='Keep a new app path; refuse to overwrite')
    parser.add_argument('--output', type=Path, help='Write a new sanitized evidence file')
    args = parser.parse_args()
    identity = args.developer_id or '-'
    with tempfile.TemporaryDirectory(prefix='remozio-service-build-') as temporary:
        app = Path(temporary) / 'RemozioServiceLifecycle.app'
        build(app, identity)
        checks = controls(app, identity)
        report = {'recordedAt': datetime.now(timezone.utc).isoformat(), 'os': run('sw_vers', '-productVersion').stdout.strip(),
                  'architecture': 'arm64', 'deploymentTarget': '26.0', 'swiftVersion': '6',
                  'signing': 'developer-id' if args.developer_id else 'ad-hoc', 'checks': checks,
                  'servicesRegistered': False, 'servicesUnregistered': False, 'rootInstalled': False,
                  'notarizationTested': False, 'bootTested': False, 'updateTested': False,
                  'dedicatedTransportAccountTested': False, 'status': 'passed',
                  'sourceSHA256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in [*sorted(SOURCE.glob('*.swift')), METADATA, Path(__file__).resolve()]}}
        if args.keep_output:
            require(not args.keep_output.exists() and not args.keep_output.is_symlink(), 'Kept output must be new')
            shutil.copytree(app, args.keep_output)
            run('codesign', '--verify', '--deep', '--strict', str(args.keep_output))
        if args.output:
            with args.output.open('x') as output:
                json.dump(report, output, indent=2); output.write('\n')
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
