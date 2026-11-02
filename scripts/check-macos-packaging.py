#!/usr/bin/env python3
"""Build and inspect a bundle without installing or registering its services."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import plistlib
import re
import shutil
import tempfile

from macos_build_checks import require, run, verify_executable

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build' / 'packaging'
ROLES = {
    'session': ('LaunchAgents', 'RemozioSessionProbe'),
    'authority': ('LaunchDaemons', 'RemozioAuthorityProbe'),
}


def check():
    BUILD.mkdir(parents=True, exist_ok=True)
    build = run('xcodebuild', '-project', str(ROOT / 'experiments/packaging/RemozioPackaging.xcodeproj'),
                '-scheme', 'RemozioPackaging', '-configuration', 'Release',
                '-destination', 'generic/platform=macOS', '-derivedDataPath', str(BUILD / 'DerivedData'),
                'build', check=False)
    log = BUILD / 'xcodebuild.log'
    log.write_text(build.stdout + build.stderr)
    require(build.returncode == 0 and not re.search(r'^error:', build.stdout + build.stderr, re.MULTILINE),
            f'Xcode build failed; see {log}')
    app = BUILD / 'DerivedData/Build/Products/Release/RemozioPackaging.app'
    run('codesign', '--verify', '--deep', '--strict', str(app))
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    require(info['LSMinimumSystemVersion'] == '26.0', 'Wrong app deployment target')
    verify_executable(app / 'Contents/MacOS/RemozioPackaging', 'dev.sebastiano.remozio.macos.experiments.app')
    for role, (folder, executable) in ROLES.items():
        relative_path = f'Contents/Helpers/{executable}'
        plist_path = app / f'Contents/Library/{folder}/dev.sebastiano.remozio.macos.experiments.{role}.plist'
        manifest = plistlib.loads(plist_path.read_bytes())
        expected = {'Label': f'dev.sebastiano.remozio.macos.experiments.{role}', 'BundleProgram': relative_path,
                    'ProgramArguments': [executable, '--describe'], 'RunAtLoad': False}
        if role == 'session':
            expected['LimitLoadToSessionType'] = 'Aqua'
        require(manifest == expected, f'{role}: unexpected launch manifest')
        binary = app / relative_path
        verify_executable(binary, f'dev.sebastiano.remozio.macos.experiments.{role}')
        require(json.loads(run(str(binary), '--describe').stdout) ==
                {'role': f'{role}-probe', 'capability': 'packaging-only'}, f'{role}: wrong probe')
        require(run(str(binary), check=False).returncode == 69, f'{role}: unexpected default behavior')

    for relative_path in ('Contents/Helpers/RemozioAuthorityProbe',
                          'Contents/Library/LaunchAgents/dev.sebastiano.remozio.macos.experiments.session.plist'):
        with tempfile.TemporaryDirectory(prefix='remozio-package-check-') as directory:
            copy = Path(directory) / app.name
            shutil.copytree(app, copy)
            run('codesign', '--verify', '--deep', '--strict', str(copy))
            with (copy / relative_path).open('ab') as handle:
                handle.write(b'\nremozio-tamper-probe\n')
            require(run('codesign', '--verify', '--deep', '--strict', str(copy), check=False).returncode != 0,
                    f'Tampering was not detected: {relative_path}')
    return {'recorded_at': datetime.now(timezone.utc).isoformat(),
            'os': run('sw_vers').stdout.strip(), 'xcode': run('xcodebuild', '-version').stdout.strip(),
            'architecture': 'arm64', 'deployment_target': '26.0', 'signing': 'ad-hoc',
            'checks': ['bundle layout', 'probe identities', 'hardened runtime', 'no privilege or debugging entitlements',
                       'probe descriptions', 'default refusal', 'nested-code tamper', 'resource tamper'],
            'services_registered': False, 'privileged_install_tested': False, 'notarization_tested': False,
            'update_replacement_tested': False, 'status': 'passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Write new evidence JSON; refuse to overwrite a file')
    args = parser.parse_args()
    report = check()
    if args.output:
        with args.output.open('x') as file:
            json.dump(report, file, indent=2)
            file.write('\n')
    print('Mac packaging: layout, identities, runtime, probe behavior, and tamper checks passed.')


if __name__ == '__main__':
    main()
