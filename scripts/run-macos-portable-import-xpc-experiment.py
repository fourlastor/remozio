#!/usr/bin/env python3
"""Check the anonymous import wire without installing a service or importing administrator rights."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

from macos_fixture_cleanup import retire_owned_tree

ROOT = Path(__file__).resolve().parents[1]
TEST = 'PortableSetupImportNativeTests.testLiveAnonymousImportWireRetainsAndRecoversWithoutRetry'
REQUIRED = ['guiSessionAvailable', 'sameProcessNativeConnection', 'testCodeHashRequirementApplied',
    'kernelPeerCredentialsChecked', 'invocationConnectionChecked', 'oldHandshakeRejected', 'wrongCodeHashRejected',
    'malformedRequestRejectedBeforeRights', 'refusedRightsLeaveStorageUnchanged', 'lostReplyCommittedPlanRecovered',
    'readbackDidNotRetryWrite', 'explicitRepeatPreservesPlan', 'crossedResultRejected']
UNPROVEN = ['installedRootAccountsTested', 'developerIDPolicyTested', 'realAdministratorAuthorizationTested',
    'providerAPICalled', 'serviceInstalled', 'realApprovalIssued']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True, help='Sanitized result file; the log is retained beside it')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or int(platform.mac_ver()[0].split('.')[0]) < 26:
        raise SystemExit('Requires Apple Silicon and macOS 26 or later.')
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    log = args.evidence.with_suffix('.log')
    if args.evidence == log:
        raise SystemExit('The evidence path must differ from its .log path.')
    if args.evidence.exists() or log.exists():
        raise SystemExit('Choose unused evidence and log paths to preserve earlier results.')
    coordination = ROOT / '.build/agent-checkpoints/native-validation-coordination.lock'
    coordination.parent.mkdir(parents=True, exist_ok=True)
    with coordination.open('a') as lock, tempfile.TemporaryDirectory(prefix='remozio-import-wire-') as directory:
        fcntl.flock(lock, fcntl.LOCK_EX)
        evidence = Path(directory) / 'evidence.json'
        environment = os.environ.copy()
        environment['REMOZIO_PORTABLE_IMPORT_XPC_EVIDENCE'] = str(evidence)
        with log.open('x') as output:
            process = subprocess.Popen(['/usr/bin/xcrun', 'swift', 'test', '--package-path', str(ROOT / 'macos/core'),
                '--triple', 'arm64-apple-macosx26.0', '--filter', TEST], cwd=ROOT, env=environment,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result = process.wait(timeout=300)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                raise SystemExit(f'Native import fixture did not finish. Diagnostics: {log}')
            finally:
                if process.poll() is None:
                    retire_owned_tree(process)
        # A skipped or headless test is not live evidence.
        if result or not evidence.is_file():
            raise SystemExit(f'Native import fixture failed or lacked a GUI session. Diagnostics: {log}')
        report = json.loads(evidence.read_text())
        if report.get('status') != 'passed' or not all(report.get(key) is True for key in REQUIRED):
            raise SystemExit(f'Native import fixture did not prove its required checks. Diagnostics: {log}')
        if not all(report.get(key) is False for key in UNPROVEN):
            raise SystemExit('Unexpected installed-service or authorization claim in fixture evidence.')
        report['sourceCommit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['sourceWorktreeModified'] = bool(subprocess.check_output(
            ['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True).strip())
        report['macOS26RuntimeQualified'] = int(platform.mac_ver()[0].split('.')[0]) == 26
        report['testSourceSHA256'] = hashlib.sha256((ROOT / 'macos/core/Tests/RemozioCoreTests/PortableSetupImportNativeTests.swift').read_bytes()).hexdigest()
        report['testLogSHA256'] = hashlib.sha256(log.read_bytes()).hexdigest()
        args.evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': 'passed', 'experiment': report['experiment'], 'evidence': str(args.evidence),
            'log': str(log), 'installedRootAccountsTested': False, 'realAdministratorAuthorizationTested': False}, sort_keys=True))


if __name__ == '__main__':
    main()
