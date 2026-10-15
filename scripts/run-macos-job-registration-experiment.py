#!/usr/bin/env python3
"""Exercise only a temporary owned GUI job. Never registers a system job or changes production services."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    'macos/core/Sources/RemozioCore/BoundedNativeCommand.swift',
    'macos/core/Sources/RemozioCore/RuntimeJobRegistration.swift',
    'macos/core/Tests/RemozioCoreTests/LiveOwnedJobInspectionTests.swift',
    'scripts/run-macos-job-registration-experiment.py',
]
FACTS = {'unknownOwnedLabelAbsent', 'loadedFieldsMatchOriginal', 'sameLabelBootstrapRejected',
         'conflictDidNotReplaceOwnedJob', 'loadedConfigurationIndependentOfDisk', 'temporaryJobRemoved',
         'loadedEndpointSettingsMatch', 'loadedPropertiesMatch', 'changedFileRetainsLoadedEndpointsAndProperties'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'darwin' or platform.machine() != 'arm64' or os.getuid() == 0:
        raise SystemExit('Requires an ordinary Apple Silicon Mac GUI session')
    with args.output.open('x', encoding='utf-8') as output:
        report = {'schemaVersion': 1, 'experiment': 'owned-launchd-job-inspection',
                  'recordedAt': datetime.now(timezone.utc).isoformat(), 'status': 'running',
                  'macOS': subprocess.check_output(['/usr/bin/sw_vers', '-productVersion'], text=True).strip(),
                  'rootSystemDomainTested': False, 'nativeServiceUIDsTested': False, 'runtimeHealthTested': False,
                  'sourceSHA256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES}}
        try:
            result = subprocess.run(['swift', 'test', '--package-path', 'macos/core', '--triple', 'arm64-apple-macosx26.0',
                                     '--jobs', '4', '--disable-keychain', '--disable-netrc', '--filter',
                                     'LiveOwnedJobInspectionTests/testOwnedGUIJobReconciliation'], cwd=ROOT,
                                    env={**os.environ, 'REMOZIO_OWNED_JOB_PROBE': '1'}, text=True, capture_output=True, timeout=180)
            log = ROOT / '.build/agent-checkpoints/owned-job-inspection-live.log'
            log.write_text(result.stdout + result.stderr)
            lines = [l.removeprefix('REMOZIO_JOB_INSPECTION_EVIDENCE ') for l in result.stdout.splitlines()
                     if l.startswith('REMOZIO_JOB_INSPECTION_EVIDENCE ')]
            facts = json.loads(lines[0]) if len(lines) == 1 else {}
            report['cases'] = facts
            report['status'] = 'passed' if result.returncode == 0 and set(facts) == FACTS and all(v is True for v in facts.values()) else 'failed'
        except Exception as error:
            report['status'] = 'failed'; report['errorType'] = type(error).__name__
        json.dump(report, output, indent=2); output.write('\n')
    print(f"{report['status']}: {args.output}")
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
