#!/usr/bin/env python3
"""Check the owned connector and real loopback readiness client without a provider or installed service."""
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
TEST = 'RelayConnectorLoopbackTests.testOwnedProcessSupervisorAndHTTPReadinessSettleTogether'
REQUIRED = ['productionSpawnPrimitiveUsed', 'productionSupervisorUsed', 'productionHTTPReadinessUsed',
    'childBoundOnlyLoopback', 'disconnectedThenConnectedWithoutReplacement', 'mismatchedConnectorIdentityRefused',
    'scopeInvalidationStopsWithoutReplacement', 'pendingHTTPRequestConfirmedByChild',
    'concurrentCloseJoinedProcessAndProbe', 'updateExcludedBeforeShutdown', 'updateAllowedAfterSettlement']
UNPROVEN = ['installedNativeFactoryTested', 'dedicatedAccountAdmissionTested', 'developerIDPolicyTested',
    'realProviderConnectivityQualified', 'providerAPICalled', 'servicesInstalled', 'realCredentialUsed', 'physicalPhoneTested']
SOURCES = ['macos/core/Tests/RemozioCoreTests/RelayConnectorLoopbackTests.swift',
    'macos/core/Tests/RemozioCoreTests/Fixtures/relay-connector/worker.c']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True, help='Sanitized JSON result; its raw log is retained beside it')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or int(platform.mac_ver()[0].split('.')[0]) < 26:
        raise SystemExit('Requires Apple Silicon and macOS 26 or later.')
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit('Run as an ordinary user without elevation.')
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    log = args.evidence.with_suffix('.log')
    if args.evidence == log or args.evidence.exists() or log.exists():
        raise SystemExit('Choose separate, unused evidence and log paths.')
    coordination = ROOT / '.build/agent-checkpoints/native-validation-coordination.lock'
    coordination.parent.mkdir(parents=True, exist_ok=True)
    with coordination.open('a') as lock, tempfile.TemporaryDirectory(prefix='remozio-relay-loopback-') as directory:
        fcntl.flock(lock, fcntl.LOCK_EX)
        evidence = Path(directory) / 'evidence.json'
        hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
        environment = os.environ.copy()
        environment['REMOZIO_RELAY_LOOPBACK_EVIDENCE'] = str(evidence)
        with log.open('x') as output:
            process = subprocess.Popen(['/usr/bin/xcrun', 'swift', 'test', '--package-path', str(ROOT / 'macos/core'),
                '--triple', 'arm64-apple-macosx26.0', '--filter', TEST], cwd=ROOT, env=environment,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                result = process.wait(timeout=300)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                raise SystemExit(f'Owned loopback fixture did not finish. Diagnostics: {log}')
            finally:
                if process.poll() is None:
                    retire_owned_tree(process)
        if result or not evidence.is_file():
            raise SystemExit(f'Owned loopback fixture failed or produced no evidence. Diagnostics: {log}')
        if hashes != {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}:
            raise SystemExit('Fixture source changed during the experiment.')
        report = json.loads(evidence.read_text())
        if report.get('experiment') != 'relay-connector-owned-loopback' or report.get('status') != 'passed' or not all(
                report.get(key) is True for key in REQUIRED):
            raise SystemExit('The fixture did not prove its required checks.')
        if not all(report.get(key) is False for key in UNPROVEN):
            raise SystemExit('Unexpected installed-service, credential or provider claim.')
        report['sourceCommit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        report['sourceWorktreeModified'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip())
        report['sourceSHA256'] = hashes
        report['testLogSHA256'] = hashlib.sha256(log.read_bytes()).hexdigest()
        report['macOS26RuntimeQualified'] = int(platform.mac_ver()[0].split('.')[0]) == 26
        args.evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': 'passed', 'experiment': report['experiment'], 'evidence': str(args.evidence),
            'log': str(log), 'installedNativeFactoryTested': False, 'realProviderConnectivityQualified': False}, sort_keys=True))


if __name__ == '__main__':
    main()
