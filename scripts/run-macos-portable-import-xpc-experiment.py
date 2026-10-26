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
ACTIVITY_TEST = 'PortableSetupImportNativeTests.testNativeCancellationKeepsUpdateExcludedUntilOwnedWorkSettles'
REPLY_TEST = 'PortableSetupImportNativeTests.testNativeReplyBoundaryExcludesUpdateAfterWorkAndPeerInvalidation'
REPLY_REQUIRED = ['guiSessionAvailable', 'sameProcessNativeConnection', 'testCodeHashRequirementApplied',
    'kernelPeerCredentialsChecked', 'invocationConnectionChecked', 'committedPlanObservedBeforeReplyReturn',
    'boundResultObservedBeforeReplyReturn', 'replyHoldExcludesUpdate', 'replyHoldPreventsOwnerClose',
    'peerInvalidationObservedBeforeReplyReturn', 'cancelledClientDoesNotReleaseReplyActivity',
    'returnedReplyAllowsUpdate', 'normalAndCancelledVariantsPassed', 'replyCallbackBoundaryTested',
    'clientConfirmedBeforeCallbackReturn', 'deliveredReplyStillExcludesUpdate']
ACTIVITY_REQUIRED = ['guiSessionAvailable', 'sameProcessNativeConnection', 'testCodeHashRequirementApplied',
    'kernelPeerCredentialsChecked', 'invocationConnectionChecked', 'idleConnectionAllowsUpdate', 'admittedWorkExcludesUpdate',
    'peerInvalidationObservedBeforeSettlement', 'cancelledClientDoesNotReleaseOwnedActivity', 'settledOwnerAllowsUpdate',
    'cancellationOutcomeNotAssumed']
REQUIRED = ['guiSessionAvailable', 'sameProcessNativeConnection', 'testCodeHashRequirementApplied',
    'kernelPeerCredentialsChecked', 'invocationConnectionChecked', 'oldHandshakeRejected', 'wrongCodeHashRejected',
    'malformedRequestRejectedBeforeRights', 'refusedRightsLeaveStorageUnchanged', 'lostReplyCommittedPlanRecovered',
    'readbackDidNotRetryWrite', 'explicitRepeatPreservesPlan', 'crossedResultRejected']
UNPROVEN = ['installedRootAccountsTested', 'developerIDPolicyTested', 'realAdministratorAuthorizationTested',
    'providerAPICalled', 'serviceInstalled', 'realApprovalIssued']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True, help='Sanitized result file; the log is retained beside it')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--activity', action='store_true', help='Check update exclusion through native cancellation and owned settlement')
    modes.add_argument('--reply-boundary', action='store_true', help='Hold the native reply after completed work and check update exclusion')
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
        if args.reply_boundary:
            variable, test, expected_experiment, required = 'REMOZIO_PORTABLE_IMPORT_REPLY_XPC_EVIDENCE', REPLY_TEST, 'portable-import-native-xpc-reply-boundary', REPLY_REQUIRED
        elif args.activity:
            variable, test, expected_experiment, required = 'REMOZIO_PORTABLE_IMPORT_ACTIVITY_XPC_EVIDENCE', ACTIVITY_TEST, 'portable-import-native-xpc-activity', ACTIVITY_REQUIRED
        else:
            variable, test, expected_experiment, required = 'REMOZIO_PORTABLE_IMPORT_XPC_EVIDENCE', TEST, 'portable-import-native-xpc', REQUIRED
        environment[variable] = str(evidence)
        with log.open('x') as output:
            process = subprocess.Popen(['/usr/bin/xcrun', 'swift', 'test', '--package-path', str(ROOT / 'macos/core'),
                '--triple', 'arm64-apple-macosx26.0', '--filter', test], cwd=ROOT, env=environment,
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
        if report.get('experiment') != expected_experiment or report.get('status') != 'passed' or not all(
                report.get(key) is True for key in required):
            raise SystemExit(f'Native import fixture did not prove its required checks. Diagnostics: {log}')
        if not all(report.get(key) is False for key in UNPROVEN):
            raise SystemExit('Unexpected installed-service or authorization claim in fixture evidence.')
        if args.activity and report.get('replyCallbackBoundaryTested') is not False:
            raise SystemExit('The activity fixture does not establish the reply callback boundary.')
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
