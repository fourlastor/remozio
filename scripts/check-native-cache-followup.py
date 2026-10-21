#!/usr/bin/env python3
"""Mac-only warm-output diagnostic after a successful complete check.sh gate.

This does not exercise Actions cache storage or rerun the complete warm gate.
The workflow must run ci-build-cache.py key BEFORE its full cold check.sh step.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import subprocess
import sys
import time


LINUX_INPUT = 'scripts/run-linux-storage-lease-experiment.py'
COMMENT = b'\n# Native cache diagnostic: unchanged Mac inputs, Linux-only comment.\n'
MAX_LOG_BYTES = 32 * 1024 * 1024
TOTAL_SECONDS = 2100


@dataclass
class Input:
    path: Path
    content: bytes | str
    mode: int
    atime_ns: int
    mtime_ns: int
    symlink: bool


def safe_path(root, name):
    parts = PurePosixPath(name)
    if parts.is_absolute() or not parts.parts or any(p in ('..', '.git') for p in parts.parts):
        raise RuntimeError('invalid tracked input path')
    path = root.joinpath(*parts.parts)
    if path.parent.resolve() != path.parent or not path.parent.is_relative_to(root):
        raise RuntimeError('tracked input has a symlinked parent')
    return path


def tracked_paths(root):
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=root, capture_output=True,
                            timeout=30, check=True)
    if len(result.stdout) > 4 * 1024 * 1024:
        raise RuntimeError('tracked inventory exceeds diagnostic bound')
    return [os.fsdecode(value) for value in result.stdout.split(b'\0') if value]


def snapshot(root, names):
    result = {}
    total = 0
    if len(names) > 10000:
        raise RuntimeError('tracked input count exceeds diagnostic bound')
    for name in names:
        path = safe_path(root, name)
        info = path.lstat()
        link = stat.S_ISLNK(info.st_mode)
        if not link and not stat.S_ISREG(info.st_mode):
            raise RuntimeError('unsupported tracked input type')
        total += info.st_size
        if info.st_size > MAX_LOG_BYTES or total > 256 * 1024 * 1024:
            raise RuntimeError('tracked input bytes exceed diagnostic bound')
        content = os.readlink(path) if link else path.read_bytes()
        result[name] = Input(path, content, stat.S_IMODE(info.st_mode),
                             info.st_atime_ns, info.st_mtime_ns, link)
    return result


def verify_inputs(inputs, changed=False, restored_times=False):
    for name, before in inputs.items():
        info = before.path.lstat()
        if stat.S_ISLNK(info.st_mode) != before.symlink or stat.S_IMODE(info.st_mode) != before.mode:
            raise RuntimeError('tracked input type or mode changed')
        content = os.readlink(before.path) if before.symlink else before.path.read_bytes()
        expected = before.content + COMMENT if changed and name == LINUX_INPUT else before.content
        if content != expected:
            raise RuntimeError('unexpected tracked input content change')
        if restored_times and not before.symlink and name != LINUX_INPUT and info.st_mtime_ns != before.mtime_ns:
            raise RuntimeError('unchanged source timestamp was not restored')


def restore_inputs(inputs):
    failures = []
    for before in inputs.values():
        try:
            if before.path.parent.resolve() != before.path.parent:
                raise RuntimeError('tracked parent changed')
            if before.symlink:
                if not before.path.is_symlink() or os.readlink(before.path) != before.content:
                    before.path.unlink(missing_ok=True)
                    before.path.symlink_to(before.content)
            else:
                if before.path.is_symlink():
                    before.path.unlink()
                if not before.path.exists() or before.path.read_bytes() != before.content:
                    before.path.write_bytes(before.content)
                before.path.chmod(before.mode)
            os.utime(before.path, ns=(before.atime_ns, before.mtime_ns), follow_symlinks=False)
        except (OSError, RuntimeError):
            failures.append(before.path.name)
    if failures:
        raise RuntimeError('failed to restore one or more tracked inputs')


def wait_publishing_status(proc, timeout):
    # A cancellation handler must not run after waitpid reaps the leader but
    # before Popen publishes returncode: that window would make killpg unsafe.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        return proc.wait(timeout=timeout)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def command(root, output, name, argv, deadline, timeout, env=None):
    log = output / f'{name}.log'
    start = time.monotonic()
    remaining = min(timeout, deadline - start)
    if remaining <= 0:
        raise RuntimeError('diagnostic total deadline exceeded')
    with log.open('wb') as stream:
        proc = None
        try:
            # Defer Python cancellation handlers during ownership publication,
            # without changing the OS mask inherited by the exec child.
            handlers = {}
            pending = []
            def defer_cancel(signum, frame):
                pending.append((signum, frame))
            try:
                handlers[signal.SIGINT] = signal.signal(signal.SIGINT, defer_cancel)
                handlers[signal.SIGTERM] = signal.signal(signal.SIGTERM, defer_cancel)
                proc = subprocess.Popen(argv, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                        env=env, start_new_session=True)
            finally:
                try:
                    if signal.SIGINT in handlers:
                        signal.signal(signal.SIGINT, handlers[signal.SIGINT])
                finally:
                    if signal.SIGTERM in handlers:
                        signal.signal(signal.SIGTERM, handlers[signal.SIGTERM])
            for signum, frame in pending:
                handler = handlers[signum]
                if callable(handler):
                    handler(signum, frame)
                elif handler != signal.SIG_IGN:
                    raise SystemExit(128 + signum)
            while True:
                if log.stat().st_size > MAX_LOG_BYTES:
                    raise RuntimeError('diagnostic command output exceeded bound')
                left = remaining - (time.monotonic() - start)
                if left <= 0:
                    raise RuntimeError('diagnostic command deadline exceeded')
                try:
                    status = wait_publishing_status(proc, timeout=min(.2, left))
                    break
                except subprocess.TimeoutExpired:
                    pass
            if log.stat().st_size > MAX_LOG_BYTES:
                raise RuntimeError('diagnostic command output exceeded bound')
            if status:
                raise RuntimeError(f'diagnostic command failed: {name}')
        finally:
            # No group signal after wait() reaped the leader: its PID may be reused.
            if proc is not None and proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                wait_publishing_status(proc, timeout=10)
    return {'seconds': round(time.monotonic() - start, 3), 'exit': status,
            'log': log.name, 'bytes': log.stat().st_size}


def helper_report(path, operation):
    records = []
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get('operation') == operation:
            records.append(value)
    if len(records) != 1:
        raise RuntimeError('expected one cache helper report')
    return records[0]


def copy_log(source, destination):
    if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_LOG_BYTES:
        raise RuntimeError('missing or oversized required native log')
    destination.write_bytes(source.read_bytes())


def xcode_summary(path):
    lines = path.read_text(errors='replace').splitlines()
    return {'bytes': path.stat().st_size, 'lines': len(lines),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'buildSucceeded': any('** BUILD SUCCEEDED **' in line for line in lines),
            'phaseLines': {phase: sum(bool(re.match(r'^' + phase + r'\b', line)) for line in lines)
                           for phase in ('CompileC', 'SwiftCompile', 'SwiftEmitModule', 'Ld', 'CodeSign')},
            'frontendCommandLines': sum(bool(re.search(r'(?:^|\s)(?:\S*/)?swift-frontend\s', line))
                                        for line in lines)}


def test_summaries(output):
    python_log = (output / 'warm-python.log').read_text(errors='replace')
    python_counts = re.findall(r'^Ran ([1-9][0-9]*) tests? in ', python_log, re.MULTILINE)
    if not python_counts or not re.search(r'^OK(?:\s|$)', python_log, re.MULTILINE):
        raise RuntimeError('repository Python test execution was not demonstrated')
    protocol_log = (output / 'warm-protocol.log').read_text(errors='replace')
    protocol = re.findall(r'Executed ([1-9][0-9]*) tests?, with (?:(\d+) tests? skipped and )?(\d+) failures',
                          protocol_log)
    if not protocol or int(protocol[-1][2]) != 0:
        raise RuntimeError('protocol XCTest execution was not demonstrated')
    return {'repositoryPythonTests': int(python_counts[-1]),
            'protocolXCTests': int(protocol[-1][0]),
            'protocolSkipped': int(protocol[-1][1] or 0), 'protocolFailures': 0}


def run(args):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64' or sys.version_info < (3, 11):
        raise RuntimeError('diagnostic requires supported arm64 Mac and Python 3.11+')
    root = args.repo.resolve(strict=True)
    output = args.output.resolve()
    if output == root or output.is_relative_to(root):
        raise RuntimeError('evidence must be outside the checkout and compiler cleanup roots')
    if not 0 <= args.cold_full_check_seconds < 7200:
        raise RuntimeError('invalid completed full-check duration')
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + TOTAL_SECONDS
    context_path = root / '.build/ci-cache-context/mac.json'
    original_context = context_path.read_bytes()
    context = json.loads(original_context)
    cold_key = helper_report(args.cold_key_log, 'key')
    if cold_key.get('scope') != 'mac' or context['key'] != cold_key.get('key'):
        raise RuntimeError('cold key context must come from before the full check')
    names = tracked_paths(root)
    inputs = snapshot(root, names)
    if LINUX_INPUT not in inputs or inputs[LINUX_INPUT].symlink:
        raise RuntimeError('required Linux-only runner must be a tracked regular file')
    timings = {}; cold_xcode = {}; warm_xcode = {}; original_manifest = None
    try:
        # Reuse BEFORE-check context: regenerating it here would hide cold-gate mutations.
        timings['save'] = command(root, output, 'save', [sys.executable,
            'scripts/ci-build-cache.py', 'save', '--scope', 'mac'], deadline, 90)
        saved = helper_report(output / 'save.log', 'save')
        if saved.get('saved_manifest') is not True:
            raise RuntimeError('cold full check did not preserve its original tracked inputs')
        manifest_path = root / '.build/ci-cache/mac.json'
        original_manifest = manifest_path.read_bytes()
        copy_log(args.cold_full_check_log, output / 'cold-full-check.log')
        copy_log(args.cold_key_log, output / 'cold-key.log')
        for configuration in ('debug', 'release'):
            dest = output / f'cold-xcodebuild-{configuration}.log'
            copy_log(root / f'.build/macos-app/xcodebuild-{configuration}.log', dest)
            cold_xcode[configuration] = xcode_summary(dest)
            if not cold_xcode[configuration]['buildSucceeded']:
                raise RuntimeError('cold app build did not succeed')
        churn_ns = time.time_ns()
        for before in inputs.values():
            if not before.symlink:
                changed_ns = churn_ns if churn_ns != before.mtime_ns else churn_ns + 1
                os.utime(before.path, ns=(before.atime_ns, changed_ns), follow_symlinks=False)
        inputs[LINUX_INPUT].path.write_bytes(inputs[LINUX_INPUT].content + COMMENT)
        verify_inputs(inputs, changed=True)
        timings['key'] = command(root, output, 'warm-key', [sys.executable,
            'scripts/ci-build-cache.py', 'key', '--scope', 'mac'], deadline, 90)
        warm_key = helper_report(output / 'warm-key.log', 'key')
        current_context = json.loads(context_path.read_text())
        if current_context['identity'] != context['identity'] or warm_key['key'] == cold_key['key']:
            raise RuntimeError('Linux-only edit must preserve identity and change exact key')
        env = os.environ.copy(); env['REMOZIO_CACHE_HIT'] = 'false'
        timings['restore'] = command(root, output, 'warm-restore', [sys.executable,
            'scripts/ci-build-cache.py', 'restore', '--scope', 'mac'], deadline, 90, env)
        restored = helper_report(output / 'warm-restore.log', 'restore')
        if restored.get('result') != 'restored' or restored.get('requires_clean_build') is not False:
            raise RuntimeError('native outputs were not eligible for warm reuse')
        verify_inputs(inputs, changed=True, restored_times=True)
        timings['python'] = command(root, output, 'warm-python', [sys.executable,
            '-m', 'unittest', 'discover', '-s', 'tests'], deadline, 300)
        timings['app'] = command(root, output, 'warm-app', [sys.executable,
            'scripts/check-macos-app.py'], deadline, 1200)
        for configuration in ('debug', 'release'):
            dest = output / f'warm-xcodebuild-{configuration}.log'
            copy_log(root / f'.build/macos-app/xcodebuild-{configuration}.log', dest)
            warm_xcode[configuration] = xcode_summary(dest)
            if not warm_xcode[configuration]['buildSucceeded']:
                raise RuntimeError('warm app build did not succeed')
        timings['protocol'] = command(root, output, 'warm-protocol', ['swift', 'test',
            '--package-path', 'protocol/swift', '--triple', 'arm64-apple-macosx26.0',
            '--force-resolved-versions', '--jobs', '4'], deadline, 600)
        verify_inputs(inputs, changed=True)
        if tracked_paths(root) != names:
            raise RuntimeError('tracked file inventory changed')
        report = {'passed': True, 'scope': 'same-workspace compiler-output reuse',
            'actualGitHubArchiveHitTested': False, 'completeWarmGateRun': False,
            'coldFullCheckSeconds': args.cold_full_check_seconds,
            'coldFullCheckExitStatus': 'successful previous workflow step required',
            'coldKey': cold_key['key'], 'warmKey': warm_key['key'],
            'compatibilityIdentity': context['identity'],
            'sameCompatibilityIdentity': True, 'exactKeyChanged': True,
            'cacheHitEnvironmentSimulatedForHelper': True,
            'restore': restored, 'changedTrackedInput': LINUX_INPUT,
            'commentSHA256': hashlib.sha256(COMMENT).hexdigest(),
            'trackedInputCount': len(inputs), 'regularFilesTimestampChurned': sum(not x.symlink for x in inputs.values()),
            'onlyExpectedTrackedContentChange': True, 'timings': timings,
            'testSummaries': test_summaries(output),
            'xcode': {'cold': cold_xcode, 'warm': warm_xcode},
            'limits': ['Cold full gate was executed by the preceding workflow step, not this script.',
                'Warm checks cover repository Python, actual Debug/Release app validation and protocol Swift tests only.',
                'No actual Actions cache archive download or full warm-suite timing is measured.',
                'Frontend/phase log counts are observed work indicators, not proof of complete Xcode reuse.']}
    finally:
        try:
            restore_inputs(inputs)
        finally:
            context_path.write_bytes(original_context)
            if original_manifest is not None:
                manifest_path.write_bytes(original_manifest)
    verify_inputs(inputs)
    for before in inputs.values():
        # The content verification itself may advance atime; restore it last too.
        os.utime(before.path, ns=(before.atime_ns, before.mtime_ns), follow_symlinks=False)
        info = before.path.lstat()
        if info.st_mtime_ns != before.mtime_ns or info.st_atime_ns != before.atime_ns:
            raise RuntimeError('tracked source timestamp restoration failed')
    report['trackedContentModesAndMtimesRestored'] = True
    report['trackedAtimesRestored'] = True
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'report': str(output / 'report.json')}))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cold-key-log', required=True, type=Path)
    parser.add_argument('--cold-full-check-log', required=True, type=Path)
    parser.add_argument('--cold-full-check-seconds', required=True, type=float)
    args = parser.parse_args()
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    previous_term = signal.signal(signal.SIGTERM, terminate)
    try:
        try:
            run(args)
        except Exception as error:
            print(f'Native cache follow-up failed: {type(error).__name__}: {error}', file=sys.stderr)
            return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
