#!/usr/bin/env python3
"""Fork-only Mac pilot: serial versus two-worker parallel macos/core XCTest runs.

The tests are built once, outside timing. Each trial then runs the complete
suite with --skip-build in the requested order (SPPS by default), so both modes
use the same binaries, host and toolchain. A trial's test failures are recorded,
not raised: under parallel execution they are isolation findings, not flakes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ElementTree


PACKAGE = 'macos/core'
TRIPLE = 'arm64-apple-macosx26.0'
MAX_LOG_BYTES = 64 * 1024 * 1024
TOTAL_SECONDS = 17400
TRIAL_SECONDS = 4200
WORKERS = 2
FIXTURE_ROOT = Path('/private/tmp')
FIXTURE_PREFIX = 'remozio-'
SERIAL_CASE = re.compile(r"^Test Case '-\[(\S+) (\S+)\]' (passed|failed|skipped) \(", re.M)
LISTED = re.compile(r'^([A-Za-z_][\w.]*)/([A-Za-z_]\w*)$')


def swift_test(*extra):
    return ['swift', 'test', '--package-path', PACKAGE, '--triple', TRIPLE, *extra]


def run(root, log, argv, timeout):
    """Run argv in its own session, returning (exit, seconds, child CPU seconds)."""
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    with log.open('wb') as stream:
        proc = subprocess.Popen(argv, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            status = proc.wait(timeout=timeout)
        finally:
            if proc.returncode is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=30)
    seconds = time.monotonic() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    if log.stat().st_size > MAX_LOG_BYTES:
        raise RuntimeError(f'{log.name} exceeded its bound')
    return status, round(seconds, 3), round(cpu, 3)


def listed_tests(text):
    # The log merges stderr, so toolchain diagnostics may surround the listing.
    names = [f'{match[1]}/{match[2]}' for match in map(LISTED.match, map(str.strip, text.splitlines())) if match]
    if not names or len(set(names)) != len(names):
        raise RuntimeError('empty or duplicated test list')
    return names


def serial_results(text):
    return [(f'{suite}/{method}', outcome) for suite, method, outcome in SERIAL_CASE.findall(text)]


def xunit_results(data):
    results = []
    durations = 0.0
    for case in ElementTree.fromstring(data).iter('testcase'):
        name = f"{case.get('classname')}/{case.get('name')}"
        if case.find('failure') is not None or case.find('error') is not None:
            outcome = 'failed'
        elif case.find('skipped') is not None:
            outcome = 'skipped'
        else:
            outcome = 'passed'
        durations += float(case.get('time') or 0)
        results.append((name, outcome))
    return results, round(durations, 3)


def classify(expected, results):
    seen = {}
    for name, outcome in results:
        seen.setdefault(name, []).append(outcome)
    outcomes = {name: values[-1] for name, values in seen.items()}
    expected_set = set(expected)
    return {
        'executed': len(outcomes),
        'passed': sum(value == 'passed' for value in outcomes.values()),
        'failed': sorted(name for name, value in outcomes.items() if value == 'failed'),
        'skipped': sorted(name for name, value in outcomes.items() if value == 'skipped'),
        'missing': len(expected_set - outcomes.keys()),
        'unexpected': len(outcomes.keys() - expected_set),
        'duplicated': sum(len(values) > 1 for values in seen.values()),
        'completeSet': outcomes.keys() == expected_set and all(len(v) == 1 for v in seen.values()),
    }


def fixture_entries():
    try:
        return {entry.name for entry in os.scandir(FIXTURE_ROOT) if entry.name.startswith(FIXTURE_PREFIX)}
    except OSError:
        return set()


def plan(order):
    if not order or set(order) - {'S', 'P'}:
        raise ValueError('order uses only S and P')
    return ['serial' if mode == 'S' else 'parallel' for mode in order]


def trial(root, output, index, mode, expected, deadline):
    name = f'trial-{index}-{mode}'
    left = deadline - time.monotonic()
    if left < 600:
        return {'mode': mode, 'index': index, 'ran': False, 'reason': 'total deadline'}
    xunit = output / f'{name}.xml'
    argv = swift_test('--skip-build')
    if mode == 'parallel':
        argv += ['--parallel', '--num-workers', str(WORKERS), '--xunit-output', str(xunit)]
    before = fixture_entries()
    try:
        status, seconds, cpu = run(root, output / f'{name}.log', argv, min(TRIAL_SECONDS, left))
    except subprocess.TimeoutExpired:
        return {'mode': mode, 'index': index, 'ran': True, 'timedOut': True}
    leftovers = fixture_entries() - before
    result = {'mode': mode, 'index': index, 'ran': True, 'timedOut': False, 'exit': status,
              'seconds': seconds, 'childCPUSeconds': cpu, 'newFixtureEntries': len(leftovers),
              'log': f'{name}.log'}
    if mode == 'parallel':
        if not xunit.is_file():
            result['resultSource'] = 'missing xunit'
            return result
        results, durations = xunit_results(xunit.read_bytes())
        result.update(resultSource='xunit', xunit=xunit.name, summedTestSeconds=durations)
    else:
        results = serial_results((output / f'{name}.log').read_text(errors='replace'))
        result['resultSource'] = 'xctest log'
    result.update(classify(expected, results))
    return result


def summary(trials):
    def seconds(mode):
        return [t['seconds'] for t in trials if t.get('mode') == mode and 'seconds' in t]
    serial, parallel = seconds('serial'), seconds('parallel')
    if not serial or not parallel:
        return {'comparable': False}
    serial_mean = sum(serial) / len(serial)
    parallel_mean = sum(parallel) / len(parallel)
    return {'comparable': True, 'serialSeconds': serial, 'parallelSeconds': parallel,
            'serialMean': round(serial_mean, 1), 'parallelMean': round(parallel_mean, 1),
            'parallelReduction': round(1 - parallel_mean / serial_mean, 4)}


def host(root):
    info = {}
    for key, argv in {'head': ['git', 'rev-parse', 'HEAD'], 'macos': ['sw_vers', '-productVersion'],
                      'xcode': ['xcodebuild', '-version'], 'swift': ['swift', '--version'],
                      'cpus': ['sysctl', '-n', 'hw.ncpu'], 'memoryBytes': ['sysctl', '-n', 'hw.memsize']}.items():
        result = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=60)
        info[key] = (result.stdout or result.stderr).strip()[:400]
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--order', default='SPPS')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise SystemExit('The pilot needs a Mac runner.')
    root = args.repo.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + TOTAL_SECONDS
    modes = plan(args.order)
    report = {'scope': 'fork-only macos/core serial versus parallel XCTest timing',
              'workers': WORKERS, 'order': args.order, 'host': host(root)}
    status, seconds, cpu = run(root, output / 'build.log',
                               ['swift', 'build', '--package-path', PACKAGE, '--triple', TRIPLE,
                                '--build-tests'], 3600)
    report['build'] = {'exit': status, 'seconds': seconds, 'childCPUSeconds': cpu}
    if status:
        raise RuntimeError('test build failed')
    status, _, _ = run(root, output / 'list.log', swift_test('list', '--skip-build'), 600)
    if status:
        raise RuntimeError('test listing failed')
    expected = listed_tests((output / 'list.log').read_text())
    report['listedTests'] = len(expected)
    report['trials'] = []
    for index, mode in enumerate(modes, 1):
        report['trials'].append(trial(root, output, index, mode, expected, deadline))
        # Rewritten after each trial so a job timeout still leaves the completed ones.
        (output / 'report.json').write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
    report['summary'] = summary(report['trials'])
    report['limits'] = [
        'One hosted runner; two samples per mode are a pilot, not a statistical estimate.',
        'The full suite is run in parallel, beyond the single class the isolation audit examined.',
        'Parallel failures are isolation findings until shown otherwise; they are not retried.',
        'Child CPU covers reaped descendants only.',
    ]
    (output / 'report.json').write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
    print(json.dumps(report['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
