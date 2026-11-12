#!/usr/bin/env python3
"""Run a Swift package's XCTest classes in balanced shards and require every selected test to run exactly once.

Each shard is one xctest process that runs whole classes serially, as `swift test` does. A class that the weights
file lists under "methods" is split instead: each of its selected tests is a unit, so one heavy class can spread over
several shards. The shards run concurrently in this job: every shard (--concurrent), or only the shards named with
--index, so that several jobs can share one partition. --only narrows the selection to named classes and tests, as
a pull request does for the tests it changes. The weights only
balance the shards: every selected test is assigned to a shard and must then report exactly one outcome, so a stale
or missing weight can make a shard slower but can never drop a test.
"""
import argparse
import heapq
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LISTED = re.compile(r'(?P<cls>[A-Za-z_]\w*\.[A-Za-z_]\w*)/(?P<method>\w+)')
OUTCOME = re.compile(r"Test Case '-\[(?P<cls>[A-Za-z_]\w*\.[A-Za-z_]\w*) (?P<method>\w+)\]' "
                     r"(?P<state>passed|failed|skipped) \((?P<seconds>[\d.]+) seconds\)")
# These macos/core classes inspect the Mac app that scripts/check-macos-app.py builds, so CI runs them in the job
# that builds it. Elsewhere they would skip instead of failing, which is why --allowed-skips guards the other job.
APP_DEPENDENT = ('SignedReleaseInspectionTests', 'RelayConnectorProcessTests')


def listed_tests(text):
    """Parse `swift test list` output into Module.Class/method identifiers."""
    return {line.strip() for line in text.splitlines() if LISTED.fullmatch(line.strip())}


def short_name(test_class):
    return test_class.split('.', 1)[-1]


def select(classes, app_dependent):
    """Apply the app-dependent selection and refuse a selection that names a class the package no longer has."""
    names = {short_name(name) for name in classes}
    missing = [name for name in APP_DEPENDENT if name not in names]
    if missing and app_dependent != 'include':
        raise SystemExit(f'App-dependent classes are not in the test list: {", ".join(missing)}')
    if app_dependent == 'only':
        return sorted(name for name in classes if short_name(name) in APP_DEPENDENT)
    if app_dependent == 'exclude':
        return sorted(name for name in classes if short_name(name) not in APP_DEPENDENT)
    return sorted(classes)


def restrict(tests, selected_tests, only):
    """Narrow the selected tests to the names in `only`, and return them with the classes that keep only some tests.

    A Module.Class name keeps every selected test of that class and a Module.Class/method name keeps that one test.
    A name that the package does not list is an error, so a stale or mistyped name cannot select nothing silently.
    A listed name outside the selection, such as an app-dependent class in a job that excludes them, keeps nothing.
    """
    listed_classes = {test.split('/', 1)[0] for test in tests}
    unknown = sorted(name for name in only if name not in tests and name not in listed_classes)
    if unknown:
        raise ValueError(f'--only names tests that the package does not list: {", ".join(unknown)}')
    kept = {test for test in selected_tests if test in only or test.split('/', 1)[0] in only}
    kept_classes = {test.split('/', 1)[0] for test in kept}
    partial = {test.split('/', 1)[0] for test in selected_tests - kept} & kept_classes
    return kept, partial


def units(classes, tests, methods, split=frozenset()):
    """Whole classes, except that each selected test of a class named in `methods` is a unit of its own.

    So is each selected test of a Module.Class in `split`: xctest given the class name would run its other tests too.
    """
    result = []
    for name in classes:
        if short_name(name) in methods or name in split:
            result += sorted(test for test in tests if test.split('/', 1)[0] == name)
        else:
            result.append(name)
    return result


def partition(units, weights, shards, methods=None):
    """Longest-processing-time assignment. Deterministic for one unit list, weight table and shard count.

    A unit is a class, or a Module.Class/method test of a split class. A test without its own weight counts as
    the median test of its class; a class without a weight counts as the median class.
    """
    if shards < 1:
        raise ValueError('At least one shard is required')
    methods = methods or {}
    known = sorted(weights.values())
    default = known[len(known) // 2] if known else 1.0

    def weight(name):
        if '/' not in name:
            return weights.get(short_name(name), default)
        test_class, method = name.split('/', 1)
        table = methods.get(short_name(test_class), {})
        values = sorted(table.values())
        return table.get(method, values[len(values) // 2] if values else default)

    loads = [0.0] * shards
    assigned = [[] for _ in range(shards)]
    heap = [(0.0, index) for index in range(shards)]
    for name in sorted(units, key=lambda name: (-weight(name), name)):
        _, index = heapq.heappop(heap)
        assigned[index].append(name)
        loads[index] += weight(name)
        heapq.heappush(heap, (loads[index], index))
    return [sorted(names) for names in assigned], loads


def shard_tests(names, tests):
    """The selected tests a shard covers: every test of each whole class, and each test listed on its own."""
    members = set(names)
    return {test for test in tests if test in members or test.split('/', 1)[0] in members}


def chosen_shards(shards, concurrent, indices):
    """The shard indices this job runs: all of them, or each --index once. Every index must be within --shards."""
    if concurrent:
        return list(range(shards))
    if len(set(indices)) != len(indices):
        raise ValueError('--index names a shard more than once')
    outside = [index for index in indices if not 0 <= index < shards]
    if outside:
        raise ValueError(f'--index must be within --shards: {", ".join(map(str, outside))}')
    return sorted(indices)


def describe(names):
    split = sum(1 for name in names if '/' in name)
    return f'{len(names) - split} classes' + (f' and {split} tests of split classes' if split else '')


def outcomes(text):
    """Map each Module.Class/method that reported an outcome to its states, in order."""
    found = {}
    for line in text.splitlines():
        match = OUTCOME.search(line)
        if match:
            found.setdefault(f"{match['cls']}/{match['method']}", []).append(match['state'])
    return found


def verify(expected, found, allowed_skips=None):
    """Return problems and skipped tests. Every expected test needs exactly one passed or skipped outcome.

    With `allowed_skips`, a skipped test outside that set is a problem too.
    """
    problems = []
    for test in sorted(expected):
        states = found.get(test, [])
        if len(states) != 1:
            problems.append(f'{test}: {len(states)} outcomes')
        elif states[0] == 'failed':
            problems.append(f'{test}: failed')
    problems += [f'{test}: ran outside its shard' for test in sorted(set(found) - set(expected))]
    skipped = sorted(test for test in expected if found.get(test) == ['skipped'])
    if allowed_skips is not None:
        problems += [f'{test}: skipped, which this job does not allow' for test in skipped if test not in allowed_skips]
    return problems, skipped


def swift(package, flags, *arguments):
    started = time.monotonic()
    result = subprocess.run(['swift', *arguments, '--package-path', str(package), *flags], text=True,
                            capture_output=True)
    operation = 'build' if arguments[0] == 'build' and '--show-bin-path' not in arguments else ' '.join(arguments[:2])
    print(f'Command timing: swift {operation}: {time.monotonic() - started:.3f}s (exit {result.returncode})',
          file=sys.stderr, flush=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f'swift {" ".join(arguments)} exited {result.returncode}')
    return result.stdout


def group(title, text):
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        print(f'::group::{title}', flush=True)
        print(text, end='' if text.endswith('\n') else '\n', flush=True)
        print('::endgroup::', flush=True)
    else:
        print(f'--- {title}\n{text}', flush=True)


def main(argv):
    own, flags = (argv[:argv.index('--')], argv[argv.index('--') + 1:]) if '--' in argv else (argv, [])
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--package-path', type=Path, required=True)
    parser.add_argument('--weights', type=Path, help='JSON object with a "weights" map of class name to seconds and an '
                        'optional "methods" map of class name to {test method: seconds} for the classes to split')
    parser.add_argument('--shards', type=int, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--index', type=int, action='append',
                      help='run only this shard; repeat it to run several shards at once in this job')
    mode.add_argument('--concurrent', action='store_true', help='run every shard at once in this job')
    parser.add_argument('--app-dependent', choices=('include', 'exclude', 'only'), default='include',
                        help=f'select the classes that need the built Mac app: {", ".join(APP_DEPENDENT)}')
    skips = parser.add_mutually_exclusive_group()
    skips.add_argument('--allowed-skips', help='comma-separated Module.Class/method tests that may skip; others fail')
    skips.add_argument('--forbid-skips', action='store_true', help='any skipped test fails the run')
    parser.add_argument('--only', help='comma-separated Module.Class and Module.Class/method names; run only those '
                        'selected tests. Every name must be in the package\'s test list')
    parser.add_argument('--log-dir', type=Path, default=ROOT / '.build/xctest-shards')
    args = parser.parse_args(own)
    try:
        selected = chosen_shards(args.shards, args.concurrent, args.index)
    except ValueError as error:
        parser.error(str(error))
    allowed_skips = set() if args.forbid_skips else (
        {test.strip() for test in args.allowed_skips.split(',') if test.strip()} if args.allowed_skips is not None else None)

    swift(args.package_path, flags, 'build', '--build-tests')
    tests = listed_tests(swift(args.package_path, flags, 'test', 'list', '--skip-build'))
    if not tests:
        raise SystemExit('swift test list reported no tests')
    bin_path = Path(swift(args.package_path, flags, 'build', '--show-bin-path').strip())
    bundles = sorted(bin_path.glob('*.xctest'))
    if len(bundles) != 1:
        raise SystemExit(f'Expected one test bundle in {bin_path}, found {[b.name for b in bundles]}')
    document = json.loads(args.weights.read_text()) if args.weights else {'weights': {}}
    weights, methods = document['weights'], document.get('methods', {})
    classes = select({test.split('/', 1)[0] for test in tests}, args.app_dependent)
    selected_tests = {test for test in tests if test.split('/', 1)[0] in set(classes)}
    partial = set()
    if args.only is not None:
        try:
            selected_tests, partial = restrict(tests, selected_tests,
                                               {name.strip() for name in args.only.split(',') if name.strip()})
        except ValueError as error:
            raise SystemExit(str(error))
        classes = sorted({test.split('/', 1)[0] for test in selected_tests})
    assignment, loads = partition(units(classes, selected_tests, methods, partial), weights, args.shards, methods)
    args.log_dir.mkdir(parents=True, exist_ok=True)

    running = []
    for index in selected:
        names = assignment[index]
        log = args.log_dir / f'shard-{index + 1}-of-{args.shards}.log'
        if not names:
            # An empty -XCTest list would run every test, so an empty shard never starts a process.
            running.append((index, names, log, None, time.monotonic()))
            continue
        handle = log.open('w')
        process = subprocess.Popen(['xcrun', 'xctest', '-XCTest', ','.join(names), str(bundles[0])],
                                   stdout=handle, stderr=subprocess.STDOUT)
        handle.close()
        running.append((index, names, log, process, time.monotonic()))

    finished = {}

    def wait(index, process):
        status = process.wait() if process else 0
        finished[index] = (status, time.monotonic())

    waiters = [threading.Thread(target=wait, args=(index, process)) for index, _, _, process, _ in running]
    for waiter in waiters:
        waiter.start()
    for waiter in waiters:
        waiter.join()

    failed = False
    summary = []
    for index, names, log, process, started in running:
        status, ended = finished[index]
        text = log.read_text(errors='replace') if process else ''
        expected = shard_tests(names, selected_tests)
        problems, skipped = verify(expected, outcomes(text), allowed_skips)
        if status != 0 and not problems:
            problems.append(f'xctest exited {status}')
        failed |= bool(problems)
        print(f'Command timing: xctest shard {index + 1}/{args.shards}: {ended - started:.3f}s (exit {status})',
              file=sys.stderr, flush=True)
        group(f'xctest shard {index + 1}/{args.shards}: {describe(names)}, {len(expected)} tests', text)
        summary.append((index, names, expected, ended - started, skipped, problems))

    for index, names, expected, elapsed, skipped, problems in summary:
        print(f'Shard {index + 1}/{args.shards}: {describe(names)}, {len(expected)} tests, '
              f'estimated {loads[index]:.0f}s, took {elapsed:.0f}s, {len(skipped)} skipped, {len(problems)} problems')
        for test in skipped:
            print(f'  skipped: {test}')
        for problem in problems:
            print(f'  problem: {problem}')
    covered = sum(len(expected) for _, _, expected, _, _, _ in summary)
    print(f'{covered} of {len(selected_tests)} selected tests ({len(tests)} listed) belong to the shards this job ran.')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
