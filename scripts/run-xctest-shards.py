#!/usr/bin/env python3
"""Run a Swift package's XCTest classes in balanced shards and require every listed test to run exactly once.

Each shard is one xctest process that runs whole classes serially, as `swift test` does. The shards either run
concurrently in this job (--concurrent) or one per CI job (--index). The weights only balance the shards: every
listed test is assigned to a shard and must then report exactly one outcome, so a stale or missing weight can make
a shard slower but can never drop a test.
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


def listed_tests(text):
    """Parse `swift test list` output into Module.Class/method identifiers."""
    tests = set()
    for line in text.splitlines():
        match = LISTED.fullmatch(line.strip())
        if match:
            tests.add(line.strip())
    return tests


def partition(classes, weights, shards):
    """Longest-processing-time assignment. Deterministic for one class list, weight table and shard count."""
    if shards < 1:
        raise ValueError('At least one shard is required')
    known = sorted(weights.values())
    default = known[len(known) // 2] if known else 1.0

    def weight(name):
        return weights.get(name.split('.', 1)[-1], default)

    loads = [0.0] * shards
    assigned = [[] for _ in range(shards)]
    heap = [(0.0, index) for index in range(shards)]
    for name in sorted(classes, key=lambda name: (-weight(name), name)):
        _, index = heapq.heappop(heap)
        assigned[index].append(name)
        loads[index] += weight(name)
        heapq.heappush(heap, (loads[index], index))
    return [sorted(names) for names in assigned], loads


def outcomes(text):
    """Map each Module.Class/method that reported an outcome to its states, in order."""
    found = {}
    for line in text.splitlines():
        match = OUTCOME.search(line)
        if match:
            found.setdefault(f"{match['cls']}/{match['method']}", []).append(match['state'])
    return found


def verify(expected, found):
    """Return problems and skipped tests. Every expected test needs exactly one passed or skipped outcome."""
    problems = []
    for test in sorted(expected):
        states = found.get(test, [])
        if len(states) != 1:
            problems.append(f'{test}: {len(states)} outcomes')
        elif states[0] == 'failed':
            problems.append(f'{test}: failed')
    problems += [f'{test}: ran outside its shard' for test in sorted(set(found) - set(expected))]
    skipped = sorted(test for test in expected if found.get(test) == ['skipped'])
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
    parser.add_argument('--weights', type=Path, help='JSON object with a "weights" map of class name to seconds')
    parser.add_argument('--shards', type=int, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--index', type=int, help='run only this shard')
    mode.add_argument('--concurrent', action='store_true', help='run every shard at once in this job')
    parser.add_argument('--log-dir', type=Path, default=ROOT / '.build/xctest-shards')
    args = parser.parse_args(own)
    if args.index is not None and not 0 <= args.index < args.shards:
        parser.error('--index must be within --shards')

    swift(args.package_path, flags, 'build', '--build-tests')
    tests = listed_tests(swift(args.package_path, flags, 'test', 'list', '--skip-build'))
    if not tests:
        raise SystemExit('swift test list reported no tests')
    bin_path = Path(swift(args.package_path, flags, 'build', '--show-bin-path').strip())
    bundles = sorted(bin_path.glob('*.xctest'))
    if len(bundles) != 1:
        raise SystemExit(f'Expected one test bundle in {bin_path}, found {[b.name for b in bundles]}')
    weights = json.loads(args.weights.read_text())['weights'] if args.weights else {}
    classes = sorted({test.split('/', 1)[0] for test in tests})
    assignment, loads = partition(classes, weights, args.shards)
    selected = range(args.shards) if args.concurrent else [args.index]
    args.log_dir.mkdir(parents=True, exist_ok=True)

    running = []
    for index in selected:
        names = assignment[index]
        log = args.log_dir / f'shard-{index}-of-{args.shards}.log'
        if not names:
            running.append((index, names, log, None, time.monotonic()))
            continue
        # An empty -XCTest list would run every test, so empty shards never start a process.
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
        elapsed = ended - started
        text = log.read_text(errors='replace') if process else ''
        expected = {test for test in tests if test.split('/', 1)[0] in names}
        problems, skipped = verify(expected, outcomes(text))
        if status != 0 and not problems:
            problems.append(f'xctest exited {status}')
        failed |= bool(problems)
        print(f'Command timing: xctest shard {index + 1}/{args.shards}: {elapsed:.3f}s (exit {status})',
              file=sys.stderr, flush=True)
        group(f'xctest shard {index + 1}/{args.shards}: {len(names)} classes, {len(expected)} tests', text)
        summary.append((index, names, expected, elapsed, skipped, problems))

    for index, names, expected, elapsed, skipped, problems in summary:
        print(f'Shard {index + 1}/{args.shards}: {len(names)} classes, {len(expected)} tests, '
              f'estimated {loads[index]:.0f}s, took {elapsed:.0f}s, {len(skipped)} skipped, {len(problems)} problems')
        for test in skipped:
            print(f'  skipped: {test}')
        for problem in problems:
            print(f'  problem: {problem}')
    covered = sum(len(expected) for _, _, expected, _, _, _ in summary)
    print(f'{covered} of {len(tests)} listed tests belong to the shards this job ran.')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
