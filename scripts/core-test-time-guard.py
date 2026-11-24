#!/usr/bin/env python3
"""Fail the Mac core tests job when a macos/core test becomes slow, so removed slowness cannot creep back.

It runs after scripts/run-xctest-shards.py and reads only the shard logs that it wrote, except for the re-runs below.

Per-test limit. Every test that reports `passed` or `failed` with a duration over LIMIT_SECONDS fails the job, unless
EXCEPTIONS (.github/macos-core-slow-tests.json) lists it as Class/method with a written reason and its own cap; a
listed test over its own cap fails too. The exceptions file is meant to shrink over time: adding an entry or raising
a cap must be a visible change that a reviewer approves on its own merits, never a quiet way to make CI pass.

Re-runs in isolation. The shards run three xctest processes at once, so one duration can be noisy. A test over its
limit is re-run once on its own, serially, after the shards, through the same xctest bundle and the same command
shape (`xcrun xctest -XCTest Module.Class/method <bundle>`). It fails, as "slow in isolation", only when it is still
over its limit there. The re-runs are capped: more than MAX_RERUNS offenders fail at once as "too many slow tests"
with nothing re-run, and the re-runs share a RERUN_BUDGET_SECONDS budget; when it runs out the job fails with the
slow tests and re-runs nothing more. A run where no test is over its limit re-runs nothing.

Weight drift. For the classes that a pull request selected (MODE=selected), or whose test files it changed (full
mode), the measured class total, the sum of its per-test durations in these logs, is compared with its weight in
WEIGHTS. A class more than DRIFT_RATIO over its weight plus DRIFT_MARGIN_SECONDS fails a pull request that does not
also update WEIGHTS. A class split under "methods" is compared with the sum of the method weights of the tests that
ran here, since each runner runs only part of it. Pushes to main, the nightly run and manual runs only warn.

Nightly total. On the scheduled run, a warning (never a failure) is printed when the summed per-test time exceeds
the exceptions file's nightly_total_cap_seconds, scaled to this job's share of the parts.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LIMIT_SECONDS = 20.0
MAX_RERUNS = 5
RERUN_BUDGET_SECONDS = 120.0
DRIFT_RATIO = 0.5
DRIFT_MARGIN_SECONDS = 10.0
EXCEPTIONS = '.github/macos-core-slow-tests.json'
WEIGHTS = '.github/macos-core-test-weights.json'
CORE_TESTS = 'macos/core/Tests/'
OUTCOME = re.compile(r"Test Case '-\[(?P<cls>[A-Za-z_]\w*\.[A-Za-z_]\w*) (?P<method>\w+)\]' "
                     r"(?P<state>passed|failed|skipped) \((?P<seconds>[\d.]+) seconds\)")
TEST_CLASS = re.compile(r'^(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:final|public|open)\s+)*class\s+(\w+)\s*:\s*XCTestCase\b',
                        re.MULTILINE)


def short(test):
    """Module.Class/method or Module.Class to Class/method or Class."""
    return test.split('.', 1)[-1]


def test_class(test):
    return short(test).split('/', 1)[0]


def durations(texts):
    """Map each Module.Class/method that passed or failed to its last reported duration in seconds."""
    found = {}
    for text in texts:
        for match in OUTCOME.finditer(text):
            if match['state'] != 'skipped':
                found[f"{match['cls']}/{match['method']}"] = float(match['seconds'])
    return found


def load_exceptions(document):
    """Validate the exceptions document and return ({Class/method: cap seconds}, nightly cap seconds)."""
    if set(document) != {'description', 'source', 'nightly_total_cap_seconds', 'exceptions'}:
        raise ValueError(f'{EXCEPTIONS} must have exactly description, source, nightly_total_cap_seconds, exceptions')
    caps = {}
    for name, entry in document['exceptions'].items():
        if name.count('/') != 1 or '.' in name:
            raise ValueError(f'{EXCEPTIONS}: {name} is not Class/method')
        if set(entry) != {'cap_seconds', 'reason'} or not str(entry['reason']).strip():
            raise ValueError(f'{EXCEPTIONS}: {name} needs a cap_seconds and a non-empty reason')
        if not isinstance(entry['cap_seconds'], (int, float)) or entry['cap_seconds'] <= LIMIT_SECONDS:
            raise ValueError(f'{EXCEPTIONS}: {name} needs a cap above {LIMIT_SECONDS:g} s')
        caps[name] = float(entry['cap_seconds'])
    return caps, float(document['nightly_total_cap_seconds'])


def limit(test, caps):
    return caps.get(short(test), LIMIT_SECONDS)


def check_limits(measured, caps, rerun, max_reruns=MAX_RERUNS, budget=RERUN_BUDGET_SECONDS):
    """Return the per-test problems. `rerun(test, timeout)` runs one test alone and returns (seconds, elapsed),
    seconds being None when it reported no passing or failing duration, or raises TimeoutError."""
    slow = sorted(test for test, seconds in measured.items() if seconds > limit(test, caps))
    if not slow:
        return []
    listing = [f'{short(test)}: {measured[test]:.3f}s (limit {limit(test, caps):g}s)' for test in slow]
    if len(slow) > max_reruns:
        return [f'too many slow tests ({len(slow)}, more than {max_reruns} to re-run): {test}' for test in listing]
    problems = []
    remaining = budget
    for index, test in enumerate(slow):
        if remaining <= 0:
            problems += [f're-run budget of {budget:g}s exhausted before re-running: {line}' for line in listing[index:]]
            break
        print(f'Re-running {short(test)} in isolation ({measured[test]:.3f}s in the shards, limit '
              f'{limit(test, caps):g}s, {remaining:.0f}s of re-run budget left)', flush=True)
        try:
            seconds, elapsed = rerun(test, remaining)
        except TimeoutError:
            problems += [f're-run budget of {budget:g}s exhausted while re-running: {line}' for line in listing[index:]]
            break
        remaining -= elapsed
        if seconds is None:
            problems.append(f'{short(test)}: the re-run in isolation reported no duration')
        elif seconds > limit(test, caps):
            problems.append(f'{short(test)}: slow in isolation, {seconds:.3f}s (limit {limit(test, caps):g}s; '
                            f'{measured[test]:.3f}s in the shards)')
        else:
            print(f'  {short(test)} took {seconds:.3f}s in isolation, within its limit', flush=True)
    return problems


def drift(measured, document, classes):
    """Classes among `classes` whose measured total exceeds their expected time by more than the allowed drift."""
    weights, methods = document['weights'], document.get('methods', {})
    totals, ran = {}, {}
    for test, seconds in measured.items():
        name = test_class(test)
        totals[name] = totals.get(name, 0.0) + seconds
        ran.setdefault(name, []).append(short(test).split('/', 1)[1])
    problems = []
    for name in sorted(set(classes) & set(totals)):
        table = methods.get(name)
        if table and all(method in table for method in ran[name]):
            expected = sum(table[method] for method in ran[name])
        elif name in weights:
            expected = weights[name]
        else:
            continue
        allowed = expected * (1 + DRIFT_RATIO) + DRIFT_MARGIN_SECONDS
        if totals[name] > allowed:
            problems.append(f'{name}: {totals[name]:.1f}s measured, weight {expected:.1f}s, allowed {allowed:.1f}s')
    return problems


def drift_classes(mode, selected_tests, changed, read_text):
    """The classes to check for drift: the selected ones, or those declared in changed core test files."""
    if mode == 'selected':
        return {test_class(name.strip()) for name in selected_tests.split(',') if name.strip()}
    classes = set()
    for path in changed:
        if path.startswith(CORE_TESTS) and path.endswith('.swift'):
            text = read_text(path)
            if text is not None:
                classes.update(TEST_CLASS.findall(text))
    return classes


def evaluate(measured, caps, nightly_cap, weights, *, event, mode, selected_tests, changed, read_text, rerun,
             parts=1):
    """Return (errors, warnings) for one job's measurements. `changed` is None when the changes are unknown."""
    errors = check_limits(measured, caps, rerun)
    warnings = []
    if event == 'pull_request':
        if changed is None:
            warnings.append('Could not read the pull request changes, so the weight drift check was skipped')
        else:
            classes = drift_classes(mode, selected_tests, changed, read_text)
            found = drift(measured, weights, classes)
            if found and WEIGHTS in changed:
                warnings += [f'weight drift, accepted because {WEIGHTS} changes: {line}' for line in found]
            else:
                errors += [f'weight drift; update {WEIGHTS} in this pull request: {line}' for line in found]
    elif mode == 'full':
        # Main and nightly runs report drift for every class, as warnings only.
        warnings += [f'weight drift: {line}' for line in drift(measured, weights, {test_class(t) for t in measured})]
    if event == 'schedule':
        total, cap = sum(measured.values()), nightly_cap / max(parts, 1)
        if total > cap:
            warnings.append(f'macos/core tests took {total:.0f}s in this job, over its {cap:.0f}s share of the '
                            f'{nightly_cap:.0f}s nightly cap')
    return errors, warnings


def git(*arguments):
    return subprocess.run(['git', *arguments], cwd=ROOT, text=True, capture_output=True, check=True).stdout


def changed_paths(base):
    """Paths that the checked-out pull request merge commit changes against its base, or None when unknown."""
    for reference in ([base] if base else []) + ['HEAD^1']:
        try:
            return [name for name in git('diff', '--name-only', '--no-renames', '-z', reference, 'HEAD').split('\0')
                    if name]
        except subprocess.CalledProcessError:
            continue
    return None


def read_text(path):
    try:
        return (ROOT / path).read_text()
    except OSError:
        return None


def xctest_rerunner(package, flags):
    """Re-run one test through the bundle that run-xctest-shards.py ran, with the same xcrun xctest command."""
    spec = importlib.util.spec_from_file_location('run_xctest_shards', ROOT / 'scripts/run-xctest-shards.py')
    shards = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shards)
    bundle = []

    def rerun(test, timeout):
        if not bundle:
            bin_path = Path(shards.swift(package, flags, 'build', '--show-bin-path').strip())
            found = sorted(bin_path.glob('*.xctest'))
            if len(found) != 1:
                raise SystemExit(f'Expected one test bundle in {bin_path}, found {[b.name for b in found]}')
            bundle.append(found[0])
        started = time.monotonic()
        try:
            result = subprocess.run(['xcrun', 'xctest', '-XCTest', test, str(bundle[0])], text=True,
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError(test)
        elapsed = time.monotonic() - started
        shards.group(f'xctest re-run in isolation: {test}', result.stdout + result.stderr)
        return durations([result.stdout + result.stderr]).get(test), elapsed

    return rerun


def main(argv):
    own, flags = (argv[:argv.index('--')], argv[argv.index('--') + 1:]) if '--' in argv else (argv, [])
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--package-path', type=Path, required=True)
    parser.add_argument('--log-dir', type=Path, default=ROOT / '.build/xctest-shards')
    parser.add_argument('--exceptions', type=Path, default=ROOT / EXCEPTIONS)
    parser.add_argument('--weights', type=Path, default=ROOT / WEIGHTS)
    parser.add_argument('--event', default='', help='the GitHub event name')
    parser.add_argument('--base', default='', help='the pull request base commit')
    parser.add_argument('--mode', default='full', choices=('full', 'selected'))
    parser.add_argument('--selected-tests', default='')
    parser.add_argument('--parts', type=int, default=1, help='how many runners share the suite')
    args = parser.parse_args(own)

    caps, nightly_cap = load_exceptions(json.loads(args.exceptions.read_text()))
    weights = json.loads(args.weights.read_text())
    logs = sorted(args.log_dir.glob('*.log'))
    measured = durations(log.read_text(errors='replace') for log in logs)
    print(f'{len(measured)} test durations in {len(logs)} shard logs, {sum(measured.values()):.0f}s in total')
    changed = changed_paths(args.base) if args.event == 'pull_request' else []
    errors, warnings = evaluate(measured, caps, nightly_cap, weights, event=args.event, mode=args.mode,
                                selected_tests=args.selected_tests, changed=changed, read_text=read_text,
                                rerun=xctest_rerunner(args.package_path, flags), parts=args.parts)
    for warning in warnings:
        print(f'::warning::{warning}')
    for error in errors:
        print(f'::error::{error}')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
