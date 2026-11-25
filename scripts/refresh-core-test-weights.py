#!/usr/bin/env python3
"""Refresh .github/macos-core-test-weights.json from the logs of the Mac core tests jobs of one green full run.

Usage: scripts/refresh-core-test-weights.py --run-id ID --commit SHA --date YYYY-MM-DD [--note TEXT] LOG...

Each LOG is the full log of one Mac core tests job. A test can be reported more than once in a job log:
scripts/core-test-time-guard.py re-runs a slow test in isolation after the shards, in the same job, so the same
Class/method appears again with its isolated duration. The weights describe the shard schedule, so each test
keeps its maximum reported duration, never its last one.

Each class weight becomes the sum of its tests' durations, and each method entry under "methods" becomes that
test's duration. A class that is listed under "methods" also gets entries for its tests that are new in this run.
Classes that the run did not execute keep their earlier weights, and the source text names them.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = ROOT / '.github/macos-core-test-weights.json'


def _guard():
    spec = importlib.util.spec_from_file_location('core_test_time_guard', ROOT / 'scripts/core-test-time-guard.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OUTCOME = _guard().OUTCOME


def max_durations(texts):
    """Map each Class/method that passed to the maximum duration reported for it across all texts."""
    found = {}
    for text in texts:
        for match in OUTCOME.finditer(text):
            if match['state'] != 'passed':
                continue
            name = f"{match['cls'].split('.', 1)[-1]}/{match['method']}"
            found[name] = max(found.get(name, 0.0), float(match['seconds']))
    return found


def refresh(document, measured):
    """Return (new document without its source, classes kept from the old document)."""
    classes = {}
    for name, seconds in measured.items():
        cls = name.split('/', 1)[0]
        classes[cls] = classes.get(cls, 0.0) + seconds
    weights = dict(document['weights'])
    kept = sorted(cls for cls in weights if cls not in classes)
    for cls, total in classes.items():
        weights[cls] = round(total, 3)
    methods = {}
    for cls, entries in document['methods'].items():
        updated = dict(entries)
        for name, seconds in measured.items():
            owner, method = name.split('/', 1)
            if owner == cls:
                updated[method] = round(seconds, 3)
        methods[cls] = dict(sorted(updated.items()))
    return {'source': document['source'], 'weights': dict(sorted(weights.items())), 'methods': methods}, kept


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--date', required=True)
    parser.add_argument('--note', default='')
    parser.add_argument('--weights', type=Path, default=WEIGHTS)
    parser.add_argument('logs', nargs='+', type=Path)
    args = parser.parse_args(argv)
    measured = max_durations(path.read_text(errors='replace') for path in args.logs)
    if not measured:
        sys.exit('no passing test durations found in the logs')
    document = json.loads(args.weights.read_text())
    refreshed, kept = refresh(document, measured)
    note = f', {args.note}' if args.note else ''
    refreshed['source'] = (
        f'Class weights and method entries from the green full main run {args.run_id} on {args.commit[:8]}, '
        f'{args.date}{note}: each class weight is the sum of its passing per-test durations in the Mac core tests '
        'jobs (CI mode, -O, three concurrent shard processes per runner), and each method entry is that test\'s '
        'duration in the same run. A test reported twice, for example re-run in isolation by '
        'scripts/core-test-time-guard.py, keeps its maximum duration. '
        + ('The classes that run did not execute keep their earlier values: ' + ', '.join(kept) + '.'
           if kept else 'Every class ran.'))
    args.weights.write_text(json.dumps(refreshed, indent=1, ensure_ascii=False) + '\n')
    print(f'{len(measured)} tests, {len(refreshed["weights"])} classes, total {sum(measured.values()):.0f} s, '
          f'kept {len(kept)}')


if __name__ == '__main__':
    main()
