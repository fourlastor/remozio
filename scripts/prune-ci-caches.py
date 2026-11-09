#!/usr/bin/env python3
"""Delete GitHub Actions cache entries that newer main entries replaced.

Each main push saves new Mac compiler outputs and, when build files change, new Gradle downloads. Two generations
do not fit the repository's 10 GB budget, so GitHub evicts entries, sometimes the small Gradle ones, and the next run
downloads Gradle again. This keeps one entry per key family:

- Only entries on refs/heads/main are considered; pull request caches are never touched.
- Only known families are pruned: `mac-build-v<N>-<scope>-` and `gradle-downloads-v<N>-<job>-<os>-`.
- In each family the newest entry stays, and so does every key this run saved (`--keep`).

API errors become workflow warnings; the script never fails the run.
"""
import argparse
from datetime import datetime
import json
import re
import subprocess
import sys

MAIN = 'refs/heads/main'
FAMILIES = (
    re.compile(r'^(mac-build-v\d+-[a-z]+-)[0-9a-f]+-[0-9a-f]+$'),
    re.compile(r'^(gradle-downloads-v\d+-[a-z0-9-]+-(?:Linux|macOS|Windows)-)[0-9a-f]+$'),
)


def family(key):
    for pattern in FAMILIES:
        match = pattern.match(key)
        if match:
            return match.group(1)
    return None


def created(entry):
    return datetime.fromisoformat(entry['created_at'].replace('Z', '+00:00'))


def plan(entries, keep):
    """Return the main entries to delete: everything in a known family except its newest entry and kept keys."""
    families = {}
    for entry in entries:
        name = family(entry['key'])
        if entry.get('ref') == MAIN and name is not None:
            families.setdefault(name, []).append(entry)
    delete = []
    for name in sorted(families):
        group = families[name]
        newest = max(group, key=lambda entry: (created(entry), entry['id']))
        delete.extend(entry for entry in sorted(group, key=created)
                      if entry['id'] != newest['id'] and entry['key'] not in keep)
    return delete


def gh(*args):
    return subprocess.run(('gh', 'api', *args), check=True, capture_output=True, text=True).stdout


def warn(message):
    print(f'::warning::{message}', flush=True)


def megabytes(size):
    return f'{size / 1048576:.0f} MB'


def run(repository, keep, dry_run=False, api=gh):
    try:
        lines = api('--paginate', f'repos/{repository}/actions/caches?ref={MAIN}&per_page=100',
                    '--jq', '.actions_caches[]')
        entries = [json.loads(line) for line in lines.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, OSError, ValueError) as error:
        warn(f'Could not list the main caches, so none were deleted: {error}')
        return 0
    doomed = plan(entries, keep)
    deleted = 0
    for entry in doomed:
        label = f"{entry['key']} ({megabytes(entry['size_in_bytes'])}, created {entry['created_at']})"
        if dry_run:
            print(f'Would delete {label}')
            continue
        try:
            api('--method', 'DELETE', f"repos/{repository}/actions/caches/{entry['id']}")
        except (subprocess.CalledProcessError, OSError) as error:
            warn(f'Could not delete {label}: {error}')
            continue
        deleted += entry['size_in_bytes']
        print(f'Deleted {label}')
    if not doomed:
        print('No superseded main cache entries.')
    if dry_run:
        print(f"Would free {megabytes(sum(entry['size_in_bytes'] for entry in doomed))}.")
        return 0
    try:
        usage = json.loads(api(f'repos/{repository}/actions/cache/usage'))
        print(f"Freed {megabytes(deleted)}. The repository now holds {usage['active_caches_count']} cache entries, "
              f"{usage['active_caches_size_in_bytes'] / 1073741824:.2f} GB.")
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError) as error:
        warn(f'Freed {megabytes(deleted)}, but could not read the cache usage: {error}')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--repository', required=True, help='owner/name')
    parser.add_argument('--keep', action='append', default=[], help='a key this run saved; repeatable')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    return run(args.repository, {key for key in args.keep if key}, args.dry_run)


if __name__ == '__main__':
    sys.exit(main())
