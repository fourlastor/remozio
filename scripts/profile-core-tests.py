#!/usr/bin/env python3
"""Fork-only: attribute slow macos/core tests to CPU, disk sync and call stacks."""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

def run(bundle, test, env, label, out, wrap=None, helper_timeout=240):
    log = open(out / f'{label}.log', 'wb')
    started = time.monotonic()
    proc = subprocess.Popen(['xcrun', 'xctest', '-XCTest', test, str(bundle)], stdout=log, stderr=subprocess.STDOUT, env=env)
    helper = wrap(proc.pid) if wrap else None
    _, status, usage = os.wait4(proc.pid, 0)
    wall = time.monotonic() - started
    if helper:
        try: helper.wait(timeout=helper_timeout)
        except subprocess.TimeoutExpired: helper.terminate()
    return {'wall': round(wall, 2), 'user': round(usage.ru_utime, 2), 'sys': round(usage.ru_stime, 2),
            'status': status, 'maxrssMiB': usage.ru_maxrss // (1024 * 1024)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bundle', required=True); p.add_argument('--tests', required=True)
    p.add_argument('--output', required=True); p.add_argument('--variant', required=True)
    p.add_argument('--deep', action='store_true'); a = p.parse_args()
    out = Path(a.output) / a.variant; out.mkdir(parents=True, exist_ok=True)
    bundle = Path(a.bundle).resolve(); results = {}
    for index, test in enumerate(Path(a.tests).read_text().split()):
        row = {'plain': run(bundle, test, dict(os.environ), f'{index}-plain', out)}
        if a.deep:
            sample = lambda pid: subprocess.Popen(['sudo', 'sample', str(pid), '300', '5', '-mayDie', '-file', str(out / f'{index}.sample.txt')],
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            row['sampled'] = run(bundle, test, dict(os.environ), f'{index}-sampled', out, sample)
            trace = out / f'{index}.fs_usage.txt'
            def fs(pid):
                handle = open(trace, 'wb')
                return subprocess.Popen(['sudo', 'fs_usage', '-w', '-f', 'filesys', str(pid)], stdout=handle, stderr=subprocess.DEVNULL)
            row['traced'] = run(bundle, test, dict(os.environ), f'{index}-traced', out, fs, 2)
            subprocess.run(['sudo', 'pkill', 'fs_usage'], check=False)
            count = total = 0
            for line in trace.read_text(errors='replace').splitlines():
                if 'F_FULLFSYNC' in line:
                    m = re.search(r'(\d+\.\d{6})\s*W?\s+\S+$', line); count += 1
                    if m: total += float(m[1])
            row['fullfsync'] = {'count': count, 'seconds': round(total, 2)}
        results[test] = row
        print(test, json.dumps(row), flush=True)
    (out / 'summary.json').write_text(json.dumps(results, indent=1) + '\n')

if __name__ == '__main__':
    sys.exit(main())
