#!/usr/bin/env python3
"""Profile individual XCTest methods: wall versus CPU time, plus a `sample` stack profile. Measurement only."""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def demangle(text):
    try:
        return subprocess.run(['xcrun', 'swift-demangle', '--simplified'], input=text, capture_output=True,
                              text=True, timeout=120).stdout or text
    except Exception:
        return text


def top_of_stack(report, limit=25):
    """Return the 'Sort by top of stack' section that `sample` prints after its call graph."""
    lines = report.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith('Sort by top of stack')), None)
    if start is None:
        return '(no top-of-stack section)'
    section = []
    for line in lines[start + 1:]:
        if not line.strip() or line.startswith('Binary Images'):
            break
        section.append(line)
    return '\n'.join(section[:limit])


def main(argv):
    bundle, out = Path(argv[0]), Path(argv[1])
    tests = argv[2:]
    out.mkdir(parents=True, exist_ok=True)
    xctest = subprocess.run(['xcrun', '--find', 'xctest'], capture_output=True, text=True, check=True).stdout.strip()
    for test in tests:
        name = re.sub(r'[^A-Za-z0-9]+', '-', test)[:120]
        log = (out / f'{name}.log').open('w')
        started = time.monotonic()
        process = subprocess.Popen([xctest, '-XCTest', test, str(bundle)], stdout=log, stderr=subprocess.STDOUT)
        sample_file = out / f'{name}.sample.txt'
        sampler = subprocess.Popen(['sample', str(process.pid), '60', '1', '-mayDie', '-file', str(sample_file)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        _, status, usage = os.wait4(process.pid, 0)
        wall = time.monotonic() - started
        try:
            sampler.wait(timeout=30)
        except subprocess.TimeoutExpired:
            sampler.terminate()
        log.close()
        outcome = re.findall(r"Test Case '.*' (passed|failed|skipped) \(([\d.]+) seconds\)", (out / f'{name}.log').read_text(errors='replace'))
        print(f'== {test}\n   outcome {outcome} wall {wall:.2f}s user {usage.ru_utime:.2f}s sys {usage.ru_stime:.2f}s '
              f'cpu/wall {(usage.ru_utime + usage.ru_stime) / wall:.2f} exit {os.waitstatus_to_exitcode(status)}', flush=True)
        if sample_file.exists():
            report = demangle(sample_file.read_text(errors='replace'))
            sample_file.write_text(report)
            print(top_of_stack(report), flush=True)
        else:
            print(f'   (no sample: {sampler.stderr.read().strip()[:300] if sampler.stderr else ""})', flush=True)


if __name__ == '__main__':
    main(sys.argv[1:])
