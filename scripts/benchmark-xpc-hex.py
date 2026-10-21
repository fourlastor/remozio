#!/usr/bin/env python3
"""Private, bounded extracted-helper microbenchmark; never runs Security/XPC code.

Requires full baseline/candidate source files and their explicitly reviewed SHA256s.
The actual production helper block is extracted byte-for-byte and compiled beside
the harness. No source checkout is changed, no packages are resolved, no network
is used, and no test-suite/Mac/full-initializer speed claim follows from this run.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import time

START = b'    private static let hexadecimalDigits = Array("0123456789abcdef".utf8)\n'
END = b'    public init(teamID: String, componentIdentifier: String, approvedCodeDirectoryHashes: Set<Data>,\n'
SIGNATURE = b'    static func hexadecimalCodeDirectoryHash(_ value: Data) -> String {\n'
OLD = b'value.map { String(format: "%02x", $0) }.joined()'
NEW = b'Self.hexadecimalCodeDirectoryHash(value)'
MASK = (1 << 64) - 1
OFFSET = 14_695_981_039_346_656_037
PRIME = 1_099_511_628_211


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def extract_helper(baseline, candidate, baseline_sha, candidate_sha):
    require(sha(baseline) == baseline_sha and sha(candidate) == candidate_sha, 'source hash mismatch')
    require(candidate.count(START) == 1 and candidate.count(END) == 1
            and candidate.count(SIGNATURE) == 1 and candidate.count(NEW) == 1,
            'candidate helper/call boundary is ambiguous')
    start, end = candidate.index(START), candidate.index(END)
    require(start < end, 'helper must precede initializer')
    block = candidate[start:end]
    require(SIGNATURE in block and block.endswith(b'    }\n\n'), 'unexpected helper boundary')
    reconstructed = (candidate[:start] + candidate[end:]).replace(NEW, OLD)
    require(baseline.count(OLD) == 1 and reconstructed == baseline,
            'candidate differs beyond the reviewed helper extraction and call replacement')
    return block, b'import Foundation\nenum XPCPeerPolicy {\n' + block + b'}\n'


def make_corpus():
    def record(value):
        return {'bytes': list(value), 'expected': value.hex()}
    mixed = [bytes(((index * 17 + offset * 29) & 255) for index in range(20)) for offset in range(32)]
    # All 256 byte values in twenty-byte hashes; mixed records also check order.
    return {'parity': [record(bytes([byte]) * 20) for byte in range(256)] + [record(value) for value in mixed],
            'timed': [record(value) for value in mixed]}


def expected_checksum(corpus, iterations):
    values = [record['expected'].encode('ascii') for record in corpus['timed']]
    value = OFFSET
    for iteration in range(iterations):
        for index in range(len(values)):
            for byte in values[(index + iteration) % len(values)]:
                value = ((value ^ byte) * PRIME) & MASK
    return str(value)


def trial_order(pairs):
    require(type(pairs) is int and 2 <= pairs <= 12 and pairs % 2 == 0,
            'pairs must be even and within 2..12')
    return [variant for pair in range(pairs)
            for variant in (('baseline', 'candidate') if pair % 2 == 0 else ('candidate', 'baseline'))]


def validate_result(result, variant, iterations, warmup, corpus, checksums):
    fixed = {'schemaVersion': 1, 'variant': variant, 'iterations': iterations,
             'warmupIterations': warmup, 'parityRecords': len(corpus['parity']),
             'recordsPerIteration': len(corpus['timed']), 'formatCalls': iterations * len(corpus['timed']),
             'checksumFNV1a64': checksums[0], 'warmupChecksumFNV1a64': checksums[1]}
    require(set(result) == set(fixed) | {'wallSeconds', 'processCPUSeconds'}, 'unexpected native result fields')
    for key, expected in fixed.items():
        require(type(result[key]) is type(expected) and result[key] == expected, f'native mismatch: {key}')
    for key in ('wallSeconds', 'processCPUSeconds'):
        require(type(result[key]) in (int, float) and math.isfinite(result[key]) and result[key] > 0,
                f'invalid native timing: {key}')


def summarize(trials):
    summary = {}
    for optimization in ('-Onone', '-O'):
        groups = {variant: [trial['native'] for trial in trials
                            if trial['optimization'] == optimization and trial['variant'] == variant]
                  for variant in ('baseline', 'candidate')}
        require(len(groups['baseline']) == len(groups['candidate']) >= 2, 'unbalanced timed observations')
        medians = {variant: statistics.median(item['wallSeconds'] for item in group)
                   for variant, group in groups.items()}
        summary[optimization] = {'samplesPerVariant': len(groups['baseline']),
                                'wallMedianSeconds': medians,
                                'candidateBaselineWallRatio': medians['candidate'] / medians['baseline'],
                                'containsSub100msTrial': any(item['wallSeconds'] < .1
                                                             for group in groups.values() for item in group)}
    return summary


def execute(command, output, name, timeout):
    start = time.monotonic()
    out_path, err_path = output / (name + '.stdout'), output / (name + '.stderr')
    with out_path.open('wb') as out, err_path.open('wb') as err:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   start_new_session=True,
                                   env={**os.environ, 'CLANG_MODULE_CACHE_PATH': str(output / 'module-cache')})
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
            raise
    require(out_path.stat().st_size <= 1_048_576 and err_path.stat().st_size <= 1_048_576,
            'command output exceeded retained-read limit')
    require(code == 0, f'{name} failed; inspect retained stdout/stderr')
    return out_path.read_bytes(), {'command': command, 'exitStatus': code,
                                   'wallSeconds': time.monotonic() - start}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-source', type=Path, required=True)
    parser.add_argument('--candidate-source', type=Path, required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--swiftc', default='swiftc')
    parser.add_argument('--target')
    parser.add_argument('--iterations', type=int, default=1_000)
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--pairs', type=int, default=6)
    args = parser.parse_args(argv)
    require(1 <= args.iterations <= 50_000 and 1 <= args.warmup <= 1_000, 'iteration/warmup bounds exceeded')
    order = trial_order(args.pairs)
    baseline, candidate = args.baseline_source.read_bytes(), args.candidate_source.read_bytes()
    block, helper = extract_helper(baseline, candidate, args.baseline_sha256, args.candidate_sha256)
    harness_path = Path(__file__).with_name('xpc-hex-benchmark.swift')
    harness = harness_path.read_bytes()
    swiftc = shutil.which(args.swiftc)
    require(swiftc is not None, 'swiftc unavailable')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'helper.swift').write_bytes(helper)
    (output / 'harness.swift').write_bytes(harness)
    (output / 'baseline-source.swift').write_bytes(baseline)
    (output / 'candidate-source.swift').write_bytes(candidate)
    (output / 'driver.py').write_bytes(Path(__file__).read_bytes())
    corpus = make_corpus()
    dump(output / 'corpus.json', corpus)
    checksums = (expected_checksum(corpus, args.iterations), expected_checksum(corpus, args.warmup))
    report = {'schemaVersion': 1, 'passed': False, 'scope': 'extracted helper only; no Security/XPC/full initializer',
              'nativeSecurityFrameworkExecuted': False, 'fullInitializerMeasured': False,
              'baselineSourceSHA256': sha(baseline), 'candidateSourceSHA256': sha(candidate),
              'extractedProductionBlockSHA256': sha(block), 'compiledHelperSHA256': sha(helper),
              'harnessSHA256': sha(harness), 'driverSHA256': sha(Path(__file__).read_bytes()),
              'corpusSHA256': sha((output / 'corpus.json').read_bytes()),
              'host': {'system': platform.system(), 'machine': platform.machine(), 'release': platform.release()},
              'pairs': args.pairs, 'iterations': args.iterations, 'warmup': args.warmup, 'order': order,
              'commands': [], 'trials': [],
              'limitations': ['Formatting, loop, UTF-8 traversal and every-result checksum are timed together.',
                              'Fixed counts are not calibrated; inspect all trial durations before interpreting ratios.',
                              'Two or more balanced pairs on one host do not establish statistical significance.',
                              'Linux/Foundation results do not establish Mac/native-test/full-CI savings.',
                              'Only the table/helper block is compiled; the complete policy and Security parser are excluded.']}
    try:
        version, metadata = execute([swiftc, '--version'], output, 'swift-version', 30)
        report['commands'].append(metadata)
        report['swiftVersion'] = version.decode('utf-8', errors='strict')
        for optimization in ('-Onone', '-O'):
            tag = optimization.removeprefix('-')
            binaries = {}
            for variant in ('baseline', 'candidate'):
                binary = output / (tag + '-' + variant)
                command = [swiftc, optimization, '-g', '-swift-version', '6', '-module-name', 'XPCHexBenchmark',
                           '-module-cache-path', str(output / 'module-cache')]
                if args.target:
                    command += ['-target', args.target]
                if variant == 'baseline':
                    command += ['-D', 'BASELINE']
                command += [str(output / 'helper.swift'), str(output / 'harness.swift'), '-o', str(binary)]
                _, metadata = execute(command, output, 'build-' + tag + '-' + variant, 300)
                metadata['binarySHA256'] = sha(binary.read_bytes())
                report['commands'].append(metadata)
                binaries[variant] = binary
            for index, variant in enumerate(order):
                command = [str(binaries[variant]), 'run', str(output / 'corpus.json'), str(args.iterations), str(args.warmup)]
                raw, metadata = execute(command, output, f'{tag}-{index:02}-{variant}', 60)
                native = json.loads(raw)
                validate_result(native, variant, args.iterations, args.warmup, corpus, checksums)
                report['commands'].append(metadata)
                report['trials'].append({'optimization': optimization, 'variant': variant, 'index': index, 'native': native})
                dump(output / 'report.json', report)
        require(args.baseline_source.read_bytes() == baseline and args.candidate_source.read_bytes() == candidate,
                'source files changed during measurement')
        require(harness_path.read_bytes() == harness, 'harness changed during measurement')
        report['summary'] = summarize(report['trials'])
        report['passed'] = True
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        dump(output / 'report.json', report)
    print(json.dumps({'passed': report['passed'], 'report': str(output / 'report.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(f'hex benchmark refused: {error}', file=sys.stderr)
        sys.exit(1)
