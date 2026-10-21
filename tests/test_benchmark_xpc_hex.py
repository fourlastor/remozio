"""Portable harness controls only: these tests never invoke Swift or time code."""
import copy
import importlib.util
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('hex_benchmark', Path(__file__).parents[1] / 'scripts/benchmark-xpc-hex.py')
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class HexBenchmarkTests(unittest.TestCase):
    def sources(self):
        baseline = b'import Foundation\nstruct XPCPeerPolicy {\n' + BENCH.END + b'ignored) {\nlet result = ' + BENCH.OLD + b'\n}\n}\n'
        block = BENCH.START + b'\n' + BENCH.SIGNATURE + b'        return "fixture"\n    }\n\n'
        candidate = baseline.replace(BENCH.END, block + BENCH.END).replace(BENCH.OLD, BENCH.NEW)
        return baseline, candidate, block

    def test_exact_source_delta_and_extracted_bytes(self):
        baseline, candidate, block = self.sources()
        observed, compiled = BENCH.extract_helper(baseline, candidate, BENCH.sha(baseline), BENCH.sha(candidate))
        self.assertEqual(observed, block)
        self.assertEqual(compiled, b'import Foundation\nenum XPCPeerPolicy {\n' + block + b'}\n')

    def test_hash_or_unrelated_source_changes_refuse(self):
        baseline, candidate, _ = self.sources()
        for changed, expected_hash in [(candidate, '0' * 64), (candidate + b'\n', BENCH.sha(candidate + b'\n')),
                                       (candidate.replace(BENCH.NEW, b'other(value)'), BENCH.sha(candidate.replace(BENCH.NEW, b'other(value)')))]:
            with self.subTest(changed=changed[-20:]), self.assertRaises(ValueError):
                BENCH.extract_helper(baseline, changed, BENCH.sha(baseline), expected_hash)

    def test_duplicate_extraction_boundaries_refuse(self):
        baseline, candidate, _ = self.sources()
        changed = candidate + BENCH.START
        with self.assertRaises(ValueError):
            BENCH.extract_helper(baseline, changed, BENCH.sha(baseline), BENCH.sha(changed))

    def test_all_bytes_and_mixed_order_use_independent_python_oracle(self):
        corpus = BENCH.make_corpus()
        self.assertEqual(len(corpus['parity']), 288)
        self.assertEqual(len(corpus['timed']), 32)
        for byte, record in enumerate(corpus['parity'][:256]):
            self.assertEqual(record['bytes'], [byte] * 20)
        for record in corpus['parity'] + corpus['timed']:
            self.assertEqual(record['expected'], bytes(record['bytes']).hex())
            self.assertEqual(len(record['expected']), 40)
        self.assertTrue(any(record['bytes'] != list(reversed(record['bytes'])) for record in corpus['timed']))

    def test_balanced_pair_order_and_bounds(self):
        self.assertEqual(BENCH.trial_order(2), ['baseline', 'candidate', 'candidate', 'baseline'])
        for pairs in (2, 6, 12):
            order = BENCH.trial_order(pairs)
            self.assertEqual(order.count('baseline'), pairs)
            self.assertEqual(order.count('candidate'), pairs)
        for invalid in (0, 1, 3, 13, True):
            with self.assertRaises(ValueError):
                BENCH.trial_order(invalid)

    def result(self):
        corpus = BENCH.make_corpus()
        checksums = (BENCH.expected_checksum(corpus, 2), BENCH.expected_checksum(corpus, 1))
        result = {'schemaVersion': 1, 'variant': 'candidate', 'iterations': 2, 'warmupIterations': 1,
                  'parityRecords': 288, 'recordsPerIteration': 32, 'formatCalls': 64,
                  'checksumFNV1a64': checksums[0], 'warmupChecksumFNV1a64': checksums[1],
                  'wallSeconds': .5, 'processCPUSeconds': .4}
        return corpus, checksums, result

    def test_result_requires_every_workload_and_checksum_field(self):
        corpus, checksums, result = self.result()
        BENCH.validate_result(result, 'candidate', 2, 1, corpus, checksums)
        for key, changed in [('checksumFNV1a64', '0'), ('warmupChecksumFNV1a64', '0'),
                             ('formatCalls', 32), ('variant', 'baseline'), ('iterations', True),
                             ('wallSeconds', float('nan')), ('processCPUSeconds', 0), ('extra', 1)]:
            bad = {**result, key: changed}
            with self.subTest(key=key), self.assertRaises(ValueError):
                BENCH.validate_result(bad, 'candidate', 2, 1, corpus, checksums)

    def test_checksum_consumes_each_iteration_and_order(self):
        corpus = BENCH.make_corpus()
        self.assertNotEqual(BENCH.expected_checksum(corpus, 1), BENCH.expected_checksum(corpus, 2))
        changed = copy.deepcopy(corpus)
        changed['timed'][0]['expected'] = '0' * 40
        self.assertNotEqual(BENCH.expected_checksum(corpus, 2), BENCH.expected_checksum(changed, 2))

    def test_summary_refuses_missing_variant(self):
        trials = [{'optimization': optimization, 'variant': variant, 'native': {'wallSeconds': value}}
                  for optimization in ('-Onone', '-O') for variant, value in [('baseline', 1), ('candidate', .5)]
                  for _ in range(2)]
        result = BENCH.summarize(trials)
        self.assertEqual(result['-O']['candidateBaselineWallRatio'], .5)
        with self.assertRaises(ValueError):
            BENCH.summarize(trials[:-1])

    def test_timeout_kills_only_owned_process_group(self):
        process = Mock(pid=9876)
        process.wait.side_effect = [subprocess.TimeoutExpired(['fake'], 1), -9]
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory, patch.object(BENCH.subprocess, 'Popen', return_value=process), \
             patch.object(BENCH.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                BENCH.execute(['fake'], Path(directory), 'case', 1)
        kill.assert_called_once_with(9876, signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 2)


if __name__ == '__main__':
    unittest.main()
