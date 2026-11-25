"""Tests for scripts/refresh-core-test-weights.py with synthetic job logs, including a re-run in isolation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('refresh_core_test_weights', ROOT / 'scripts/refresh-core-test-weights.py')
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)


def line(test, seconds, state='passed'):
    test_class, method = test.split('/')
    return f"2026-11-25T01:00:00.0000000Z Test Case '-[RemozioCoreTests.{test_class} {method}]' {state} ({seconds:.3f} seconds).\n"


SHARD_THEN_RERUN = (line('SlowTests/testGate', 25.932) + line('SlowTests/testOther', 1.0)
                    + 'Re-running SlowTests/testGate in isolation (25.932s in the shards, limit 20s)\n'
                    + line('SlowTests/testGate', 11.749))


class MaxDurationTests(unittest.TestCase):
    def test_a_re_run_in_isolation_never_replaces_the_longer_shard_duration(self):
        found = REFRESH.max_durations([SHARD_THEN_RERUN])
        self.assertEqual(found['SlowTests/testGate'], 25.932)

    def test_the_maximum_holds_in_either_order_and_across_job_logs(self):
        found = REFRESH.max_durations([line('SlowTests/testGate', 11.0), line('SlowTests/testGate', 26.0)])
        self.assertEqual(found['SlowTests/testGate'], 26.0)

    def test_failed_and_skipped_tests_are_not_weights(self):
        found = REFRESH.max_durations([line('A/testFailed', 3.0, 'failed') + line('A/testSkipped', 0.0, 'skipped')])
        self.assertEqual(found, {})


class RefreshTests(unittest.TestCase):
    def test_class_weights_use_the_maximum_and_untouched_classes_are_kept(self):
        document = {'source': 'old', 'weights': {'SlowTests': 5.0, 'GoneTests': 7.0},
                    'methods': {'SlowTests': {'testGate': 4.0, 'testOther': 1.0}}}
        refreshed, kept = REFRESH.refresh(document, REFRESH.max_durations([SHARD_THEN_RERUN]))
        self.assertEqual(refreshed['weights'], {'GoneTests': 7.0, 'SlowTests': 26.932})
        self.assertEqual(refreshed['methods'], {'SlowTests': {'testGate': 25.932, 'testOther': 1.0}})
        self.assertEqual(kept, ['GoneTests'])

    def test_main_writes_the_file_and_names_the_kept_classes(self):
        with tempfile.TemporaryDirectory() as folder:
            weights, log = Path(folder, 'weights.json'), Path(folder, 'job.log')
            weights.write_text(json.dumps({'source': 'old', 'weights': {'SlowTests': 5.0, 'GoneTests': 7.0},
                                           'methods': {}}))
            log.write_text(SHARD_THEN_RERUN)
            REFRESH.main(['--run-id', '1', '--commit', '0123456789', '--date', '2026-11-25',
                          '--weights', str(weights), str(log)])
            written = json.loads(weights.read_text())
        self.assertEqual(written['weights']['SlowTests'], 26.932)
        self.assertIn('keeps its maximum duration', written['source'])
        self.assertIn('GoneTests', written['source'])


if __name__ == '__main__':
    unittest.main()
