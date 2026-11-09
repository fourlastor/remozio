"""XCTest shards must cover every selected test exactly once and report skips and failures."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('xctest_shards', ROOT / 'scripts/run-xctest-shards.py')
SHARDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARDS)

LISTING = '''Building for debugging...
RemozioCoreTests.ATests/testOne
RemozioCoreTests.ATests/testTwo
RemozioCoreTests.BTests/testThree
RemozioCoreTests.SignedReleaseInspectionTests/testBundle
RemozioCoreTests.RelayConnectorProcessTests/testVendor
not a test line
'''


def outcome(test, state):
    cls, method = test.split('/')
    return f"Test Case '-[{cls} {method}]' {state} (0.012 seconds).\n"


class XCTestShardTests(unittest.TestCase):
    def test_listing_keeps_only_module_class_method_lines(self):
        self.assertEqual(SHARDS.listed_tests(LISTING), {
            'RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.ATests/testTwo', 'RemozioCoreTests.BTests/testThree',
            'RemozioCoreTests.SignedReleaseInspectionTests/testBundle',
            'RemozioCoreTests.RelayConnectorProcessTests/testVendor'})

    def test_app_dependent_selection_is_exact_and_complementary(self):
        classes = {test.split('/')[0] for test in SHARDS.listed_tests(LISTING)}
        only = SHARDS.select(classes, 'only')
        excluded = SHARDS.select(classes, 'exclude')
        self.assertEqual({SHARDS.short_name(name) for name in only}, set(SHARDS.APP_DEPENDENT))
        self.assertEqual(set(only) | set(excluded), classes)
        self.assertFalse(set(only) & set(excluded))
        self.assertEqual(SHARDS.select(classes, 'include'), sorted(classes))

    def test_a_missing_app_dependent_class_refuses_the_selection(self):
        with self.assertRaises(SystemExit):
            SHARDS.select({'RemozioCoreTests.ATests'}, 'exclude')
        self.assertEqual(SHARDS.select({'RemozioCoreTests.ATests'}, 'include'), ['RemozioCoreTests.ATests'])

    def test_partition_assigns_every_class_once_and_is_deterministic(self):
        classes = [f'RemozioCoreTests.C{index}Tests' for index in range(40)]
        weights = {f'C{index}Tests': float(index % 7) for index in range(30)}
        first, loads = SHARDS.partition(classes, weights, 3)
        self.assertEqual(sorted(sum(first, [])), sorted(classes))
        self.assertEqual(first, SHARDS.partition(list(reversed(classes)), weights, 3)[0])
        self.assertLessEqual(max(loads) - min(loads), max(weights.values()))

    def test_more_shards_than_classes_leaves_empty_shards(self):
        assigned, _ = SHARDS.partition(['RemozioCoreTests.ATests'], {}, 3)
        self.assertEqual(assigned, [['RemozioCoreTests.ATests'], [], []])
        with self.assertRaises(ValueError):
            SHARDS.partition(['RemozioCoreTests.ATests'], {}, 0)

    def test_missing_duplicate_failed_and_foreign_outcomes_are_problems(self):
        expected = {'RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.ATests/testTwo',
                    'RemozioCoreTests.BTests/testThree'}
        log = (outcome('RemozioCoreTests.ATests/testOne', 'passed') + outcome('RemozioCoreTests.ATests/testOne', 'passed')
               + outcome('RemozioCoreTests.BTests/testThree', 'failed')
               + outcome('RemozioCoreTests.CTests/testFour', 'passed'))
        problems, skipped = SHARDS.verify(expected, SHARDS.outcomes(log))
        self.assertEqual(problems, ['RemozioCoreTests.ATests/testOne: 2 outcomes',
                                    'RemozioCoreTests.ATests/testTwo: 0 outcomes',
                                    'RemozioCoreTests.BTests/testThree: failed',
                                    'RemozioCoreTests.CTests/testFour: ran outside its shard'])
        self.assertEqual(skipped, [])

    def test_skips_are_reported_and_only_allowed_skips_pass_when_guarded(self):
        expected = {'RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.ATests/testTwo'}
        log = outcome('RemozioCoreTests.ATests/testOne', 'skipped') + outcome('RemozioCoreTests.ATests/testTwo', 'passed')
        found = SHARDS.outcomes(log)
        self.assertEqual(SHARDS.verify(expected, found), ([], ['RemozioCoreTests.ATests/testOne']))
        self.assertEqual(SHARDS.verify(expected, found, {'RemozioCoreTests.ATests/testOne'})[0], [])
        self.assertEqual(SHARDS.verify(expected, found, set())[0],
                         ['RemozioCoreTests.ATests/testOne: skipped, which this job does not allow'])

    def test_weights_file_covers_the_app_dependent_classes_and_holds_seconds(self):
        weights = json.loads((ROOT / '.github/macos-core-test-weights.json').read_text())['weights']
        self.assertGreater(len(weights), 400)
        self.assertTrue(all(isinstance(value, (int, float)) and value >= 0 for value in weights.values()))
        self.assertTrue(set(SHARDS.APP_DEPENDENT) <= set(weights))


if __name__ == '__main__':
    unittest.main()
