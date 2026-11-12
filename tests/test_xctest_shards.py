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

    def test_a_split_class_runs_each_selected_test_as_its_own_unit(self):
        classes = ['RemozioCoreTests.ATests', 'RemozioCoreTests.BTests']
        tests = {'RemozioCoreTests.ATests/testTwo', 'RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.BTests/testThree'}
        self.assertEqual(SHARDS.units(classes, tests, {'ATests': {'testOne': 1.0}}),
                         ['RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.ATests/testTwo', 'RemozioCoreTests.BTests'])
        self.assertEqual(SHARDS.units(classes, tests, {}), classes)

    def test_a_heavy_split_class_spreads_over_the_shards_and_every_test_runs_once(self):
        heavy = {f'test{index}': 10.0 for index in range(9)}
        tests = {f'RemozioCoreTests.HeavyTests/{name}' for name in heavy}
        tests |= {f'RemozioCoreTests.L{index}Tests/testOnly' for index in range(6)}
        classes = sorted({test.split('/')[0] for test in tests})
        weights = {'HeavyTests': 90.0, **{f'L{index}Tests': 5.0 for index in range(6)}}
        _, whole = SHARDS.partition(classes, weights, 3)
        split, loads = SHARDS.partition(SHARDS.units(classes, tests, {'HeavyTests': heavy}), weights, 3,
                                        {'HeavyTests': heavy})
        self.assertEqual(max(whole), 90.0)
        self.assertEqual(loads, [40.0, 40.0, 40.0])
        covered = [SHARDS.shard_tests(names, tests) for names in split]
        self.assertEqual(sorted(test for shard in covered for test in shard), sorted(tests))
        self.assertEqual(sum(1 for shard in covered if any(test.startswith('RemozioCoreTests.HeavyTests/')
                                                           for test in shard)), 3)

    def test_a_test_without_its_own_weight_counts_as_the_median_test_of_its_class(self):
        methods = {'HeavyTests': {'testA': 1.0, 'testB': 3.0, 'testC': 100.0}}
        self.assertEqual(SHARDS.partition(['RemozioCoreTests.HeavyTests/testNew'], {'OtherTests': 7.0}, 1, methods)[1],
                         [3.0])
        self.assertEqual(SHARDS.partition(['RemozioCoreTests.OtherTests/testNew'], {'OtherTests': 7.0}, 1, methods)[1],
                         [7.0])

    def test_shard_tests_cover_whole_classes_and_single_tests_only(self):
        tests = {'RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.ATests/testTwo',
                 'RemozioCoreTests.HeavyTests/testOne', 'RemozioCoreTests.HeavyTests/testTwo'}
        names = ['RemozioCoreTests.ATests', 'RemozioCoreTests.HeavyTests/testTwo']
        self.assertEqual(SHARDS.shard_tests(names, tests), {
            'RemozioCoreTests.ATests/testOne', 'RemozioCoreTests.ATests/testTwo', 'RemozioCoreTests.HeavyTests/testTwo'})
        self.assertEqual(SHARDS.describe(names), '1 classes and 1 tests of split classes')
        self.assertEqual(SHARDS.describe(['RemozioCoreTests.ATests']), '1 classes')

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
        document = json.loads((ROOT / '.github/macos-core-test-weights.json').read_text())
        weights = document['weights']
        self.assertGreater(len(weights), 400)
        self.assertTrue(all(isinstance(value, (int, float)) and value >= 0 for value in weights.values()))
        self.assertTrue(set(SHARDS.APP_DEPENDENT) <= set(weights))
        for name, table in document.get('methods', {}).items():
            self.assertIn(name, weights)
            self.assertNotIn(name, SHARDS.APP_DEPENDENT)
            self.assertTrue(table)
            self.assertTrue(all(isinstance(value, (int, float)) and value >= 0 for value in table.values()))


if __name__ == '__main__':
    unittest.main()
